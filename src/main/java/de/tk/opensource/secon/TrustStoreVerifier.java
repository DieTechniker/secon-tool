package de.tk.opensource.secon;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

public class TrustStoreVerifier implements Verifier {

	private final KeyStore trustStore;

	private final boolean revocationCheck;

	public TrustStoreVerifier(KeyStore trustStore, boolean revocationCheck) {
		super();

		this.revocationCheck = revocationCheck;
		this.trustStore = trustStore;
	}

	@Override
	public void verify(X509Certificate addCerts) throws CertificateVerificationException {
		try {
			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");

			PKIXRevocationChecker rc = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();

			rc.setOptions(EnumSet.of( //
					PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
					PKIXRevocationChecker.Option.NO_FALLBACK, //
					PKIXRevocationChecker.Option.SOFT_FAIL)); // soft-fail on network issues

			PKIXParameters params = new PKIXParameters(trustStore);

			params.addCertPathChecker(rc);
			params.setRevocationEnabled(revocationCheck);

			CertPath certPath = buildPath(addCerts);
			certPathValidator.validate(certPath, params);

			handleSoftFailures(rc);
		} catch (Exception e) {
			throw new CertificateVerificationException("Error verifying signer certificate", e);
		}
	}

	/**
	 * 
	 * Baut eine Zertifikatskette für die zu prüfenden Zertifikate auf. Wird nur ein
	 * einzelnes Zertifikat übergeben wird eine Kette bis zu einem Root-Zertifikat
	 * im Trustore aufgebaut. Werden mehrere Zertifikate übergeben werden diese in
	 * ein {@link CertPath}-Objekt konvertiert. Die zurückgebene Kette kann
	 * anschließend nach PKIX-Algorithmus validiert werden.
	 * 
	 * @param toValidate ein oder mehrere Zertifikate
	 * @return Zertifikatskette für Überprüfung
	 */
	private CertPath buildPath(X509Certificate... toValidate)
			throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
			NoSuchProviderException, KeyStoreException, CertPathBuilderException {

		List<X509Certificate> chainWithoutRoot = Arrays.asList(toValidate);
		// falls Kette aus mehreren Zert. Root-CA herausfiltern
		if (toValidate.length > 1) {

			// Kette ohne Root-CA aufbauen (Root ist als TrustAnchor definiert)
			chainWithoutRoot = chainWithoutRoot.stream()
					.filter(cert -> !cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal()))
					.collect(Collectors.toList());
		}

		if (chainWithoutRoot.size() == 0) {
			throw new IllegalArgumentException("leere Zertifikatskette übergeben");
		} else if (chainWithoutRoot.size() == 1) {
			X509Certificate endEntityCertificate = chainWithoutRoot.get(0);
			// CertStore mit dem Zertifikat erzeugen

			CertStore certStore = createCertStore(endEntityCertificate);
			// Ziel-Zertifikat mit CertSelector definieren
			X509CertSelector certSelector = createSelector(endEntityCertificate);

			// Zertifizierungspfad aufbauen
			CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
			CertPathBuilderResult result = certPathBuilder.build(createBuilderParameters(certStore, certSelector));

			return result.getCertPath();
		} else {
			CertificateFactory certFactory = CertificateFactory.getInstance("X509");
			return certFactory.generateCertPath(chainWithoutRoot);
		}
	}

	private void handleSoftFailures(PKIXRevocationChecker rc) {

		if (!rc.getSoftFailExceptions().isEmpty()) {
			rc.getSoftFailExceptions().forEach(securityException -> {
				securityException.printStackTrace();
			});
		}
	}

	private PKIXBuilderParameters createBuilderParameters(CertStore certStore, CertSelector certSelector)
			throws KeyStoreException, InvalidAlgorithmParameterException {
		PKIXBuilderParameters certPathBuilderParams = new PKIXBuilderParameters(trustStore, certSelector);
		certPathBuilderParams.addCertStore(certStore);
		// beim Bauen des Pfades ist kein Revocation-Check nötig, wird später gemacht
		certPathBuilderParams.setRevocationEnabled(false);
		return certPathBuilderParams;

	}

	private X509CertSelector createSelector(X509Certificate toValidate) throws IOException {
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setCertificate(toValidate);
		certSelector.setSubject(toValidate.getSubjectDN().getName()); // seems to be required
		return certSelector;
	}

	private CertStore createCertStore(X509Extension... toValidate)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		ArrayList<X509Extension> certs = new ArrayList<X509Extension>(Arrays.asList(toValidate));
		CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(certs);
		CertStore certStore = CertStore.getInstance("Collection", certStoreParams);
		return certStore;

	}

}
