package de.tk.opensource.secon;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.io.IOException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

class SignatureValidator {

	private final Verifier verifier;
	private final Directory[] directories;

	public SignatureValidator(Verifier verifier, Directory[] directories) {
		super();
		this.verifier = verifier;
		this.directories = directories;
	}
	
	/**
	 * Prüft die in der Nachricht enthaltene Signatur. Zunächst wird versucht das Signaturzertifikat aus dem eigenen Verzeichnis zu ermitteln.
	 * Wird das Signaturzertifikat nicht gefunden, werden die in der Nachricht enthaltenen Signaturzertifikate zur Prüfung verwendet.
	 * Für jedes in der Nachricht enthaltene Zertifikat wird geprüft ob dessen Aussteller im eigenen Verzeichnis gefunden werden kann.
	 * 
	 * @param info Signaturinformation aus der Nachricht
	 * @param certificates in der Nachricht enthaltene Zertifikate
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public void verify(SignerInformation info, Store<X509CertificateHolder> certificates) throws Exception {
		Optional<X509Certificate> certificateFromDir = certificate(info.getSID());

		if (certificateFromDir.isPresent()) {
			// Signaturprüfung mit dem Zertifikat aus eigenem Verzeichnis
			verify(info, certificateFromDir.get());
		} else {
			// Signaturprüfung mit den Zertifikaten aus der Nachricht
			verify(info, certificates.getMatches(info.getSID()));
		}
	}


	/**
	 * Prüft die Signatur anhand einer Menge von Zertifikaten. Für jedes Zertifikat muss zumindest dessen Aussteller im Verzeichnis bekannt sein. 
	 * 
	 * @param info Signaturinformation aus der Nachricht
	 * @param certCollection Zertifikate aus der Nachricht
	 * @throws Exception
	 */
	private void verify(SignerInformation info, Collection<X509CertificateHolder> certCollection) throws Exception {
		if (certCollection.isEmpty()) {
			throw new IllegalArgumentException("No certificates found for verification of signer: "+info.getSID().getSerialNumber());
		}
		for (X509CertificateHolder certHolder : certCollection) {
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
			Optional<X509Certificate> issuer = issuer(cert.getIssuerX500Principal());
			if(issuer.isPresent()) {
				verifyIssuer(cert, issuer.get());
				verifySignature(verifier, info, cert);
			} else {
				throw new CertificateNotFoundException(String.format("Issuer: %s not found for certificate: %s", cert.getIssuerX500Principal().getName(), cert.getSubjectX500Principal().getName()));
			}
		}
	}

	private void verifyIssuer(X509Certificate certToVerify, X509Certificate parent) throws CertificateVerificationException {
		try {
			certToVerify.verify(parent.getPublicKey());
		} catch (Exception e) {
			throw new CertificateVerificationException(String.format("Invalid issuer certificate for certificate: %s", certToVerify.getSubjectX500Principal().getName()), e);
		}	
	}

	/**
	 * Prüft die Signatur anhand des gegebenen Zertifikats 
	 * 
	 * @param info Signaturinformation aus der Nachricht
	 * @param cert Signatur-Zertifikat
	 * @throws Exception
	 */
	private void verify(SignerInformation info, X509Certificate cert) throws Exception {
		verifySignature(verifier, info, cert);
	}
	
	private void verifySignature(final Verifier verifier, final SignerInformation info, final X509Certificate signerCert)
			throws OperatorCreationException, CMSException, InvalidSignatureException, CertificateVerificationException,
			Exception {
		final SignerInformationVerifier ver = new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER_NAME)
				.build(signerCert);
		if (!info.verify(ver)) {
			throw new InvalidSignatureException();
		}
		verifier.verify(signerCert);
	}

	private Optional<X509Certificate> certificate(SignerId id) throws Exception {
		final X509CertSelector selector = selector(id);
		for (final Directory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(selector);
			if (cert.isPresent()) {
				return cert;
			}
		}
		return Optional.empty();
	}
	
	private Optional<X509Certificate> issuer(X500Principal issuer) throws Exception {
		final X509CertSelector selector = selector(issuer);
		for (final Directory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(selector);
			if (cert.isPresent()) {
				return cert;
			}
		}
		return Optional.empty();
	}

	private static X509CertSelector selector(final X500Principal subject) {
		final X509CertSelector sel = new X509CertSelector();
		sel.setSubject(subject);
		return sel;
	}

	private static X509CertSelector selector(final SignerId id) {
		final X509CertSelector sel = new X509CertSelector();
		Optional.ofNullable(id.getIssuer()).ifPresent(issuer -> sel.setIssuer(principal(issuer)));
		sel.setSerialNumber(id.getSerialNumber());
		sel.setSubjectKeyIdentifier(id.getSubjectKeyIdentifier());
		return sel;
	}

	private static X500Principal principal(final X500Name name) {
		try {
			return new X500Principal(name.getEncoded());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

}
