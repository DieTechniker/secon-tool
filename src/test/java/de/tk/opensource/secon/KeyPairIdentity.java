package de.tk.opensource.secon;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

class KeyPairIdentity implements Identity {

	private static final String SHA256_WITH_RSA_ENCRYPTION = "SHA256WithRSAEncryption";
	private final KeyPair pair;
	private final X509Certificate certificate;

	private static X500Name ROOT_DN = new X500Name("CN=root-cert");
	private static final KeyPair ROOT_KEY = createKeyPair();
	private static final X509Certificate ROOT_CERT = generateRootCertificate(ROOT_KEY, 1000, SHA256_WITH_RSA_ENCRYPTION);
	
	
	public KeyPairIdentity(String distinguishedName, int validityDays) {
		super();
		try {
			this.pair = createKeyPair();
			certificate = generateCertificate(distinguishedName, pair, validityDays, SHA256_WITH_RSA_ENCRYPTION);
			certificate.verify(ROOT_CERT.getPublicKey(), "BC");
		} catch (Exception e) {
			throw new RuntimeException("Error initializing KeyPair-Identity", e);
		}
	}
	@Override
	public PrivateKey privateKey() throws Exception {
		return pair.getPrivate();
	}

	@Override
	public X509Certificate certificate() throws Exception {
		return certificate;
	}

	private static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
			throws CertificateException {

		try {
			Security.addProvider(new BouncyCastleProvider());
			X500Name name = new X500Name(dn);
			Date from = new Date();
			Date to = new Date(from.getTime() + days * 86400000L);
			BigInteger sn = new BigInteger(64, new SecureRandom());			
			
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(name, pair.getPublic());
	        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SHA256_WITH_RSA_ENCRYPTION).setProvider("BC");

	        // Sign the new KeyPair with the root cert Private Key
	        ContentSigner csrContentSigner = csrBuilder.build(ROOT_KEY.getPrivate());
	        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

	        // Use the Signed KeyPair and CSR to generate an issued Certificate
	        // Here serial number is randomly generated. In general, CAs use
	        // a sequence to generate Serial number and avoid collisions
	        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(ROOT_DN, sn, from, to, csr.getSubject(), csr.getSubjectPublicKeyInfo());

	        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

	        // Add Extensions
	        // Use BasicConstraints to say that this Cert is not a CA
	        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

	        // Add Issuer cert identifier as Extension
	        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(ROOT_CERT));
	        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

	        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
	        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(issuedCertHolder);			
		} catch (CertificateException ce) {
			throw ce;
		} catch (Exception e) {
			throw new CertificateException(e);
		}
	}
	
	public static X509Certificate generateRootCertificate(KeyPair pair, int days, String algorithm) {

		try {
			Security.addProvider(new BouncyCastleProvider());
			
			Date from = new Date();
			Date to = new Date(from.getTime() + days * 86400000L);
			BigInteger sn = new BigInteger(64, new SecureRandom());
			
			
	        X500Name rootCertSubject = ROOT_DN;
	        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(algorithm).setProvider("BC").build(pair.getPrivate());
	        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(ROOT_DN, sn, from, to, rootCertSubject, pair.getPublic());

	        // Add Extensions
	        // A BasicConstraint to mark root certificate as CA certificate
	        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
	        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
	        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(pair.getPublic()));

	        // Create a cert holder and export to X509Certificate
	        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
	        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);
		} catch (Exception ce) {
			throw new RuntimeException(ce);
		}
	}
	private static KeyPair createKeyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(4096, new SecureRandom());
			return keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public X509Certificate getRootCert() {
		return ROOT_CERT;
	}

}
