package de.tk.opensource.secon;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

public class KeyPairIdentity implements Identity {

	private final KeyPair pair;
	private final X509Certificate certificate;

	public KeyPairIdentity(KeyPair pair) {
		super();
		this.pair = pair;

		try {
			certificate = generateCertificate("CN=John Doe", pair, 10, "SHA256WithRSAEncryption");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
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
	
	public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
			throws CertificateException {
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
			ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
			X500Name name = new X500Name(dn);
			Date from = new Date();
			Date to = new Date(from.getTime() + days * 86400000L);
			BigInteger sn = new BigInteger(64, new SecureRandom());
			
			X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(name, sn, from, to, name, subPubKeyInfo);
			X509CertificateHolder certificateHolder = v1CertGen.build(sigGen);
			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		} catch (CertificateException ce) {
			throw ce;
		} catch (Exception e) {
			throw new CertificateException(e);
		}
	}

}
