/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.text.MessageFormat;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.ByteStreams;

import de.tk.sys.security.cms.api.PKCS7CMSService;
import de.tk.sys.security.cms.api.PKCS7KeyLocator;
import de.tk.sys.security.cms.padding.CMSAlgorithms;
import de.tk.sys.security.cms.padding.OAEPKeyTransEnvelopedRecipient;
import de.tk.sys.security.cms.padding.OAEPTransRecipientInfoGenerator;
import de.tk.sys.security.cms.padding.PSSContentSignerBuilder;

/**
 * Default-Implementierung für PKCS#7 a.k.a. CMS-basierte Ver-/Entschlüsselung. Welche Schlüssel verwendet werden, wird
 * über die jeweilige Implementierung von {@link PKCS7KeyLocator} gesteuert.
 *
 * @see     PKCS7KeyLocator
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class PKCS7EncryptionServiceImpl implements PKCS7CMSService {

	private static final ASN1ObjectIdentifier ENCRYPTION_ALGORITHM = CMSAlgorithm.AES256_CBC;

	private static final Logger LOGGER = LoggerFactory.getLogger(PKCS7EncryptionServiceImpl.class);

	private final PKCS7KeyLocator keyLocator;

	/**
	 * Initialisiert den Service mit einem {@link PKCS7KeyLocator}
	 *
	 * @param  locator  Steuert den Zugriff auf die nötigen Schlüssel
	 */
	public PKCS7EncryptionServiceImpl(PKCS7KeyLocator locator) {
		this.keyLocator = locator;
	}

	@Override
	public InputStream signAndEncrypt(InputStream payload, String identifier) {

		try {
			InputStream signedContent = sign(payload, identifier);
			return encrypt(signedContent, identifier);
		} catch (Exception e) {
			throw new RuntimeException("Fehler bei der Verschlüsselung/Signatur für " + identifier, e);
		}
	}

	@Override
	public InputStream decryptAndVerify(InputStream signedAndEncrypted, String identifier) {
		try {
			InputStream decrypted = decrypt(signedAndEncrypted, identifier);

			InputStream payload = verify(decrypted, identifier);
			return payload;
		} catch (Exception e) {
			throw new RuntimeException("Fehler bei der Entschlüsselung/Signaturprüfung für " + identifier, e);
		}
	}

	private InputStream sign(InputStream payload, String employerNumber) throws OperatorCreationException,
		CertificateEncodingException, CMSException, IOException
	{

		CMSTypedData msg = new CMSProcessableByteArray(ByteStreams.toByteArray(payload));

		X509Certificate signatureCertificate = keyLocator.lookupSignatureCertificate();
		PrivateKey signatureKey = keyLocator.lookupSignatureKey();
		ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(signatureCertificate.getSigAlgOID());
		byte[] sigAlgParams = signatureCertificate.getSigAlgParams();

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		ContentSigner signer = null;
		if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOID)) {
			AlgorithmIdentifier sigAlgId =
				new AlgorithmIdentifier(sigAlgOID, ASN1Primitive.fromByteArray(sigAlgParams));
			signer =
				new PSSContentSignerBuilder(sigAlgId, CMSAlgorithms.SIGNATURE_DIGEST_ALGORITHM).build(
					PrivateKeyFactory.createKey(signatureKey.getEncoded())
				);
		} else {
			signer =
				new JcaContentSignerBuilder(signatureCertificate.getSigAlgName())
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build(signatureKey);
		}

		gen.addSignerInfoGenerator(
			new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build()
			).build(signer, signatureCertificate)
		);

		CMSSignedData sigData = gen.generate(msg, true);

		return new ASN1InputStream(sigData.getEncoded());
	}

	private InputStream encrypt(InputStream payload, String employerNumber) throws CertificateEncodingException,
		CMSException, IOException, InvalidAlgorithmParameterException, InvalidParameterSpecException,
		NoSuchAlgorithmException, NoSuchProviderException
	{
		CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();

		X509Certificate recipient = keyLocator.lookupEncryptionCertificate(employerNumber);

		if (getKeySize(recipient) < 4096) {
			generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient));
		} else {
			generator.addRecipientInfoGenerator(
				new OAEPTransRecipientInfoGenerator(recipient, CMSAlgorithms.ENCRYPTION_ALGORITHM_RSAES_OEAP)
			);
		}

		CMSProcessableByteArray cmsData = new CMSProcessableByteArray(ByteStreams.toByteArray(payload));

		CMSEnvelopedData enveloped =
			generator.generate(
				cmsData,
				new JceCMSContentEncryptorBuilder(ENCRYPTION_ALGORITHM)
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build()
			);

		return new ASN1InputStream(enveloped.getEncoded());
	}

	private InputStream decrypt(InputStream signedAndEncrypted, String employerNumber) throws CMSException,
		IOException
	{
		CMSEnvelopedData envelopedMessage = new CMSEnvelopedData(signedAndEncrypted);
		X509Certificate recipientCertificate = keyLocator.lookupDecryptionCertificate();
		RecipientInformationStore recipientInfos = envelopedMessage.getRecipientInfos();
		RecipientInformation recipientFromContent =
			recipientInfos.get(new JceKeyTransRecipientId(recipientCertificate));

		if (recipientFromContent == null) {
			throw new IllegalArgumentException(
				MessageFormat.format(
					"Es wurde kein passender Empfänger (Public-Key) in der Nachricht von {0} gefunden.",
					employerNumber
				)
			);
		}

		PrivateKey decryptionKey = keyLocator.lookupDecryptionKey();

		Recipient recipient = determineKeyTransRecipient(recipientCertificate, recipientFromContent, decryptionKey);
		CMSTypedStream recData = recipientFromContent.getContentStream(recipient);
		return recData.getContentStream();
	}

	/*
	 * Schlüssel-Verschlüsselungsalgorithmus richtig ermitteln 1. falls Schlüssellänge >= 4096 und Parameter gegeben:
	 * RSAES-OAEP sonst Standard-RSA
	 */
	private Recipient determineKeyTransRecipient(
		X509Certificate		 recipientCertificate,
		RecipientInformation recipientFromContent,
		PrivateKey			 decryptionKey
	) throws IOException
	{
		Recipient recipient;
		DERSequence parameters = (DERSequence) recipientFromContent.getKeyEncryptionAlgorithm().getParameters();
		if (getKeySize(recipientCertificate) < 4096 || parameters.size() == 0) {
			recipient =
				new JceKeyTransEnvelopedRecipient(decryptionKey).setProvider(BouncyCastleProvider.PROVIDER_NAME);
		} else {
			recipient = new OAEPKeyTransEnvelopedRecipient(decryptionKey);
		}
		return recipient;
	}

	private int getKeySize(X509Certificate recipient) {
		RSAPublicKey rsaPk = (RSAPublicKey) recipient.getPublicKey();
		int keySize = rsaPk.getModulus().bitLength();
		return keySize;
	}

	private InputStream verify(InputStream signed, String employerNumber) throws OperatorCreationException,
		CMSException, IOException
	{

		try(ASN1InputStream asnInputStream = new ASN1InputStream(signed)) {
			CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
			SignerInformationStore signers = cmsSignedData.getSignerInfos();

			for (Object signerInfo : signers.getSigners()) {
				SignerInformation signer = (SignerInformation) signerInfo;

				X500Name issuer = signer.getSID().getIssuer();
				BigInteger serialNumber = signer.getSID().getSerialNumber();

				X509Certificate signatureVerificationCert =
					keyLocator.lookupVerificationCertificate(
						serialNumber,
						new X500Principal(issuer.getEncoded()),
						employerNumber
					);

				LOGGER.info(
					MessageFormat.format("Prüfe Signatur für Zertifikat {0}, {1,number,#}", issuer, serialNumber)
				);

				if (
					!signer.verify(
						new JcaSimpleSignerInfoVerifierBuilder()
							.setProvider(BouncyCastleProvider.PROVIDER_NAME)
							.build(signatureVerificationCert)
					)
				) {
					throw new IllegalStateException("Signaturprüfung fehlgeschlagen");
				}
			}

			CMSTypedData payload = cmsSignedData.getSignedContent();
			return new ByteArrayInputStream((byte[]) payload.getContent());
		}
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
