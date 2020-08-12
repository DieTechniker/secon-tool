/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
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

import de.tk.sys.security.cms.api.PKCS7KeyLocator;
import de.tk.sys.security.cms.padding.CMSAlgorithms;
import de.tk.sys.security.cms.padding.OAEPKeyTransEnvelopedRecipient;
import de.tk.sys.security.cms.padding.OAEPTransRecipientInfoGenerator;
import de.tk.sys.security.cms.padding.PSSContentSignerBuilder;

/**
 * ACHTUNG!!! Diese Klasse befindet sich noch in der Entwicklung und ist nicht für den produktiven Einsatz gedacht<br/>
 * <br/>
 * Implementierung für PKCS#7 a.k.a. CMS-basierte Ver-/Entschlüsselung. Welche Schlüssel verwendet werden, wird über die
 * jeweilige Implementierung von {@link PKCS7KeyLocator} gesteuert. Diese Implementierung verwendet die
 * Streaming-Variante der Bouncycastle CMS-API und ist daher besser für große Datenmengen geeignet.
 *
 * @see     PKCS7KeyLocator
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
class PKCS7StreamEncryptionServiceImpl {

	private static final ASN1ObjectIdentifier ENCRYPTION_ALGORITHM = CMSAlgorithm.AES256_CBC;

	private static final Logger LOGGER = LoggerFactory.getLogger(PKCS7StreamEncryptionServiceImpl.class);

	private final PKCS7KeyLocator keyLocator;

	/**
	 * Initialisiert den Service mit einem {@link PKCS7KeyLocator}
	 *
	 * @param  locator  Steuert den Zugriff auf die nötigen Schlüssel
	 */
	public PKCS7StreamEncryptionServiceImpl(PKCS7KeyLocator locator) {
		this.keyLocator = locator;
	}

	public void signAndEncrypt(InputStream payload, OutputStream output, String identifier) {

		try {
			OutputStream enryptionStream = encrypt(output, identifier);
			OutputStream signatureStream = sign(enryptionStream, identifier);
			IOUtils.copy(payload, signatureStream);

			signatureStream.close();
			enryptionStream.close();

		} catch (Exception e) {
			throw new RuntimeException("Fehler bei der Verschlüsselung/Signatur für " + identifier, e);
		}
	}

	public InputStream decryptAndVerify(InputStream signedAndEncrypted, String identifier) {
		try {
			InputStream decrypted = decrypt(signedAndEncrypted, identifier);

			//TODO wie kann man entschlüsseln und Signatur verifizieren ohne den Stream doppelt zu lesen oder zwischenzuspeichern???
			//decrypted.mark(Integer.MAX_VALUE);
			return verify(decrypted, identifier);
			//decrypted.reset();
			//return getContents(decrypted, identifier);
		} catch (Exception e) {
			throw new RuntimeException("Fehler bei der Entschlüsselung/Signaturprüfung für " + identifier, e);
		}
	}

	private OutputStream sign(OutputStream output, String employerNumber) throws OperatorCreationException,
		CertificateEncodingException, CMSException, IOException
	{
		X509Certificate signatureCertificate = keyLocator.lookupSignatureCertificate();
		PrivateKey signatureKey = keyLocator.lookupSignatureKey();
		ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(signatureCertificate.getSigAlgOID());
		byte[] sigAlgParams = signatureCertificate.getSigAlgParams();

		CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

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

		return gen.open(output, true);
	}

	private OutputStream encrypt(OutputStream signedOutputStream, String employerNumber)
		throws CertificateEncodingException, CMSException, IOException, InvalidAlgorithmParameterException,
			InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchProviderException
	{
		CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();

		X509Certificate recipient = keyLocator.lookupEncryptionCertificate(employerNumber);

		if (getKeySize(recipient) < 4096) {
			generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient));
		} else {
			generator.addRecipientInfoGenerator(
				new OAEPTransRecipientInfoGenerator(recipient, CMSAlgorithms.ENCRYPTION_ALGORITHM_RSAES_OEAP)
			);
		}

		return
			generator.open(
				signedOutputStream,
				new JceCMSContentEncryptorBuilder(ENCRYPTION_ALGORITHM)
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build()
			);
	}

	private InputStream decrypt(InputStream signedAndEncrypted, String employerNumber) throws CMSException,
		IOException
	{
		CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(new BufferedInputStream(signedAndEncrypted, 1024));

		X509Certificate recipientCertificate = keyLocator.lookupDecryptionCertificate();
		RecipientInformationStore recipientInfos = ep.getRecipientInfos();
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

		Recipient recipient = null;
		PrivateKey decryptionKey = keyLocator.lookupDecryptionKey();

		// falls Schlüssellänge >= 4096 RSAES-OAEP, sonst RSA
		if (getKeySize(recipientCertificate) < 4096) {
			recipient =
				new JceKeyTransEnvelopedRecipient(decryptionKey).setProvider(BouncyCastleProvider.PROVIDER_NAME);
		} else {
			recipient = new OAEPKeyTransEnvelopedRecipient(decryptionKey);
		}
		CMSTypedStream recData = recipientFromContent.getContentStream(recipient);
		return recData.getContentStream();
	}

	private int getKeySize(X509Certificate recipient) {
		RSAPublicKey rsaPk = (RSAPublicKey) recipient.getPublicKey();
		int keySize = rsaPk.getModulus().bitLength();
		return keySize;
	}

//  private InputStream getContents(InputStream signed, String employerNumber) throws OperatorCreationException,
//      CMSException, IOException
//  {
//      CMSSignedDataParser sp =
//          new CMSSignedDataParser(
//              new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(),
//              new BufferedInputStream(signed, 1024)
//          );
//      CMSTypedStream signedContent = sp.getSignedContent();
//      if (signedContent != null) {
//          return signedContent.getContentStream();
//      } else {
//          throw new IllegalStateException("Keine Daten gefunden");
//      }
//  }

	private InputStream verify(InputStream signed, String identifier) throws OperatorCreationException, CMSException,
		IOException
	{
		CMSSignedDataParser sp =
			new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(),
				new BufferedInputStream(signed, 1024)
			);
		File tempFile = File.createTempFile(identifier, "decrypted");
		CMSTypedStream signedContent = sp.getSignedContent();
		if (signedContent != null) {

			IOUtils.copy(signedContent.getContentStream(), new FileOutputStream(tempFile));
			//signedContent.drain();
		}
		SignerInformationStore signers = sp.getSignerInfos();

		for (Object signerInfo : signers.getSigners()) {
			SignerInformation signer = (SignerInformation) signerInfo;

			X500Name issuer = signer.getSID().getIssuer();
			BigInteger serialNumber = signer.getSID().getSerialNumber();

			X509Certificate signatureVerificationCert =
				keyLocator.lookupVerificationCertificate(
					serialNumber,
					new X500Principal(issuer.getEncoded()),
					identifier
				);

			LOGGER.info(MessageFormat.format("Prüfe Signatur für Zertifikat {0}, {1,number,#}", issuer, serialNumber));

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

		return new FileInputStream(tempFile);
		//return signedContent.getContentStream();
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
