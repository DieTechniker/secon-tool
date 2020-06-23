/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

/**
 * {@link Recipient} der einen mit RSAES-OAEP verschlüsselten Schlüssel erwartet.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class OAEPKeyTransEnvelopedRecipient extends BcRSAKeyTransEnvelopedRecipient {

	private AsymmetricKeyParameter key;

	/**
	 * Erzeugt eine neue Instanz unter Verwendung des privaten Schlüssels des Empfängers
	 *
	 * @param   key
	 *
	 * @throws  IOException
	 */
	public OAEPKeyTransEnvelopedRecipient(PrivateKey key) throws IOException {
		this(PrivateKeyFactory.createKey(key.getEncoded()));
	}

	OAEPKeyTransEnvelopedRecipient(AsymmetricKeyParameter key) {
		super(key);
		this.key = key;
	}

	@Override
	protected CipherParameters extractSecretKey(
		AlgorithmIdentifier keyEncryptionAlgorithm,
		AlgorithmIdentifier encryptedKeyAlgorithm,
		byte[]				encryptedEncryptionKey
	) throws CMSException
	{
		AsymmetricKeyUnwrapper unwrapper = new OAEPAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, key);

		try {
			return getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
		} catch (OperatorException e) {
			throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
		}
	}

	static CipherParameters getBcKey(GenericKey key) {
		if ((key.getRepresentation() instanceof CipherParameters)) {
			return (CipherParameters) key.getRepresentation();
		}

		if ((key.getRepresentation() instanceof byte[])) {
			return new KeyParameter((byte[]) key.getRepresentation());
		}

		throw new IllegalArgumentException("unknown generic key type");
	}
}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
