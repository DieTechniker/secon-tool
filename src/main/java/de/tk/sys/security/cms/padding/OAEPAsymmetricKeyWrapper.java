/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

/**
 * Verpackt den symmetrischen Content-Encryption-Key für eine CMS-Nachricht. Der symmetrische Schlüssel wird mit dem
 * öffentlichen Schlüssels des Empfängers unter Verwendung des RSAES-OAEP-Algorithmus verschlüsselt.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class OAEPAsymmetricKeyWrapper extends BcAsymmetricKeyWrapper {

	public OAEPAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, PublicKey publicKey) throws IOException {
		super(encAlgId, PublicKeyFactory.createKey(publicKey.getEncoded()));
	}

	@Override
	protected AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
		return CMSAlgorithms.createOEAPEncoding();
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
