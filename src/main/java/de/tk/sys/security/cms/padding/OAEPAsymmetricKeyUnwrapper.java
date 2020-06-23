/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;

/**
 * Packt den symmetrischen Content-Encryption-Key für eine CMS-Nachricht aus. Der symmetrische Schlüssel wird mittels
 * RSAES-OEAP-Algorithmus entschlüsselt. Dazu wird der private Schlüssel des Nachrichtenenmpfängers benötigt.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class OAEPAsymmetricKeyUnwrapper extends BcRSAAsymmetricKeyUnwrapper {

	public OAEPAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey) {
		super(encAlgId, privateKey);
	}

	@Override
	protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm) {
		return CMSAlgorithms.createOEAPEncoding();
	}
}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
