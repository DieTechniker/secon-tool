/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

/**
 * Enthält Konstanten für die verschiedenen Signatur- und Verschlüsselungsalgorithmen, die im PKCS7/CMS-Umfeld verwendet
 * werden.<br/>
 * RSAES-OAEP: spezielles Padding-Verfahren für RSA-Verschlüsselung<br/>
 * RSASSA-PSS: RSA-basiertes Signaturverfahren mit erweitertem Padding-Algorithmus<br/>
 * <br/>
 * <a
 * href="https://gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">
 * Security-Schnittstelle</a>
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class CMSAlgorithms {

	// OAEP-Parameter
	private static final AlgorithmIdentifier OAEP_HASH_ALGORITHM =
		new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
	private static final AlgorithmIdentifier OAEP_MASK_GEN_FUNCTION =
		new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, OAEP_HASH_ALGORITHM);
	private static final AlgorithmIdentifier OAEP_P_SOURCE =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_pSpecified,
			new DEROctetString(PSource.PSpecified.DEFAULT.getValue())
		);

	/**
	 * Parameter-Definition für RSAES-OAEP-Verschlüsselung (Hash-Algorithmus, MaskGen-Funktion, "Label L = empty
	 * String")
	 */
	public static final AlgorithmIdentifier ENCRYPTION_ALGORITHM_RSAES_OEAP =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_RSAES_OAEP,
			new RSAESOAEPparams(OAEP_HASH_ALGORITHM, OAEP_MASK_GEN_FUNCTION, OAEP_P_SOURCE)
		);

	/**
	 * Hash-Algorithmus für Signatur
	 */
	public static final AlgorithmIdentifier SIGNATURE_DIGEST_ALGORITHM =
		new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

	/**
	 * Erzeugt die Parameter für das OAEP-Paddingverfahren
	 *
	 * @return
	 */
	public static OAEPEncoding createOEAPEncoding() {
		return
			new OAEPEncoding(
				new RSAEngine(),
				DigestFactory.getDigest("SHA-256"),
				DigestFactory.getDigest("SHA-256"),
				PSource.PSpecified.DEFAULT.getValue()
			);
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
