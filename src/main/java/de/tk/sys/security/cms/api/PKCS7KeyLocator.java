/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.api;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

/**
 * Ermittelt die für PKCS#7 nötigen Schlüssel und Zertifikate für Signatur, Verschlüsselung, Entschlüsselung und
 * Signaturprüfung. An welchem Ort die Schlüssel und Zertifikate verwaltet werden, bleibt der Implementierung überlassen
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public interface PKCS7KeyLocator {

	/**
	 * Gibt den öffentlichen Schlüssel des Empfängers mit der übergebenen ID zurück. Mit diesem Schlüssel wird die
	 * Nachricht verschlüsselt (oder genauer ein symmetrischer Schlüssel für die Nachrichtenverschlüsselung, siehe
	 * PKCS#7)
	 *
	 * @param   identifier  ID des Empfängers, z.B. Arbeitgebernummer o.ä.
	 *
	 * @return  öffentlicher Schlüssel des Nachrichtenempfängers
	 */
	X509Certificate lookupEncryptionCertificate(String identifier);

	/**
	 * Gibt das Signaturzertifikat des Absenders zurück. Die Informationen über den Signierer werden mit in die
	 * signierte Nachricht übernommen (Issuer und Seriennummer).
	 *
	 * @return  Signaturzertifikat des Absenders
	 */
	X509Certificate lookupSignatureCertificate();

	/**
	 * Gibt den privaten Schlüssel des Absenders zur Signatur der Nachricht zurück. Mit diesem Key wird die Nachricht
	 * signiert.
	 *
	 * @return  Signaturschlüssel
	 */
	PrivateKey lookupSignatureKey();

	/**
	 * @return  Gibt das Zertifikat für die Entschlüsselung der Nachricht zurück.
	 */
	X509Certificate lookupDecryptionCertificate();

	/**
	 * @return  Gibt den privaten Schlüssel für die Entschlüsselung einer empfangenen Nachricht zurück.
	 */
	PrivateKey lookupDecryptionKey();

	/**
	 * Gibt das Zertifikat zurück anhand dessen die Signatur der Nachricht überprüft werden soll. Es wird das Zertifikat
	 * zurückgegeben, welches zur übergebenen Seriennummer/Issuer-Kombination passt
	 *
	 * @param   serialNumber   Seriennummer des Zertifikats
	 * @param   x500Principal  Issuer-DN (Zertifikatsherausgeber)
	 * @param   identifier     Identifier der den Signaturersteller identifiziert (z.B. Betriebsnummer, IK o.ä.)
	 *
	 * @return  Zertifikat gegen das die Signatur geprüft wird.
	 */
	X509Certificate lookupVerificationCertificate(
		BigInteger    serialNumber,
		X500Principal x500Principal,
		String		  identifier
	);

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
