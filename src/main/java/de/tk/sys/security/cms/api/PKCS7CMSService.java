/*--- (C) 1999-2019 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.api;

import java.io.InputStream;

/**
 * Schnittstelle für das Entschlüsseln und Verschlüsseln von Nachrichten im PKCS#7/CMS-Format. Nachrichten müssen
 * grundsätzlich mit Signaturen versehen werden. Beim Entschlüsseln wird die Signatur der Nachricht anhand des
 * entsprechenden Signatur-Zertifikats geprüft. Beim Verschlüsseln wird die Nachricht entsprechend mit dem
 * Signatur-Zertifikat signiert. Siehe auch <a href="https://tools.ietf.org/html/rfc5652">RFC5652</a>
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public interface PKCS7CMSService {

	/**
	 * Signiert und verschlüsselt eine Nachricht (erst Signieren dann Verschlüsseln). Die Nachricht wird zunächst
	 * signiert und als SignedData-Objekt verpackt. Danach wird die signierte Nachricht verschlüsselt und als
	 * EnvelopedData-Objekt zurückgeliefert.
	 *
	 * @param   payload     die zu verschlüsselnde Nachricht
	 * @param   identifier  die ID des Empfängers, z.B. die Arbeitgebernummer
	 *
	 * @return  InputStream auf die signierte und mit dem Public-Key des Empfängers verschlüsselte SMIME-Nachricht
	 */
	InputStream signAndEncrypt(InputStream payload, String identifier);

	/**
	 * Entschlüsselt eine Nachricht und überprüft die Signatur in der Nachricht.
	 *
	 * @param   signedAndEncrypted  signierte und verschlüsselte Nachricht
	 * @param   identifier          ID des Absenders/Signierenden
	 *
	 * @return  InputStream auf die entschlüsselte Nachricht im Klartext.
	 */
	InputStream decryptAndVerify(InputStream signedAndEncrypted, String identifier);

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
