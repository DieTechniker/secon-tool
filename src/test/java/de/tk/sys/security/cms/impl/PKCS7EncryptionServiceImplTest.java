/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Tag("UnitTest")
public class PKCS7EncryptionServiceImplTest {

	@BeforeAll
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * KV sendet signierte und verschlüsselte Nachricht an Arbeitgeber, Arbeitgeber entschlüsselt und überprüft die
	 * Signatur der KV
	 */
	@Test
	void nachricht_KV_an_Arbeitgeber() throws Exception {

		// Keystores und Zertifikate initialiseren
		KeystoreKeyLocator locator = setupKeys("techniker.p12", "arbeitgeber.p12");
		PKCS7EncryptionServiceImpl service = new PKCS7EncryptionServiceImpl(locator);

		// Nachricht für Arbeitgeber verschlüsseln und signieren
		InputStream signedAndEncrypted =
			service.signAndEncrypt(new ByteArrayInputStream("testnachricht".getBytes("UTF-8")), "12345678");

		// Nachricht entschlüsseln und prüfen
		InputStream decryptedAndVerified = service.decryptAndVerify(signedAndEncrypted, "12345678");

		verifyMessage(decryptedAndVerified, "testnachricht");
	}

	private void verifyMessage(InputStream decryptedAndVerified, String plainText) throws IOException {
		byte[] byteArray = IOUtils.toByteArray(decryptedAndVerified);
		assertEquals(plainText, new String(byteArray));
	}

	/**
	 * Arbeitgeber sendet signierte und verschlüsselte Nachricht an KV, KV entschlüsselt und überprüft die Signatur des
	 * Arbeitgebers
	 */
	@Test
	void nachricht_Arbeitgeber_an_KV() throws Exception {

		// Keystores und Zertifikate initialiseren
		KeystoreKeyLocator locator = setupKeys("arbeitgeber.p12", "techniker.p12");
		PKCS7EncryptionServiceImpl service = new PKCS7EncryptionServiceImpl(locator);

		// Nachricht für Empfaenger verschlüsseln und signieren
		InputStream signedAndEncrypted =
			service.signAndEncrypt(new ByteArrayInputStream("testnachricht".getBytes("UTF-8")), "12345678");

		// Nachricht entschlüsseln und prüfen
		InputStream decryptedAndVerified = service.decryptAndVerify(signedAndEncrypted, "12345678");

		verifyMessage(decryptedAndVerified, "testnachricht");
	}

	private KeystoreKeyLocator setupKeys(String senderKey, String recipientKey) throws Exception, KeyStoreException {
		KeyStore sender = loadKeystore(this.getClass().getResourceAsStream(senderKey), "tkeasy");
		KeyStore recipient = loadKeystore(this.getClass().getResourceAsStream(recipientKey), "tkeasy");

		return new KeystoreKeyLocator(sender, recipient);
	}

	private KeyStore loadKeystore(InputStream stream, String password) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(stream, password.toCharArray());
		return ks;
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
