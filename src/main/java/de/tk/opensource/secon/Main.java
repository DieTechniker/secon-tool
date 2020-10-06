/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.opensource.secon;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.*;

/**
 * Ein Kommandozeilenwerkzeug, welches einem Kommunikationsteilnehmer im Krankenkassenkommunikationssystem (KKS)
 * ermöglicht, digital signierte und verschlüsselte Nachrichten zu generieren oder zu lesen.
 *
 * @author  Christian Schlichtherle
 */
public final class Main {

	public static void main(final String... args) throws SeconException {
		try {
			new Main(args).run();
		} catch (final IllegalArgumentException e) {
			System.err.print(
				""
				+ "Error: "
				+ e.getMessage()
				+ "\n\n"
				+ "Usage:\n\n"
				+ "To sign and encrypt:\n\n"
				+ "    java -jar build/libs/secon-tool-*-all.jar \\\n"
				+ "        -recipient <identifier> \\\n"
				+ "        -source <plainfile> -sink <cipherfile> \\\n"
				+ "        -keystore <storefile> -storepass <password> [-storetype <type>] \\\n"
				+ "        -alias <name> [-keypass <password>] \\\n"
				+ "       [-ldap <url>]\n\n"
				+ "To decrypt and verify:\n\n"
				+ "    java -jar build/libs/secon-tool-*-all.jar \\\n"
				+ "        -source <cipherfile> -sink <plainfile> \\\n"
				+ "        -keystore <storefile> -storepass <password> [-storetype <type>] \\\n"
				+ "        -alias <name> [-keypass <password>] \\\n"
				+ "       [-ldap <url>]\n\n"
				+ "Parameters:\n\n"
				+ "    -alias <name>\n"
				+ "        The alias name of the private key entry in the Java key store which is used to prove your identity.\n\n"
				+ "    -keypass <password>\n"
				+ "        The password for the private key entry in the Java key store.\n"
				+ "        If not provided then it defaults to the password for the Java key store.\n\n"
				+ "    -keystore <path>\n"
				+ "        The pathname of a file for the Java key store.\n\n"
				+ "    -ldap <url>\n"
				+ "        The URL of an LDAP server holding the certificate of the communication partner.\n"
				+ "        The LDAP server must allow anonymous access and the schema of its Directory Information Tree must conform to\n"
				+ "        chapter 4.6.2  \"LDAP-Verzeichnis\" der \"Security-Schnittstelle (SECON) - Anlage 16\", see\n"
				+ "        https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf .\n"
				+ "        If not provided then the certificate is only looked up in the Java key store.\n\n"
				+ "    -recipient <identifier>\n"
				+ "        The identifier of the message recipient. This is can be an alias in the Java key store or an\n"
				+ "        \"Institutionskennzeichen\" in the LDAP server, if configured.\n\n"
				+ "    -sink <path>\n"
				+ "    -source <path>\n"
				+ "        The pathname of a file for the plaintext or the ciphertext.\n\n"
				+ "    -storepass <password>\n"
				+ "        The password for the Java key store.\n\n"
				+ "    -storetype <type>\n"
				+ "        The type of the Java key store, see\n"
				+ "        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore .\n"
				+ "        If not provided then it defaults to PKCS12.\n"
			);
			System.exit(1);
		}
	}

	private final Map<String, String> options = new HashMap<>();

	private Main(final String[] _args) {
		final List<String> args = Arrays.asList(_args);
		for (final Iterator<String> it = args.iterator(); it.hasNext();) {
			final String arg = it.next();
			if (arg.startsWith("-")) {
				if (it.hasNext()) {
					final String value = it.next();
					options.put(arg.substring(1), value);
				} else {
					throw new IllegalArgumentException(arg + " parameter has no value.");
				}
			} else {
				throw new IllegalArgumentException(
					arg
					+ " is not a valid parameter name because it doesn't start with a '-' character."
				);
			}
		}
	}

	private void run() throws SeconException {
		final KeyStore keyStore =
			keyStore(
				() -> new FileInputStream(param("keystore")),
				param("storepass")::toCharArray,
				optParam("storetype").orElse("PKCS12")
			);
		final Identity identity =
			identity(keyStore, param("alias"), optParam("keypass").orElseGet(optParam("storepass")::get)::toCharArray);
		final Directory keyStoreDir = directory(keyStore);
		final Subscriber subscriber =
			optParam("ldap")
				.map(url -> directory(URI.create(url)))
				.map(ldapDir -> subscriber(identity, keyStoreDir, ldapDir))
				.orElseGet(() -> subscriber(identity, keyStoreDir));
		final Callable<InputStream> source = () -> new FileInputStream(param("source"));
		final Callable<OutputStream> sink = () -> new FileOutputStream(param("sink"));
		final Optional<String> recipient = optParam("recipient");
		if (recipient.isPresent()) {
			copy(source, subscriber.signAndEncryptTo(sink, recipient.get()));
		} else {
			copy(subscriber.decryptAndVerifyFrom(source), sink);
		}
	}

	private String param(String name) {
		return
			Optional
				.ofNullable(options.get(name))
				.orElseThrow(() -> new IllegalArgumentException("-" + name + " parameter is undefined."));
	}

	private Optional<String> optParam(String name) {
		return Optional.ofNullable(options.get(name));
	}
}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
