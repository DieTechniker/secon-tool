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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.*;

/**
 * Ein Kommandozeilenwerkzeug, welches einem Kommunikationsteilnehmer im Krankenkassenkommunikationssystem (SECON)
 * ermöglicht, digital signierte und verschlüsselte Nachrichten zu generieren oder zu lesen.
 *
 * @author  Christian Schlichtherle
 */
public final class Main {

	private final Map<String, String> options = new HashMap<>();

	public static void main(final String... args) throws SeconException {
		try {
			new Main(args).run();
		} catch (final IllegalArgumentException e) {
			System.err.println(
				"Error:\n"
				+ "\t"
				+ e
				+ "\n"
				+ "\n"
				+ "Usage:\n"
				+ "\n"
				+ "\tTo sign and encrypt:\n"
				+ "\n"
				+ "\t\tsecon-tool -recipient <identifier> -source <plainfile> -sink <cipherfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> [-keypass <password>] [-ldap <url>]\n"
				+ "\n"
				+ "OR\n"
				+ "\n"
				+ "\tTo decrypt and verify:\n"
				+ "\n"
				+ "\t\tsecon-tool -source <cipherfile> -sink <plainfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> [-keypass <password>] [-ldap <url>]\n"
			);
			System.exit(1);
		}
	}

	private Main(final String[] _args) {
		final List<String> args = new LinkedList<>(Arrays.asList(_args));
		for (final Iterator<String> it = args.iterator(); it.hasNext();) {
			final String arg = it.next();
			if (arg.startsWith("-")) {
				it.remove();
				if (it.hasNext()) {
					final String value = it.next();
					it.remove();
					options.put(arg.substring(1), value);
				}
			}
		}
		if (!args.isEmpty()) {
			throw new IllegalArgumentException("Too many arguments!");
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

	private String param(final String name) {
		final String value = options.get(name);
		if (null != value) {
			return value;
		}
		throw new IllegalArgumentException("-" + name + " parameter is undefined!");
	}

	private Optional<String> optParam(String name) {
		return Optional.ofNullable(options.get(name));
	}
}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
