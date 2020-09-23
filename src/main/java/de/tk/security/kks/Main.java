/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of kks-encryption
 * (see https://github.com/DieTechniker/kks-encryption).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tk.security.kks;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.Callable;

import static de.tk.security.kks.KKS.*;

/**
 * Ein Kommandozeilenwerkzeug, welches einem Kommunikationsteilnehmer im Krankenkassenkommunikationssystem (KKS)
 * ermöglicht, digital signierte und verschlüsselte Nachrichten zu generieren oder zu lesen.
 *
 * @author Christian Schlichtherle
 */
public final class Main {

    private final Map<String, String> options = new HashMap<>();

    public static void main(final String... args) throws KksException {
        try {
            new Main(args).run();
        } catch (final IllegalArgumentException e) {
            System.err.println(
                    "Error:\n" +
                            "\t" + e + "\n" +
                            "\n" +
                            "Usage:\n" +
                            "\n" +
                            "\tTo sign and encrypt:\n" +
                            "\n" +
                            "\t\tkks -recipient <identifier> -source <plainfile> -sink <cipherfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> [-keypass <password>] [-ldap <url>]\n" +
                            "\n" +
                            "OR\n" +
                            "\n" +
                            "\tTo decrypt and verify:\n" +
                            "\n" +
                            "\t\tkks -source <cipherfile> -sink <plainfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> [-keypass <password>] [-ldap <url>]\n"
            );
            System.exit(1);
        }
    }

    private Main(final String[] _args) {
        final List<String> args = new LinkedList<>(Arrays.asList(_args));
        for (final Iterator<String> it = args.iterator(); it.hasNext(); ) {
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

    private void run() throws KksException {
        final KeyStore keyStore = keyStore(
                () -> new FileInputStream(param("keystore")),
                param("storepass")::toCharArray,
                optParam("storetype").orElse("PKCS12")
        );
        final KksIdentity identity = identity(
                keyStore,
                param("alias"),
                optParam("keypass").orElseGet(optParam("storepass")::get)::toCharArray
        );
        final KksDirectory keyStoreDir = directory(keyStore);
        final KksSubscriber subscriber = optParam("ldap")
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
