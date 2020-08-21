/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.tk.security.kks;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
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

    public static void main(final String... args) throws Exception {
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
                            "\t\tkks -recipient <aliasname> -source <plainfile> -sink <cipherfile> -keystore <storefile> -storepass <password> -alias <name> -keypass <password>\n" +
                            "\n" +
                            "OR\n" +
                            "\n" +
                            "\tTo decrypt and verify:\n" +
                            "\n" +
                            "\t\tkks -source <cipherfile> -sink <plainfile> -keystore <storefile> -storepass <password> -alias <name> -keypass <password>\n"
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

    private void run() throws Exception {
        final KeyStore ks = keyStore(() -> new FileInputStream(param("keystore")), param("storepass")::toCharArray);
        final KksSubscriber subscriber = subscriber(ks, param("alias"), param("keypass")::toCharArray);
        final Callable<InputStream> source = () -> new FileInputStream(param("source"));
        final Callable<OutputStream> sink = () -> new FileOutputStream(param("sink"));
        final Optional<String> recipient = optParam("recipient");
        if (recipient.isPresent()) {
            final X509Certificate recipientCert = (X509Certificate) ks.getCertificate(recipient.get());
            copy(source, subscriber.signAndEncryptTo(sink, recipientCert));
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

    @SuppressWarnings("SameParameterValue")
    private Optional<String> optParam(String name) {
        return Optional.ofNullable(options.get(name));
    }
}
