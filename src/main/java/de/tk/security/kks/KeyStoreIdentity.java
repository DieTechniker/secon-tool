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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class KeyStoreIdentity implements KksIdentity {

    private final KeyStore ks;
    private final String alias;
    private final Callable<char[]> password;

    KeyStoreIdentity(final KeyStore ks, final String alias, final Callable<char[]> password) {
        this.ks = ks;
        this.alias = alias;
        this.password = password;
    }

    @Override
    public PrivateKey privateKey() throws Exception {
        final char[] pw = password.call();
        try {
            return requireNonNull((PrivateKey) ks.getKey(alias, pw));
        } finally {
            Arrays.fill(pw, (char) 0);
        }
    }

    @Override
    public X509Certificate certificate() throws Exception{
        return requireNonNull((X509Certificate) ks.getCertificate(alias));
    }
}
