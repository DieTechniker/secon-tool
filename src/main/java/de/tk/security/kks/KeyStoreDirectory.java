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
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class KeyStoreDirectory implements KksDirectory {

    private final KeyStore keyStore;

    KeyStoreDirectory(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public final Optional<X509Certificate> certificate(X509CertSelector selector) throws KeyStoreException {
        return Collections
                .list(keyStore.aliases())
                .stream()
                .flatMap(this::certificateStream)
                .filter(selector::match)
                .findFirst();
    }

    private Stream<X509Certificate> certificateStream(final String alias) {
        try {
            return certificate(alias).map(Stream::of).orElseGet(Stream::empty);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot get certificate for alias `" + alias + "`:", e);
        }
    }

    @Override
    public final Optional<X509Certificate> certificate(final String identifier) throws KeyStoreException {
        final Certificate cert = keyStore.getCertificate(identifier);
        return cert instanceof X509Certificate ? Optional.of((X509Certificate) cert) : Optional.empty();
    }
}
