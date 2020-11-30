/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of secon-tool
 * (see https://github.com/DieTechniker/secon-tool).
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
package de.tk.opensource.secon;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class KeyStoreIdentity implements Identity {

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
            return Optional
                    .ofNullable((PrivateKey) ks.getKey(alias, pw))
                    .orElseThrow(PrivateKeyNotFoundException::new);
        } finally {
            Arrays.fill(pw, (char) 0);
        }
    }

    @Override
    public X509Certificate certificate() throws Exception {
        return Optional
                .ofNullable((X509Certificate) ks.getCertificate(alias))
                .orElseThrow(CertificateNotFoundException::new);
    }

    @Override
    public final Optional<PrivateKey> privateKey(X509CertSelector selector) throws Exception {
        return Collections
                .list(ks.aliases())
                .stream()
                .flatMap(this::privateKeyEntryStream)
                .filter(entry -> selector.match(entry.getCertificate()))
                .map(KeyStore.PrivateKeyEntry::getPrivateKey)
                .findFirst();
    }

    private Stream<KeyStore.PrivateKeyEntry> privateKeyEntryStream(final String alias) {
        try {
            if (ks.isKeyEntry(alias)) {
                final KeyStore.Entry entry;
                final char[] pw = password.call();
                try {
                    entry = ks.getEntry(alias, new KeyStore.PasswordProtection(pw));
                } finally {
                    Arrays.fill(pw, (char) 0);
                }
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    return Stream.of((KeyStore.PrivateKeyEntry) entry);
                }
            }
            return Stream.empty();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot get keystore entry with alias `" + alias + "`:", e);
        }
    }
}
