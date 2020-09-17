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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.Callable;

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
    public X509Certificate certificate() throws Exception {
        return requireNonNull((X509Certificate) ks.getCertificate(alias));
    }
}
