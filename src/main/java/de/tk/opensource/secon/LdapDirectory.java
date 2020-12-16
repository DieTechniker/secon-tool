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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static javax.naming.directory.SearchControls.OBJECT_SCOPE;
import static javax.naming.directory.SearchControls.ONELEVEL_SCOPE;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class LdapDirectory implements Directory {

    private static final Comparator<X509Certificate> CERTIFICATE_COMPARATOR =
            Comparator.comparing(X509Certificate::getNotAfter);

    private volatile CertificateFactory certificateFactory;

    private final DirContextPool pool;

    LdapDirectory(final DirContextPool pool) {
        this.pool = pool;
    }

    @Override
    public Optional<X509Certificate> certificate(final X509CertSelector selector) throws Exception {
        final String base = String.format("cn=%06X,%s", selector.getSerialNumber(), selector.getIssuerAsString());
        final List<X509Certificate> result = new ArrayList<>();
        pool.accept(visitor -> {
            for (byte[] bytes : visitor.search(base, "objectClass=pkiUser", OBJECT_SCOPE, byte[].class, "userCertificate;binary")) {
                final X509Certificate cert = certificate(bytes);
                if (selector.match(cert)) {
                    result.add(cert);
                }
            }
        });
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    @Override
    public Optional<X509Certificate> certificate(final String identifier) throws Exception {
        final String base = identifier.length() == 9
                ? "ou=IK" + identifier + ",o=LE,c=DE"
                : "ou=BN" + identifier + ",o=AG,c=DE";
        final List<X509Certificate> result = new ArrayList<>();
        pool.accept(visitor -> {
            for (final String dn : visitor.search(base, "objectClass=*", ONELEVEL_SCOPE, String.class, "seeAlso")) {
                for (byte[] bytes : visitor.search(dn, "objectClass=pkiUser", OBJECT_SCOPE, byte[].class, "userCertificate;binary")) {
                    result.add(certificate(bytes));
                }
            }
/* Faster alternative for IKs, but doesn't work with all LDAP variants:
            for (byte[] bytes : visitor.<byte[]>search("c=de", "sn=IK" + identifier, "userCertificate;binary")) {
                result.add(parseCertificate(bytes));
            }
*/
        });
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    private X509Certificate certificate(byte[] bytes) throws CertificateException {
        return (X509Certificate) certificateFactory().generateCertificate(new ByteArrayInputStream(bytes));
    }

    private CertificateFactory certificateFactory() throws CertificateException {
        final CertificateFactory f = certificateFactory;
        return null != f ? f : (certificateFactory = CertificateFactory.getInstance("X.509"));
    }
}
