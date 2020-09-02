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
final class LdapDirectory implements KksDirectory {

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
            for (byte[] bytes : visitor.<byte[]>search(base, "objectClass=pkiUser", OBJECT_SCOPE, "userCertificate;binary")) {
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
            for (final String dn : visitor.<String>search(base, "objectClass=*", ONELEVEL_SCOPE, "seeAlso")) {
                for (byte[] bytes : visitor.<byte[]>search(dn, "objectClass=pkiUser", OBJECT_SCOPE, "userCertificate;binary")) {
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
