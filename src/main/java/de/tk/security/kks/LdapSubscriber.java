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
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.Callable;

import static de.tk.security.kks.KKS.callable;
import static de.tk.security.kks.KKS.socket;
import static javax.naming.directory.SearchControls.OBJECT_SCOPE;
import static javax.naming.directory.SearchControls.ONELEVEL_SCOPE;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class LdapSubscriber extends KeyStoreSubscriber {

    private static final Comparator<X509Certificate> CERTIFICATE_COMPARATOR =
            Comparator.comparing(X509Certificate::getNotAfter);

    private final DirContextPool pool;
    private volatile CertificateFactory certificateFactory;

    LdapSubscriber(KeyStore ks, String alias, Callable<char[]> password, DirContextPool pool) {
        super(ks, alias, password);
        this.pool = pool;
    }

    @Override
    protected Optional<X509Certificate> certificate(final X509CertSelector selector) throws Exception {
        Optional<X509Certificate> result = super.certificate(selector);
        if (!result.isPresent()) {
            result = lookup(selector);
        }
        return result;
    }

    @Override
    public KksCallable<OutputStream> signAndEncryptTo(
            final Callable<OutputStream> output,
            final String recipientId,
            final String... otherIds) {
        @SuppressWarnings("unchecked") final Callable<X509Certificate>[] recipients = new Callable[otherIds.length + 1];
        recipients[0] = () -> lookup(recipientId);
        for (int i = 0; i < otherIds.length; ) {
            final String other = otherIds[i];
            recipients[++i] = () -> lookup(other);
        }
        return callable(signAndEncryptTo(socket(output), recipients));
    }

    private Optional<X509Certificate> lookup(final X509CertSelector selector) throws Exception {
        final String base = String.format("cn=%06X,%s", selector.getSerialNumber(), selector.getIssuerAsString());
        final List<X509Certificate> result = new ArrayList<>();
        pool.accept(visitor -> {
            for (byte[] bytes : visitor.<byte[]>search(base, "objectClass=pkiUser", OBJECT_SCOPE, "userCertificate;binary")) {
                result.add(parseCertificate(bytes));
            }
        });
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    private X509Certificate lookup(final String identifier) throws Exception {
        final String base = identifier.length() == 9
                ? "ou=IK" + identifier + ",o=LE,c=DE"
                : "ou=BN" + identifier + ",o=AG,c=DE";
        final List<X509Certificate> result = new ArrayList<>();
        pool.accept(visitor -> {
            for (final String dn : visitor.<String>search(base, "objectClass=*", ONELEVEL_SCOPE, "seeAlso")) {
                for (byte[] bytes : visitor.<byte[]>search(dn, "objectClass=pkiUser", OBJECT_SCOPE, "userCertificate;binary")) {
                    result.add(parseCertificate(bytes));
                }
            }
/* Faster alternative for IKs, but doesn't work with all LDAP variants:
            for (byte[] bytes : visitor.<byte[]>search("c=de", "sn=IK" + identifier, "userCertificate;binary")) {
                result.add(parseCertificate(bytes));
            }
*/
        });
        return result
                .stream()
                .max(CERTIFICATE_COMPARATOR)
                .orElseThrow(() -> new KksCertificateNotFoundException(identifier));
    }

    private X509Certificate parseCertificate(byte[] bytes) throws CertificateException {
        return (X509Certificate) certificateFactory().generateCertificate(new ByteArrayInputStream(bytes));
    }

    private CertificateFactory certificateFactory() throws CertificateException {
        final CertificateFactory f = certificateFactory;
        return null != f ? f : (certificateFactory = CertificateFactory.getInstance("X.509"));
    }
}
