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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import static de.tk.security.kks.KKS.callable;
import static de.tk.security.kks.KKS.socket;

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
            final int recipientId,
            final int... otherIds) {
        @SuppressWarnings("unchecked") final Callable<X509Certificate>[] recipients = new Callable[otherIds.length + 1];
        recipients[0] = () -> lookup(recipientId);
        for (int i = 0; i < otherIds.length; ) {
            final int other = otherIds[i];
            recipients[++i] = () -> lookup(other);
        }
        return callable(signAndEncryptTo(socket(output), recipients));
    }

    private Optional<X509Certificate> lookup(X509CertSelector selector) throws Exception {
        return lookup(String.format("cn=0%X,%s", selector.getSerialNumber(), selector.getIssuerAsString()), "");
    }

    private X509Certificate lookup(int identifier) throws Exception {
        return lookup("c=de", "(sn=IK" + identifier + ")")
                .orElseThrow(() -> new KksCertificateNotFoundException("IK" + identifier));
    }

    private Optional<X509Certificate> lookup(final String base, final String filter) throws Exception {
        final List<X509Certificate> result = new ArrayList<>();
        pool.accept(visitor -> {
            for (byte[] bytes : visitor.<byte[]>search(base, filter, "userCertificate;binary")) {
                result.add(parseCertificate(bytes));
            }
        });
        return result.stream().max(CERTIFICATE_COMPARATOR);
    }

    private X509Certificate parseCertificate(byte[] bytes) throws CertificateException {
        return (X509Certificate) certificateFactory().generateCertificate(new ByteArrayInputStream(bytes));
    }

    private CertificateFactory certificateFactory() throws CertificateException {
        final CertificateFactory f = certificateFactory;
        return null != f ? f : (certificateFactory = CertificateFactory.getInstance("X.509"));
    }
}
