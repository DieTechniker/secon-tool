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

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static de.tk.opensource.secon.SECON.directory;
import static java.lang.Character.toUpperCase;
import static java.util.Locale.ENGLISH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("LDAP")
public class LdapDirectoryTest {

    private final Directory dir = directory(URI.create("ldap://localhost"));

    @Test
    void BITMARCK_Service_GmbH() throws Exception {
        assertCertificate(
                "62:2a:7c:50:98:95:f6:cd:9d:75:85:83:16:d2:e6:a2:24:a3:1f:1b",
                "104027544",
                "27c3b",
                "o=itsg trustcenter fuer sonstige leistungserbringer, c=de"
        );
    }

    @Test
    void HV_Postbeamtenkrankenkasse() throws Exception {
        assertCertificate(
                "16:31:17:98:b5:c2:89:7e:71:12:f4:aa:64:48:f0:fa:e7:7e:b3:59",
                "103600182",
                "325d8",
                "o=itsg trustcenter fuer sonstige leistungserbringer, c=de"
        );
    }

    @Test
    void Techniker_Krankenkasse() throws Exception {
        assertCertificate(
                "c7:5c:aa:44:f1:9a:16:a5:c4:5d:22:94:45:ba:ba:8b:e7:fd:dc:d1",
                "99301342",
                "f644b",
                "o=itsg trustcenter fuer arbeitgeber, c=de"
        );
    }

    private void assertCertificate(
            final String sha1sum,
            final String identifier,
            final String serial,
            final String issuerDN
    ) throws Exception {
        assertIdentifier(sha1sum, identifier, serial, issuerDN);
        assertSelector(sha1sum, serial, issuerDN);
    }

    private void assertIdentifier(
            final String sha1sum,
            final String identifier,
            final String serial,
            final String issuerDN
    ) throws Exception {
        final Optional<X509Certificate> maybeCert = dir.certificate(identifier);
        assertTrue(maybeCert.isPresent());
        final X509Certificate cert = maybeCert.get();
        assertEquals(sha1sum.toUpperCase(ENGLISH), fingerprint(cert));
        assertEquals(serial, cert.getSerialNumber().toString(16));
        assertEquals(issuerDN.toUpperCase(ENGLISH), cert.getIssuerDN().toString().toUpperCase(ENGLISH));
    }

    private void assertSelector(final String sha1sum, final String serial, final String issuerDN) throws Exception {
        final X509CertSelector sel = new X509CertSelector();
        sel.setSerialNumber(new BigInteger(serial, 16));
        sel.setIssuer(issuerDN);
        final Optional<X509Certificate> cert = dir.certificate(sel);
        assertTrue(cert.isPresent());
        assertEquals(sha1sum.toUpperCase(ENGLISH), fingerprint(cert.get()));
    }

    private static String fingerprint(X509Certificate cert) throws Exception {
        return prettyPrint(new BigInteger(1, MessageDigest.getInstance("SHA1").digest(cert.getEncoded()))
                .toString(16));
    }

    private static String prettyPrint(final String hexCode) {
        final int len = hexCode.length();
        final int resultLen = len + (len - 1) / 2;
        final StringBuilder result = new StringBuilder(resultLen);
        for (int i = 0; i < len; i++) {
            if (i != 0 && i % 2 == 0) {
                result.append(':');
            }
            result.append(toUpperCase(hexCode.charAt(i)));
        }
        assert result.length() == resultLen;
        return result.toString();
    }
}
