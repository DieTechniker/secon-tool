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

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static de.tk.security.kks.KKS.directory;
import static java.lang.Character.toUpperCase;
import static java.util.Locale.ENGLISH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("LDAP")
public class LdapDirectoryTest {

    private final KksDirectory dir = directory(URI.create("ldap://localhost"));

    @Test
    void BITMARCK_Service_GmbH() throws Exception {
        assertCertificate(
                "8a:99:51:df:75:c6:56:bc:1a:f4:da:ca:c7:7b:e2:fb:fc:3f:17:a2",
                "104027544",
                "30d64",
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
        assertIdentifier(sha1sum, identifier);
        assertSelector(sha1sum, serial, issuerDN);
    }

    private void assertIdentifier(final String sha1sum, final String identifier) throws Exception {
        final Optional<X509Certificate> cert = dir.certificate(identifier);
        assertTrue(cert.isPresent());
        assertEquals(sha1sum.toUpperCase(ENGLISH), fingerprint(cert.get()));
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
