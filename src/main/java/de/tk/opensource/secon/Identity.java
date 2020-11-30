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

import java.security.PrivateKey;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Identifiziert einen Kommunikationsteilnehmer im SECON mittels eines privaten Schlüssels und des dazugehörigen
 * Zertifikats.
 * Dies ist eine Schnittstelle für Serviceprovider.
 *
 * @author Christian Schlichtherle
 */
public interface Identity {

    /**
     * Sucht den privaten Schlüssel für einen Kommunikationsteilnehmer, welcher zu dem gegebenen Selektor passt.
     * Dieser Schlüssel wird verwendet, um Nachrichten zu entschlüsseln.
     *
     * @since 1.1.0
     */
    default Optional<PrivateKey> privateKey(X509CertSelector selector) throws Exception {
        return selector.match(certificate()) ? Optional.of(privateKey()) : Optional.empty();
    }

    /**
     * Gibt den privaten Schlüssel für diesen Kommunikationsteilnehmer zurück.
     * Dieser Schlüssel wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen.
     *
     * @throws PrivateKeyNotFoundException falls der private Schlüssel nicht gefunden werden kann.
     * @throws Exception in allen anderen Fehlerfällen, z.B. wenn ein KeyStore nicht geladen werden kann.
     */
    PrivateKey privateKey() throws Exception;

    /**
     * Gibt das Zertifikat für diesen Kommunikationsteilnehmer zurück.
     * Dieses Zertifikat wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen.
     *
     * @throws CertificateNotFoundException falls das Zertifikat nicht gefunden werden kann.
     * @throws Exception in allen anderen Fehlerfällen, z.B. wenn ein KeyStore nicht geladen werden kann.
     */
    X509Certificate certificate() throws Exception;
}
