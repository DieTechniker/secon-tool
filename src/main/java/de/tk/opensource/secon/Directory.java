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

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Verzeichnisdienst für Zertifikate von Kommunikationsteilnehmern im SECON.
 * Dies ist eine Schnittstelle für Serviceprovider.
 *
 * @author Christian Schlichtherle
 */
public interface Directory {

    /**
     * Sucht das Zertifikat für einen Kommunikationsteilnehmer, welches zu dem gegebenen Selektor passt.
     * Dieses Zertifikat wird verwendet, um die digitalen Signaturen von Nachrichten zu überprüfen.
     */
    Optional<X509Certificate> certificate(X509CertSelector selector) throws Exception;

    /**
     * Sucht das Zertifikat für einen Kommunikationsteilnehmer, welches zu dem gegebenen Kennzeichen passt.
     * Dieses Zertifikat wird verwendet, um Nachrichten für den Zertifikatsinhaber zu verschlüsseln.
     *
     * @param identifier
     * Eine neunstellige Zahl, falls es sich um ein Institutionskennzeichen für einen Leistungserbringer handelt, z.B.
     * eine Krankenkasse.
     * Andernfalls wird angenommen, dass es sich um einen Arbeitgeber handelt.
     */
    Optional<X509Certificate> certificate(String identifier) throws Exception;
}
