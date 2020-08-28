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

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Verzeichnisdienst für Zertifikate im KKS.
 * Dies ist eine Schnittstelle für Serviceprovider.
 *
 * @author Christian Schlichtherle
 */
public interface KksDirectory {

    /**
     * Sucht das Zertifikat für einen Kommunikationsteilnehmer, das zu dem gegebenen Selektor passt.
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
