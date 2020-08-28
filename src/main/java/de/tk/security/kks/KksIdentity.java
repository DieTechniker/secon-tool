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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Identifiziert einen Kommunikationsteilnehmer im KKS.
 * Dies ist eine Schnittstelle für Serviceprovider.
 *
 * @author Christian Schlichtherle
 */
public interface KksIdentity {

    /**
     * Gibt den privaten Schlüssel für diesen Kommunikationsteilnehmer zurück.
     * Der private Schlüssel wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen und um
     * verschlüsselte Nachrichten zu entschlüsseln.
     */
    PrivateKey myPrivateKey() throws Exception;

    /**
     * Gibt das Zertifikat für diesen Kommunikationsteilnehmer zurück.
     * Das Zertifikat wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen und um verschlüsselte
     * Nachrichten zu entschlüsseln.
     */
    X509Certificate myCertificate() throws Exception;
}
