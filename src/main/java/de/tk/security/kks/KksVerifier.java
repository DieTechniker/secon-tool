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

import java.security.cert.X509Certificate;

/**
 * Überprüft ein Zertifikat <em>nach</em> erfolgreicher Überprüfung einer digitalen Signatur.
 * Falls nötig, ist es im Zusammenspiel mit der {@link KksDirectory}-Schnittstelle möglich, rekursiv die komplette
 * Zertifikatskette zu überprüfen.
 *
 * @author Christian Schlichtherle
 */
@FunctionalInterface
public interface KksVerifier {

    /** Das Null-Objekt überprüft das gegebene Zertifikat <em>nicht</em>. */
    KksVerifier NULL = cert -> {
    };

    /**
     * Überprüft das gegebene Zertifikat.
     * Diese Methode wird <em>nach</em> der erfolgreichen Überprüfung einer digitalen Signatur aufgerufen, um das
     * zugehörige Zertifikat selbst zu überprüfen.
     * Bei Fehlschlag wird eine Ausnahme ausgelöst.
     */
    void verify(X509Certificate cert) throws Exception;
}
