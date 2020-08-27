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

/**
 * Zeigt an, dass das im KKS-Kontext {@linkplain KksSubscriber#myCertificate() konfigurierte Zertifikat} zu keinem der
 * vorgesehenen Empfänger einer verschlüsselten Nachricht passt und die Nachricht daher nicht entschlüsselt werden kann.
 * Eine Instanziierung dieser Klasse außerhalb dieses Pakets ist nicht möglich.
 *
 * @author Christian Schlichtherle
 */
public class KksCertificateMismatchException extends KksException {

    private static final long serialVersionUID = 0L;

    KksCertificateMismatchException() {
    }
}
