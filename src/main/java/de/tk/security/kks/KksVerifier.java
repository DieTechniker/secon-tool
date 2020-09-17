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
