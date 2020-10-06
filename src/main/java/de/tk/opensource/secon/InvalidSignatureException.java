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

/**
 * Zeigt an, dass bei der Signaturprüfung eine ungültige digitale Signatur gefunden wurde.
 * Eine Instanziierung dieser Klasse außerhalb dieses Pakets ist nicht möglich.
 *
 * @author Christian Schlichtherle
 */
public class InvalidSignatureException extends SeconException {

    private static final long serialVersionUID = 0L;

    InvalidSignatureException() {
    }
}
