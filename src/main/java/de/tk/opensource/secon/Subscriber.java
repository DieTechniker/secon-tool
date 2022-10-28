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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

/**
 * Ein Kontextobjekt, welches einen Kommunikationsteilnehmer im SECON repräsentiert und diesem das Versenden und
 * Empfangen von Nachrichten im CMS-Format (Cryptographic Message Syntax) ermöglicht.
 *
 * @author  Wolfgang Schmiesing
 * @author  Christian Schlichtherle
 */
public interface Subscriber {

	/**
	 * Erzeugt einen erneuerbaren Ausgabestrom, der die Daten, die in den gegebenen erneuerbaren Ausgabestrom
	 * geschrieben werden, signiert und für die gegebenen Empfänger verschlüsselt. Die Empfänger werden durch die
	 * gegebenen Zertifikate identifiziert.
	 *
	 * <p>Der Aufrufer ist verpflichtet, die erzeugten Ausgabeströme zu {@linkplain OutputStream#close() schließen}, da
	 * es andernfalls zu Datenverlust kommt! Es wird daher empfohlen, die erneuerbaren Ausgabeströme nur in <i>
	 * try-with-resources</i>-Anweisungen zu benutzen.
	 */
	SeconCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final X509Certificate		 recipient,
		final X509Certificate...     others
	);

	/**
	 * Erzeugt einen erneuerbaren Ausgabestrom, der die Daten, die in den gegebenen erneuerbaren Ausgabestrom
	 * geschrieben werden, signiert und für die gegebenen Empfänger verschlüsselt. Die Empfänger werden durch die
	 * gegebenen Institutionskennzeichen identifiziert. Diese fangen typischerweise mit "IK" oder "BN" an, gefolgt von
	 * einer neunstelligen Zahl gemäß <a
	 * href="https://www.gkv-datenaustausch.de/media/dokumente/faq/Gemeinsames_Rundschreiben_IK_2015-03.pdf">
	 * Rundschreiben ARGE-IK</a>. Die entsprechenden Zertifikate werden vom LDAP-Server geladen.
	 *
	 * <p>Der Aufrufer ist verpflichtet, die erzeugten Ausgabeströme zu {@linkplain OutputStream#close() schließen}, da
	 * es andernfalls zu Datenverlust kommt! Es wird daher empfohlen, die erneuerbaren Ausgabeströme nur in <i>
	 * try-with-resources</i>-Anweisungen zu benutzen.
	 */
	SeconCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final String				 recipientId,
		final String... 			 otherIds
	);

	/**
	 * Erzeugt einen erneuerbaren Eingabestrom, der die Daten, die von dem gegebenen erneuerbaren Eingabestrom gelesen
	 * werden, entschlüsselt und die digitalen Signaturen überprüft. Bei dieser Variante der Methode werden die
	 * Zertifikate der Absender <em>nicht überprüft</em>!
	 *
	 * <p>Der Aufrufer ist verpflichtet, die erzeugten Eingabeströme zu {@linkplain InputStream#close() schließen}, da
	 * andernfalls die digitalen Signaturen nicht überprüft werden! Es wird daher empfohlen, die erneuerbaren
	 * Eingabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	default SeconCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input) {
		return decryptAndVerifyFrom(input, Verifier.NULL);
	}

	/**
	 * Erzeugt einen erneuerbaren Eingabestrom, der die Daten, die von dem gegebenen erneuerbaren Eingabestrom gelesen
	 * werden, entschlüsselt und die digitalen Signaturen überprüft. Bei dieser Variante der Methode werden die
	 * Zertifikate der Absender zusätzlich durch den gegebenen Verifizierer überprüft.
	 *
	 * <p>Der Aufrufer ist verpflichtet, die erzeugten Eingabeströme zu {@linkplain InputStream#close() schließen}, da
	 * andernfalls die digitalen Signaturen nicht überprüft werden! Es wird daher empfohlen, die erneuerbaren
	 * Eingabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	SeconCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input, Verifier v);
}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
