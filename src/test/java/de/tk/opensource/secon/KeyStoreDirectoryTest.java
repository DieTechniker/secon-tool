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

import static de.tk.opensource.secon.SECON.keyStore;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeyStoreDirectoryTest {

	private KeyStoreDirectory directory;
	private LRUCache<X509Certificate, X509Certificate> cache;

	@BeforeEach
	void setup() throws Exception {
		
		KeyStore keystore = keyStore(() -> KeyStoreDirectoryTest.class.getResourceAsStream("truststore.p12"), "secret"::toCharArray);			
		cache = new LRUCache<X509Certificate, X509Certificate>(50);
		directory = new KeyStoreDirectory(keystore, cache);
	}

	@Test
	void findIssuerForCertificate() throws Exception {
		
		Optional<X509Certificate> alice = directory.certificate("alice");
		assertTrue(alice.isPresent());
		// noch nicht im Cache
		assertFalse(cache.get(alice.get()).isPresent());
		
		Optional<X509Certificate> issuer = directory.issuer(alice.get());
		assertTrue(issuer.isPresent());
		// Issuer im Cache
		assertTrue(cache.get(alice.get()).isPresent());
		
		Optional<X509Certificate> issuer2 = directory.issuer(alice.get());
		assertTrue(issuer2.isPresent());
		// Issuer im Cache
		assertTrue(cache.get(alice.get()).isPresent());
	}

}
