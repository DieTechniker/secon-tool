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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * @author Wolfgang Schmiesing
 * @author Christian Schlichtherle
 */
final class KeyStoreDirectory implements Directory {

	private final KeyStore ks;
	
	private final LRUCache<X509Certificate, X509Certificate> issuerCache;
	
	KeyStoreDirectory(final KeyStore ks) {
		this(ks, new LRUCache<X509Certificate, X509Certificate>(50));
	}
	
	KeyStoreDirectory(final KeyStore ks, LRUCache<X509Certificate, X509Certificate> cache) {
		this.ks = ks;
		this.issuerCache = cache;
	}

	@Override
	public final Optional<X509Certificate> certificate(X509CertSelector selector) throws KeyStoreException {
		return certificates(selector).findFirst();
	}

	private final Stream<X509Certificate> certificates(X509CertSelector selector) throws KeyStoreException {
		return Collections.list(ks.aliases()).stream().flatMap(this::certificateStream).filter(selector::match);
	}

	@Override
	public Optional<X509Certificate> issuer(X509Certificate cert) throws Exception {
		if(issuerCache.containsKey(cert)) {
			return issuerCache.get(cert);
		}
		
		final X509CertSelector selector = new X509CertSelector();
		selector.setSubject(cert.getIssuerX500Principal());

		// find first matching issuer since principal might not be unique
		Optional<X509Certificate> issuer = certificates(selector).filter(p -> {
			try {
				cert.verify(p.getPublicKey());
				return true;
			} catch (Exception e) {
				return false;
			}
		}).findFirst();
		if(issuer.isPresent()) {
			issuerCache.put(cert, issuer.get());
		}
		return issuer;
	}

	private Stream<X509Certificate> certificateStream(final String alias) {
		try {
			return certificate(alias).map(Stream::of).orElseGet(Stream::empty);
		} catch (KeyStoreException e) {
			throw new IllegalStateException("Cannot get certificate for alias `" + alias + "`:", e);
		}
	}

	@Override
	public final Optional<X509Certificate> certificate(final String identifier) throws KeyStoreException {
		final Certificate cert = ks.getCertificate(identifier);
		return cert instanceof X509Certificate ? Optional.of((X509Certificate) cert) : Optional.empty();
	}
	
}
