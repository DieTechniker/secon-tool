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

import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.concurrent.Callable;

import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.*;

/**
 * Erzeugt je nach Schlüssellänge den korrekten Wrapper für den Session-Key
 *
 * @author  Wolfgang Schmiesing
 */
public final class RecipientInfoGeneratorFactory {

	public static RecipientInfoGenerator create(Callable<X509Certificate> certCallable) {
		try {
			X509Certificate cert = certCallable.call();
			if (keySize(cert) < 4096) {

				// für Schlüssel kleiner 4096 Bit den Algorithmus des öffentlichen Schlüssels verwenden (RSA)
				return new JceKeyTransRecipientInfoGenerator(cert).setProvider(PROVIDER_NAME);
			} else {

				// für Schlüssel >= 4096 RSAES_OAEP verwenden
				return
					new JceKeyTransRecipientInfoGenerator(cert, KksAlgorithms.ENCRYPTION_ALGORITHM_RSAES_OAEP)
						.setProvider(PROVIDER_NAME);
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static int keySize(final X509Certificate cert) throws InvalidKeyException {
		if (cert != null && cert.getPublicKey() instanceof RSAKey) {
			final RSAKey rsaPk = (RSAKey) cert.getPublicKey();
			return rsaPk.getModulus().bitLength();
		} else {
			throw new InvalidKeyException("Only RSA keys are supported");
		}
	}

}
