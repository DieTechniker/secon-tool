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

import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author  Wolfgang Schmiesing
 * @author  Christian Schlichtherle
 */
final class KksAlgorithms {

	private static final AlgorithmIdentifier OAEP_HASH_ALGORITHM =
		new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

	private static final AlgorithmIdentifier OAEP_MASK_GEN_FUNCTION =
		new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, OAEP_HASH_ALGORITHM);

	private static final AlgorithmIdentifier OAEP_P_SOURCE =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_pSpecified,
			new DEROctetString(PSource.PSpecified.DEFAULT.getValue())
		);

	static final AlgorithmIdentifier ENCRYPTION_ALGORITHM_RSAES_OAEP =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_RSAES_OAEP,
			new RSAESOAEPparams(OAEP_HASH_ALGORITHM, OAEP_MASK_GEN_FUNCTION, OAEP_P_SOURCE)
		);

}
