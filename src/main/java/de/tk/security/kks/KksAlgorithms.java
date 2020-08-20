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

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

import javax.crypto.spec.PSource;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class KksAlgorithms {

	static final AlgorithmIdentifier OAEP_HASH_ALGORITHM =
		new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

	static final AlgorithmIdentifier OAEP_MASK_GEN_FUNCTION =
		new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, OAEP_HASH_ALGORITHM);

	static final AlgorithmIdentifier OAEP_P_SOURCE =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_pSpecified,
			new DEROctetString(PSource.PSpecified.DEFAULT.getValue())
		);

	static final AlgorithmIdentifier ENCRYPTION_ALGORITHM_RSAES_OAEP =
		new AlgorithmIdentifier(
			PKCSObjectIdentifiers.id_RSAES_OAEP,
			new RSAESOAEPparams(OAEP_HASH_ALGORITHM, OAEP_MASK_GEN_FUNCTION, OAEP_P_SOURCE)
		);

	static final AlgorithmIdentifier SIGNATURE_DIGEST_ALGORITHM =
		new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

	static OAEPEncoding createOEAPEncoding() {
		return
			new OAEPEncoding(
				new RSAEngine(),
				DigestFactory.getDigest("SHA-256"),
				DigestFactory.getDigest("SHA-256"),
				PSource.PSpecified.DEFAULT.getValue()
			);
	}
}
