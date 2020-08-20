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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.bc.BcKeyTransRecipientInfoGenerator;

import java.security.cert.X509Certificate;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class OaepTransRecipientInfoGenerator extends BcKeyTransRecipientInfoGenerator {

	OaepTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmIdentifier algorithm) throws Exception {
		super(
			new JcaX509CertificateHolder(recipientCert),
			new OaepAsymmetricKeyWrapper(algorithm, recipientCert.getPublicKey())
		);
	}
}
