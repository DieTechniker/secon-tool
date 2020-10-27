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
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.operator.GenericKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import static de.tk.opensource.secon.SECON.*;

class KeyEncryptionTest {

	@Test
	void use_RSAES_OAEP_for_4096bit_Keys() throws Exception {
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), "secret"::toCharArray);

		RecipientInfo info =
			RecipientInfoGeneratorFactory
				.create(() -> { return (X509Certificate) ks.getCertificate("alice_pss_256"); })
				.generate(generateRandomAESKey());

		assertKeyEncryption_RSAES_OAEP((KeyTransRecipientInfo) info.getInfo());
	}

	@Test
	void use_RSA_for_Old_Keys() throws Exception {
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), "secret"::toCharArray);

		RecipientInfo info =
			RecipientInfoGeneratorFactory
				.create(() -> { return (X509Certificate) ks.getCertificate("alice_rsa_256"); })
				.generate(generateRandomAESKey());

		assertKeyEncryption_RSA((KeyTransRecipientInfo) info.getInfo());
	}

	private void assertKeyEncryption_RSA(KeyTransRecipientInfo keyTransRecipientInfo) {
		AlgorithmIdentifier keyEncryptionAlgorithm = keyTransRecipientInfo.getKeyEncryptionAlgorithm();
		assertEquals("1.2.840.113549.1.1.1", keyEncryptionAlgorithm.getAlgorithm().getId());

		assertTrue(keyEncryptionAlgorithm.getParameters() instanceof DERNull);
	}

	private void assertKeyEncryption_RSAES_OAEP(KeyTransRecipientInfo keyTransRecipientInfo) {
		AlgorithmIdentifier keyEncryptionAlgorithm = keyTransRecipientInfo.getKeyEncryptionAlgorithm();
		assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP.getId(), keyEncryptionAlgorithm.getAlgorithm().getId());

		RSAESOAEPparams parameters = (RSAESOAEPparams) keyEncryptionAlgorithm.getParameters();
		assertEquals(NISTObjectIdentifiers.id_sha256.getId(), parameters.getHashAlgorithm().getAlgorithm().getId());
		assertEquals(PKCSObjectIdentifiers.id_mgf1.getId(), parameters.getMaskGenAlgorithm().getAlgorithm().getId());
		assertEquals(
			PKCSObjectIdentifiers.id_pSpecified.getId(),
			parameters.getPSourceAlgorithm().getAlgorithm().getId()
		);
	}

	private GenericKey generateRandomAESKey() throws Exception {
		SecretKey generatedKey = KeyGenerator.getInstance("AES").generateKey();

		return
			new GenericKey(
				AlgorithmIdentifierFactory.generateEncryptionAlgID(
					NISTObjectIdentifiers.id_aes256_CBC,
					256,
					new SecureRandom()
				),
				generatedKey.getEncoded()
			);
	}

}
