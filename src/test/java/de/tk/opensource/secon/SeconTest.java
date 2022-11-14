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

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.jupiter.api.Test;

import de.tk.opensource.secon.Directory;
import de.tk.opensource.secon.SeconException;
import de.tk.opensource.secon.Identity;
import de.tk.opensource.secon.Subscriber;

import static de.tk.opensource.secon.SECON.*;
import static global.namespace.fun.io.bios.BIOS.*;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author  Wolfgang Schmiesing
 * @author  Christian Schlichtherle
 * @author  Marcus Fey 
*/
public class SeconTest {

	@Test
	void aliceToBobUsingRSA256() throws Exception {
		assertCommunicationRoundtrip("alice_rsa_256", "bob_rsa_256");
	}

	@Test
	void bobToAliceUsingRSA256() throws Exception {
		assertCommunicationRoundtrip("bob_rsa_256", "alice_rsa_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_256() throws Exception {
		assertCommunicationRoundtrip("alice_pss_256", "bob_pss_256");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_256() throws Exception {
		assertCommunicationRoundtrip("bob_pss_256", "alice_pss_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_384() throws Exception {
		assertCommunicationRoundtrip("alice_pss_384", "bob_pss_384");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_384() throws Exception {
		assertCommunicationRoundtrip("bob_pss_384", "alice_pss_384");
	}

	private static void assertCommunicationRoundtrip(final String sender, final String recipient) throws Exception {
		final Callable<char[]> pw = "secret"::toCharArray;
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), pw);
		assertCommunicationRoundtrip(identity(ks, sender, pw), identity(ks, recipient, pw), directory(ks));
	}

	private static void assertCommunicationRoundtrip(
		final Identity  senderId,
		final Identity  recipientId,
		final Directory directory
	) throws Exception
	{
		final Subscriber senderSub = subscriber(senderId, directory);
		final Subscriber recipientSub = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		final Store plain = memory(), cipher = memory(), clone = memory();
		plain.content("Hello world!".getBytes());
		copy(input(plain), senderSub.signAndEncryptTo(output(cipher), recipientCert));

        // Simulate certificate verification failure:
        {
            final CertificateVerificationException e = new CertificateVerificationException("invalid certificate");
            assertSame(e, assertThrows(SeconException.class, () -> copy(
                    recipientSub.decryptAndVerifyFrom(input(cipher), certs -> {
                        throw e;
                    }),
                    output(clone)
            )));
        }

		copy(recipientSub.decryptAndVerifyFrom(input(cipher)), output(clone));
		assertArrayEquals(plain.content(), clone.content());
	}

	private static Callable<InputStream> input(Source source) {
		return callable(source.input());
	}

	private static Callable<OutputStream> output(Sink sink) {
		return callable(sink.output());
	}

	@Test
	void bobToAliceUsingRSASSA_RSS_256_BadEncAlgo() throws Exception {
		final Callable<char[]> pw = "secret"::toCharArray;
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), pw);
		Identity senderId = identity(ks, "bob_rsa_256", pw);
		Identity recipientId = identity(ks, "alice_rsa_256", pw);
		Directory directory = directory(ks);

		final Subscriber senderSub = new DefaultSubscriber(senderId,new Directory[] {directory}, CMSAlgorithm.DES_CBC);
		
		final Subscriber recipientSub = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		final Store plain = memory(), cipher = memory(), clone = memory();
		plain.content("Hello world!".getBytes());
		copy(input(plain), senderSub.signAndEncryptTo(output(cipher), recipientCert));
		
		assertThrows(EncryptionAlgorithmIllegalException.class, () -> {
			copy(recipientSub.decryptAndVerifyFrom(input(cipher)), output(clone));
		});
	}
}
