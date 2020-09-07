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

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.Test;

import static global.namespace.fun.io.bios.BIOS.*;

import static org.junit.jupiter.api.Assertions.*;

import static de.tk.security.kks.KKS.*;
import static de.tk.security.kks.KKS.copy;
import static de.tk.security.kks.KKS.directory;
import static de.tk.security.kks.KKS.identity;

/**
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author  Christian Schlichtherle
 */
public class KksTest {

	@Test
	void aliceToBobUsingRSA256() throws Exception {
		assertKks("alice_rsa_256", "bob_rsa_256");
	}

	@Test
	void bobToAliceUsingRSA256() throws Exception {
		assertKks("bob_rsa_256", "alice_rsa_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_256() throws Exception {
		assertKks("alice_pss_256", "bob_pss_256");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_256() throws Exception {
		assertKks("bob_pss_256", "alice_pss_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_384() throws Exception {
		assertKks("alice_pss_384", "bob_pss_384");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_384() throws Exception {
		assertKks("bob_pss_384", "alice_pss_384");
	}

	private static void assertKks(final String sender, final String recipient) throws Exception {
		final Callable<char[]> pw = "secret"::toCharArray;
		final KeyStore ks = keyStore(() -> KksTest.class.getResourceAsStream("keystore.p12"), pw);
		assertKks(identity(ks, sender, pw), identity(ks, recipient, pw), directory(ks));
	}

	private static void assertKks(
		final KksIdentity  senderId,
		final KksIdentity  recipientId,
		final KksDirectory directory
	) throws Exception
	{
		final KksSubscriber senderSub = subscriber(senderId, directory);
		final KksSubscriber recipientSub = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		final Store plain = memory(), cipher = memory(), clone = memory();
		plain.content("Hello world!".getBytes());
		copy(input(plain), senderSub.signAndEncryptTo(output(cipher), recipientCert));

        // Simulate certificate verification failure:
        {
            final KksException e = new KksException();
            assertSame(e, assertThrows(KksException.class, () -> copy(
                    recipientSub.decryptAndVerifyFrom(input(cipher), cert -> {
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
}

