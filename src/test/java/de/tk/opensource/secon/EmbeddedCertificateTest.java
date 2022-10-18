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

import static de.tk.opensource.secon.SECON.callable;
import static de.tk.opensource.secon.SECON.copy;
import static de.tk.opensource.secon.SECON.directory;
import static de.tk.opensource.secon.SECON.identity;
import static de.tk.opensource.secon.SECON.keyStore;
import static de.tk.opensource.secon.SECON.subscriber;
import static global.namespace.fun.io.bios.BIOS.memory;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class EmbeddedCertificateTest {

	private KeyStore keystore;
	private final Callable<char[]> pw = "secret"::toCharArray;

	@BeforeEach
	void setup() throws Exception {
		keystore = keyStore(() -> EmbeddedCertificateTest.class.getResourceAsStream("keystore.p12"), pw);
	}

	@Test
	void embedCertificateIntoPayload() throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(1024, new SecureRandom());

		// sender uses self-signed cert
		Identity senderId = new KeyPairIdentity(keyPairGenerator.generateKeyPair());
		
		Identity recipientId = identity(keystore, "alice_rsa_256", pw);
		Directory directory = directory(keystore);

		final Subscriber sender = subscriber(senderId, directory);
		final Subscriber recipient = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		
		final Store plain = memory(), cipher = memory(), clone = memory();
		// input message
		plain.content("Hello world!".getBytes());
		
		copy(input(plain), sender.signAndEncryptTo(output(cipher), recipientCert));

		copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone));
		assertArrayEquals(plain.content(), clone.content());
	}

	private static Callable<InputStream> input(Source source) {
		return callable(source.input());
	}

	private static Callable<OutputStream> output(Sink sink) {
		return callable(sink.output());
	}


}
