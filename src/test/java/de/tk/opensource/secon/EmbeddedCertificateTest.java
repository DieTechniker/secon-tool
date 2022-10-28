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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;

/**
 * @author Wolfgang Schmiesing
 */
public class EmbeddedCertificateTest {

	private KeyStore keystore;
	
	private final Callable<char[]> pw = "secret"::toCharArray;

	private Subscriber sender;

	private Subscriber recipient;

	private X509Certificate recipientCert;
	
	private Store plain, cipher, clone;

	private Identity senderId;	

	@BeforeEach
	void setup() throws Exception {
		plain = memory(); 
		cipher = memory(); 
		clone = memory();
		
		// input message
		plain.content("Hello world!".getBytes());
		
		keystore = keyStore(() -> EmbeddedCertificateTest.class.getResourceAsStream("keystore.p12"), pw);		
	}

	@Test
	void embedded_cert_found_in_directory() throws Exception {
		// sender
		createSender(directory(keystore), identity(keystore, "bob_rsa_256", pw));		
		// recipient
		createRecipient(directory(keystore));
		
		// send -> receive
		copy(input(plain), sender.signAndEncryptTo(output(cipher), recipientCert));
		copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone));
		
		assertArrayEquals(plain.content(), clone.content());
	}

	@Test
	void verify_embeddedCertificate_against_truststore() throws Exception {
		// sender with self-signed certificate
		createSender(directory(keystore), new KeyPairIdentity("CN=John Doe", 10));		
		// recipient trusts sender
		createRecipient(directory(keystore(senderId.certificate())));
		
		// send -> receive
		copy(input(plain), sender.signAndEncryptTo(output(cipher), recipientCert));
        copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone));
		
		assertArrayEquals(plain.content(), clone.content());
	}

	@Test
	void verify_embeddedCertificate_against_empty_truststore() throws Exception {
		// sender
		createSender(directory(keystore), new KeyPairIdentity("CN=John Doe", 10));		
		// empty truststore	
		createRecipient(new EmptyDirectory());

		// send -> receive
		copy(input(plain), sender.signAndEncryptTo(output(cipher), recipientCert));
        assertThrows(CertificateNotFoundException.class, () -> copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone)));
		
		assertArrayEquals(plain.content(), clone.content());
	}
	
	@Test
	void verify_embeddedCertificate_against_truststore_failure() throws Exception {
		// sender
		createSender(directory(keystore), new KeyPairIdentity("CN=John Doe", 10));		
		// default Java truststore
		KeyStore trusted = keyStore(() -> EmbeddedCertificateTest.class.getResourceAsStream("cacerts"), "changeit"::toCharArray);	
		createRecipient(directory(trusted));
		

		// send -> receive
		copy(input(plain), sender.signAndEncryptTo(output(cipher), recipientCert));
        assertThrows(CertificateNotFoundException.class, () -> copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone)));
		
		assertArrayEquals(plain.content(), clone.content());
	}



	private static Callable<InputStream> input(Source source) {
		return callable(source.input());
	}

	private static Callable<OutputStream> output(Sink sink) {
		return callable(sink.output());
	}
	

	private void createRecipient(Directory directory) throws Exception {
		Identity recipientId = identity(keystore, "alice_rsa_256", pw);
		recipient = subscriber(recipientId, directory);
		recipientCert = recipientId.certificate();
	}

	private void createSender(Directory directory, Identity senderId) {
		this.senderId = senderId;
		sender = subscriber(senderId, directory);
	}


	private KeyStore keystore(X509Certificate cert)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, Exception {
		KeyStore trusted = KeyStore.getInstance(KeyStore.getDefaultType());
		trusted.load(null,null);
		trusted.setCertificateEntry("trusted", cert);
		return trusted;
	}
	
	class EmptyDirectory implements Directory {

		@Override
		public Optional<X509Certificate> certificate(X509CertSelector selector) throws Exception {
			return Optional.empty();
		}

		@Override
		public Optional<X509Certificate> certificate(String identifier) throws Exception {
			return Optional.empty();
		}
		
	}
}
