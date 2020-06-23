/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.impl;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import de.tk.sys.security.cms.api.PKCS7KeyLocator;

/**
 * Mock-Implementierung für {@link PKCS7KeyLocator}. Bezieht seine Schlüssel aus 2 fest kodierten Keystores.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class KeystoreKeyLocator implements PKCS7KeyLocator {

	private final KeyStore sender;
	private final KeyStore recipient;

	private final String senderAlias;
	private final String recipientAlias;

	public KeystoreKeyLocator(KeyStore sender, KeyStore recipient) throws KeyStoreException {
		super();
		this.recipient = recipient;
		this.sender = sender;
		this.senderAlias = getFirstAlias(sender);
		this.recipientAlias = getFirstAlias(recipient);
	}

	@Override
	public X509Certificate lookupEncryptionCertificate(String identifier) {
		try {
			return (X509Certificate) recipient.getCertificate(recipientAlias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Encryption certificate not found", e);
		}
	}

	@Override
	public X509Certificate lookupSignatureCertificate() {
		try {
			return (X509Certificate) sender.getCertificate(senderAlias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Signature certificate not found", e);
		}
	}

	@Override
	public PrivateKey lookupSignatureKey() {
		try {
			return (PrivateKey) sender.getKey(senderAlias, "tkeasy".toCharArray());
		} catch (Exception e) {
			throw new RuntimeException("Signature key not found", e);
		}
	}

	@Override
	public X509Certificate lookupDecryptionCertificate() {
		try {
			return (X509Certificate) recipient.getCertificate(recipientAlias);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Recipient certificate not found", e);
		}
	}

	@Override
	public PrivateKey lookupDecryptionKey() {
		try {
			return (PrivateKey) recipient.getKey(recipientAlias, "tkeasy".toCharArray());
		} catch (Exception e) {
			throw new RuntimeException("Signature key not found", e);
		}
	}

	@Override
	public X509Certificate lookupVerificationCertificate(
		BigInteger    serialNumber,
		X500Principal x500Principal,
		String		  identifier
	) {
		return lookupSignatureCertificate();
	}

	private String getFirstAlias(KeyStore enryption) throws KeyStoreException {
		return enryption.aliases().nextElement();
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
