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

import global.namespace.fun.io.api.Socket;
import global.namespace.fun.io.api.function.XFunction;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.Optional;
import java.util.concurrent.Callable;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import static java.util.Objects.*;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.*;

import static de.tk.security.kks.KKS.*;

/**
 * Ein Kontextobjekt, welches einen Kommunikationsteilnehmer im KKS repräsentiert und diesem das Versenden und Empfangen
 * von Nachrichten im CMS-Format (Cryptographic Message Syntax) ermöglicht.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author  Christian Schlichtherle
 */
public final class KksSubscriber {

	private volatile PrivateKey privateKey;
	private volatile X509Certificate certificate;

	private final KksIdentity identity;
	private final KksDirectory[] directories;

	KksSubscriber(final KksIdentity identity, final KksDirectory[] directories) {
		this.identity = identity;
		this.directories = directories;
	}

	private PrivateKey privateKey() throws Exception {
		final PrivateKey k = this.privateKey;
		return null != k ? k : (this.privateKey = identity.privateKey());
	}

	private X509Certificate certificate() throws Exception {
		final X509Certificate c = this.certificate;
		return null != c ? c : (this.certificate = identity.certificate());
	}

	private static X500Principal principal(final X500Name name) {
		try {
			return new X500Principal(name.getEncoded());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private static X509CertSelector selector(final SignerId id) {
		final X509CertSelector sel = new X509CertSelector();
		Optional.ofNullable(id.getIssuer()).ifPresent(issuer -> sel.setIssuer(principal(issuer)));
		sel.setSerialNumber(id.getSerialNumber());
		sel.setSubjectKeyIdentifier(id.getSubjectKeyIdentifier());
		return sel;
	}

	private X509Certificate certificate(SignerId id) throws Exception {
		return certificate(selector(id));
	}

	private X509Certificate certificate(final X509CertSelector selector) throws Exception {
		for (final KksDirectory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(selector);
			if (cert.isPresent()) {
				return cert.get();
			}
		}
		throw new KksCertificateNotFoundException(selector.toString());
	}

	private X509Certificate certificate(final String identifier) throws Exception {
		for (final KksDirectory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(identifier);
			if (cert.isPresent()) {
				return cert.get();
			}
		}
		throw new KksCertificateNotFoundException(identifier);
	}

	private OutputStream sign(final OutputStream out) throws Exception {
		final X509Certificate cert = certificate();
		final PrivateKey key = privateKey();
		final ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(cert.getSigAlgOID());
		final ContentSigner signer;
		if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOID)) {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance(cert.getSigAlgName());
			parameters.init(cert.getSigAlgParams());
			signer =
				new JcaContentSignerBuilder(cert.getSigAlgName(), parameters.getParameterSpec(PSSParameterSpec.class))
					.setProvider(PROVIDER_NAME)
					.build(key);

		} else {
			signer = new JcaContentSignerBuilder(cert.getSigAlgName())
					.setProvider(PROVIDER_NAME)
					.build(key);
		}
		final CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
		gen.addSignerInfoGenerator(
			new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder()
					.setProvider(PROVIDER_NAME)
					.build()
			).build(signer, cert)
		);
		return gen.open(out, true);
	}

	private final XFunction<OutputStream, OutputStream> sign = Streams.fixOutputstreamClose(this::sign);

	private InputStream verify(final InputStream in, final KksVerifier verifier) throws Exception {
		final CMSSignedDataParser parser =
			new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER_NAME).build(),
				new BufferedInputStream(in)
			);
		final CMSTypedStream signedContent = parser.getSignedContent();
		return
			new FilterInputStream(signedContent.getContentStream()) {

				@Override
				public void close() throws IOException {
					SideEffect.runAll(signedContent::drain, this::verifyIo);
				}

				private void verifyIo() throws IOException {
					try {
						verify();
					} catch (IOException | RuntimeException e) {
						throw e;
					} catch (Exception e) {
						throw new IOException(e);
					}
				}

				private void verify() throws Exception {
					for (final SignerInformation info : parser.getSignerInfos()) {
						final X509Certificate cert = certificate(info.getSID());
						final SignerInformationVerifier ver =
							new JcaSimpleSignerInfoVerifierBuilder()
								.setProvider(PROVIDER_NAME)
								.build(cert);
						if (!info.verify(ver)) {
							throw new KksInvalidSignatureException();
						}
						verifier.verify(cert);
					}
				}
			};
	}

	private XFunction<InputStream, InputStream> verify(KksVerifier v) {
		return Streams.fixInputstreamClose(in -> verify(in, v));
	}

	private OutputStream encrypt(final OutputStream out, final Callable<X509Certificate>[] recipients)
		throws Exception
	{
		final CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
		for (final Callable<X509Certificate> recipient : recipients) {
			final X509Certificate cert = recipient.call();
			gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(PROVIDER_NAME));
		}
		final OutputEncryptor encryptor =
			new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
				.setProvider(PROVIDER_NAME)
				.build();
		return gen.open(out, encryptor);
	}

	private XFunction<OutputStream, OutputStream> encrypt(Callable<X509Certificate>[] recipients) {
		return Streams.fixOutputstreamClose(out -> encrypt(out, recipients));
	}

	private InputStream decrypt(final InputStream in) throws Exception {
		final X509Certificate cert = certificate();
		final PrivateKey key = privateKey();
		final RecipientInformation info =
			Optional
				.ofNullable(
					new CMSEnvelopedDataParser(new BufferedInputStream(in))
						.getRecipientInfos()
						.get(new JceKeyTransRecipientId(cert))
				)
				.orElseThrow(KksCertificateMismatchException::new);

		final Recipient recipient =
			new JceKeyTransEnvelopedRecipient(key).setProvider(BouncyCastleProvider.PROVIDER_NAME);
		return info.getContentStream(recipient).getContentStream();
	}

	private final XFunction<InputStream, InputStream> decrypt = Streams.fixInputstreamClose(this::decrypt);

	private Socket<OutputStream> signAndEncryptTo(Socket<OutputStream> output, Callable<X509Certificate>[] recipients) {
		return output.map(sign.compose(encrypt(recipients)));
	}

	/**
	 * Erzeugt einen erneuerbaren Ausgabestrom, der die Daten, die in den gegebenen erneuerbaren Ausgabestrom
     * geschrieben werden, signiert und für die gegebenen Empfänger verschlüsselt.
     * Die Empfänger werden durch die gegebenen Zertifikate identifiziert.
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Ausgabeströme zu {@linkplain OutputStream#close() schließen}, da
     * es andernfalls zu Datenverlust kommt!
     * Es wird daher empfohlen, die erneuerbaren Ausgabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	public KksCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final X509Certificate		 recipient,
		final X509Certificate...     others
	) {
		@SuppressWarnings("unchecked")
		final Callable<X509Certificate>[] recipients = new Callable[others.length + 1];
		requireNonNull(recipient);
		recipients[0] = () -> recipient;
		for (int i = 0; i < others.length;) {
			final X509Certificate other = requireNonNull(others[i]);
			recipients[++i] = () -> other;
		}
		return callable(signAndEncryptTo(socket(output), recipients));
	}

	/**
	 * Erzeugt einen erneuerbaren Ausgabestrom, der die Daten, die in den gegebenen erneuerbaren Ausgabestrom
     * geschrieben werden, signiert und für die gegebenen Empfänger verschlüsselt.
     * Die Empfänger werden durch die gegebenen Institutionskennzeichen identifiziert.
     * Diese fangen typischerweise mit "IK" oder "BN" an, gefolgt von einer neunstelligen Zahl gemäß
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/faq/Gemeinsames_Rundschreiben_IK_2015-03.pdf">Rundschreiben ARGE-IK</a>.
     * Die entsprechenden Zertifikate werden vom LDAP-Server geladen.
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Ausgabeströme zu {@linkplain OutputStream#close() schließen}, da
     * es andernfalls zu Datenverlust kommt!
     * Es wird daher empfohlen, die erneuerbaren Ausgabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	public KksCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final String				 recipientId,
		final String... 			 otherIds
	) {
		@SuppressWarnings("unchecked")
		final Callable<X509Certificate>[] recipients = new Callable[otherIds.length + 1];
		requireNonNull(recipientId);
		recipients[0] = () -> certificate(recipientId);
		for (int i = 0; i < otherIds.length;) {
			final String other = requireNonNull(otherIds[i]);
			recipients[++i] = () -> certificate(other);
		}
		return callable(signAndEncryptTo(socket(output), recipients));
	}

	private Socket<InputStream> decryptAndVerifyFrom(Socket<InputStream> input, KksVerifier v) {
		return input.map(verify(v).compose(decrypt));
	}

	/**
     * Erzeugt einen erneuerbaren Eingabestrom, der die Daten, die von dem gegebenen erneuerbaren Eingabestrom
     * gelesen werden, entschlüsselt und die digitalen Signaturen überprüft.
     * Bei dieser Variante der Methode werden die Zertifikate der Absender <em>nicht überprüft</em>!
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Eingabeströme zu {@linkplain InputStream#close() schließen}, da
     * andernfalls die digitalen Signaturen nicht überprüft werden!
     * Es wird daher empfohlen, die erneuerbaren Eingabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	public KksCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input) {
		return callable(decryptAndVerifyFrom(socket(input), KksVerifier.NULL));
	}

	/**
     * Erzeugt einen erneuerbaren Eingabestrom, der die Daten, die von dem gegebenen erneuerbaren Eingabestrom
     * gelesen werden, entschlüsselt und die digitalen Signaturen überprüft.
     * Bei dieser Variante der Methode werden die Zertifikate der Absender zusätzlich durch den gegebenen Verifizierer
     * überprüft.
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Eingabeströme zu {@linkplain InputStream#close() schließen}, da
     * andernfalls die digitalen Signaturen nicht überprüft werden!
     * Es wird daher empfohlen, die erneuerbaren Eingabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
	 */
	public KksCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input, KksVerifier v) {
		return callable(decryptAndVerifyFrom(socket(input), v));
	}
}

