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
import java.util.Arrays;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import static java.util.Objects.*;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.*;

import static de.tk.opensource.secon.SECON.*;

/**
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author  Christian Schlichtherle
 */
final class DefaultSubscriber implements Subscriber {

	private volatile PrivateKey privateKey;
	private volatile X509Certificate certificate;

	private final Identity identity;
	private final Directory[] directories;

	DefaultSubscriber(final Identity identity, final Directory[] directories) {
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
		for (final Directory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(selector);
			if (cert.isPresent()) {
				return cert.get();
			}
		}
		throw new CertificateNotFoundException(selector.toString());
	}

	private X509Certificate certificate(final String identifier) throws Exception {
		for (final Directory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(identifier);
			if (cert.isPresent()) {
				return cert.get();
			}
		}
		throw new CertificateNotFoundException(identifier);
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

	private InputStream verify(final InputStream in, final Verifier verifier) throws Exception {
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
							throw new InvalidSignatureException();
						}
						verifier.verify(cert);
					}
				}
			};
	}

	private XFunction<InputStream, InputStream> verify(Verifier v) {
		return Streams.fixInputstreamClose(in -> verify(in, v));
	}

	private OutputStream encrypt(final OutputStream out, final Callable<X509Certificate>[] recipients)
		throws Exception
	{
		final CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
		Arrays.stream(recipients).map(RecipientInfoGeneratorFactory::create).forEach(gen::addRecipientInfoGenerator);
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
				.orElseThrow(CertificateMismatchException::new);

		final Recipient recipient =
			new JceKeyTransEnvelopedRecipient(key).setProvider(BouncyCastleProvider.PROVIDER_NAME);
		return info.getContentStream(recipient).getContentStream();
	}

	private final XFunction<InputStream, InputStream> decrypt = Streams.fixInputstreamClose(this::decrypt);

	private Socket<OutputStream> signAndEncryptTo(Socket<OutputStream> output, Callable<X509Certificate>[] recipients) {
		return output.map(sign.compose(encrypt(recipients)));
	}

	@Override
	public SeconCallable<OutputStream> signAndEncryptTo(
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

	@Override
	public SeconCallable<OutputStream> signAndEncryptTo(
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

	private Socket<InputStream> decryptAndVerifyFrom(Socket<InputStream> input, Verifier v) {
		return input.map(verify(v).compose(decrypt));
	}

	@Override
	public SeconCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input) {
		return callable(decryptAndVerifyFrom(socket(input), Verifier.NULL));
	}

	@Override
	public SeconCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input, Verifier v) {
		return callable(decryptAndVerifyFrom(socket(input), v));
	}
}
