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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Optional;
import java.util.concurrent.Callable;

import static de.tk.security.kks.KKS.socket;
import static de.tk.security.kks.KKS.callable;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

/**
 * Ein Kontextobjekt, welches einen Kommunikationsteilnehmer im KKS repräsentiert und diesem das Versenden und Empfangen
 * von Nachrichten im CMS-Format (Cryptographic Message Syntax) ermöglicht.
 *
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
public abstract class KksSubscriber {

    /**
     * Gibt den privaten Schlüssel für diesen Kommunikationsteilnehmer zurück.
     * Der private Schlüssel wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen und um
     * verschlüsselte Nachrichten zu entschlüsseln.
     */
    protected abstract PrivateKey myPrivateKey() throws Exception;

    /**
     * Gibt das Zertifikat für diesen Kommunikationsteilnehmer zurück.
     * Das Zertifikat wird verwendet um Nachrichten mit einer digitalen Signatur zu versehen und um verschlüsselte
     * Nachrichten zu entschlüsseln.
     */
    public abstract X509Certificate myCertificate() throws Exception;

    /**
     * Sucht das Zertifikat für einen anderen Kommunikationsteilnehmer, das zu dem gegebenen Selektor passt.
     * Das Zertifikat wird verwendet, um die digitalen Signaturen von Nachrichten zu überprüfen.
     */
    protected abstract Optional<X509Certificate> certificate(X509CertSelector selector) throws Exception;

    private OutputStream sign(final OutputStream out) throws Exception {
        final X509Certificate cert = myCertificate();
        final PrivateKey key = myPrivateKey();
        final ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(cert.getSigAlgOID());
        final ContentSigner signer;
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOID)) {
            signer = new PssContentSignerBuilder(
                    new AlgorithmIdentifier(
                            sigAlgOID,
                            ASN1Primitive.fromByteArray(cert.getSigAlgParams())
                    ),
                    KksAlgorithms.SIGNATURE_DIGEST_ALGORITHM
            ).build(PrivateKeyFactory.createKey(key.getEncoded()));
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

    private InputStream verify(final InputStream in) throws Exception {
        final CMSSignedDataParser parser = new CMSSignedDataParser(
                new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER_NAME).build(),
                new BufferedInputStream(in)
        );
        final CMSTypedStream signedContent = parser.getSignedContent();
        return new FilterInputStream(signedContent.getContentStream()) {

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
                    final X509CertSelector selector = selector(info.getSID());
                    final X509Certificate cert = certificate(selector)
                            .orElseThrow(() -> new KksCertificateNotFoundException(selector.toString()));
                    final SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider(PROVIDER_NAME)
                            .build(cert);
                    if (!info.verify(verifier)) {
                        throw new KksInvalidSignatureException();
                    }
                }
            }

            private X509CertSelector selector(final SignerId signerId) {
                final X509CertSelector selector = new X509CertSelector();
                Optional.ofNullable(signerId.getIssuer())
                        .ifPresent(issuer -> selector.setIssuer(principal(issuer)));
                selector.setSerialNumber(signerId.getSerialNumber());
                selector.setSubjectKeyIdentifier(signerId.getSubjectKeyIdentifier());
                return selector;
            }

            private X500Principal principal(final X500Name name) {
                try {
                    return new X500Principal(name.getEncoded());
                } catch (IOException e) {
                    throw new AssertionError(e);
                }
            }
        };
    }

    private final XFunction<InputStream, InputStream> verify = Streams.fixInputstreamClose(this::verify);

    private static int keySize(final X509Certificate cert) {
        final RSAKey rsaPk = (RSAKey) cert.getPublicKey();
        return rsaPk.getModulus().bitLength();
    }

    private OutputStream encrypt(final OutputStream out, final X509Certificate... recipients) throws Exception {
        final CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
        for (final X509Certificate recipient :  recipients) {
            if (keySize(recipient) < 4096) {
                gen.addRecipientInfoGenerator(
                        new JceKeyTransRecipientInfoGenerator(recipient)
                                .setProvider(PROVIDER_NAME)
                );
            } else {
                gen.addRecipientInfoGenerator(new OaepTransRecipientInfoGenerator(
                        recipient,
                        KksAlgorithms.ENCRYPTION_ALGORITHM_RSAES_OAEP
                ));
            }
        }
        final OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider(PROVIDER_NAME)
                .build();
        return gen.open(out, encryptor);
    }

    private XFunction<OutputStream, OutputStream> encrypt(X509Certificate... recipients) {
        return Streams.fixOutputstreamClose(out -> encrypt(out, recipients));
    }

    private InputStream decrypt(final InputStream in) throws Exception {
        final X509Certificate cert = myCertificate();
        final PrivateKey key = myPrivateKey();
        final RecipientInformation info = Optional.ofNullable(
                new CMSEnvelopedDataParser(new BufferedInputStream(in))
                        .getRecipientInfos()
                        .get(new JceKeyTransRecipientId(cert))
        ).orElseThrow(KksCertificateMismatchException::new);
        final Recipient recipient;
        if (keySize(cert) < 4096) {
            recipient = new JceKeyTransEnvelopedRecipient(key).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        } else {
            recipient = new OaepKeyTransEnvelopedRecipient(key);
        }
        return info.getContentStream(recipient).getContentStream();
    }

    private final XFunction<InputStream, InputStream> decrypt = Streams.fixInputstreamClose(this::decrypt);

    private final XFunction<InputStream, InputStream> decryptAndVerify = verify.compose(decrypt);

    private Socket<OutputStream> signAndEncryptTo(Socket<OutputStream> output, X509Certificate... recipients) {
        return output.map(sign.compose(encrypt(recipients)));
    }

    /**
     * Gibt einen erneuerbaren Ausgabestrom zurück, der die Daten, die in den gegebenen erneuerbaren Ausgabestrom
     * geschrieben werden, signiert und für die gegebenen Empfänger verschlüsselt.
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Ausgabeströme zu {@linkplain OutputStream#close() schließen}, da
     * es andernfalls zu Datenverlust kommt!
     * Es wird daher empfohlen, die erneuerbaren Ausgabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
     */
    public final KksCallable<OutputStream> signAndEncryptTo(
            final Callable<OutputStream> output,
            final X509Certificate recipient,
            final X509Certificate... others
    ) {
        final X509Certificate[] recipients = new X509Certificate[others.length + 1];
        recipients[0] = recipient;
        System.arraycopy(others, 0, recipients, 1, others.length);
        return callable(signAndEncryptTo(socket(output), recipients));
    }

    private Socket<InputStream> decryptAndVerifyFrom(Socket<InputStream> input) {
        return input.map(decryptAndVerify);
    }

    /**
     * Gibt einen erneuerbaren Eingabestrom zurück, der die Daten, die von dem gegebenen erneuerbaren Eingabestrom
     * gelesen werden, entschlüsselt und die digitalen Signaturen überprüft.
     * <p>
     * Der Aufrufer ist verpflichtet, die erzeugten Eingabeströme zu {@linkplain InputStream#close() schließen}, da
     * andernfalls die digitalen Signaturen nicht überprüft werden!
     * Es wird daher empfohlen, die erneuerbaren Eingabeströme nur in <i>try-with-resources</i>-Anweisungen zu benutzen.
     */
    public final KksCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input) {
        return callable(decryptAndVerifyFrom(socket(input)));
    }
}
