package de.tk.opensource.secon;

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.callable;
import static de.tk.opensource.secon.SECON.copy;
import static de.tk.opensource.secon.SECON.keyStore;
import static de.tk.opensource.secon.SECON.subscriber;
import static global.namespace.fun.io.bios.BIOS.memory;
import static org.junit.jupiter.api.Assertions.*;

public final class IssuerValidationTest {

    private KeyStore keystore;

    private final Callable<char[]> pw = "secret"::toCharArray;

    @BeforeEach
    void setup() throws Exception {
        keystore = keyStore(() -> EmbeddedCertificateTest.class.getResourceAsStream("keystore.p12"), pw);
    }

    private static final byte[] CONTENT = "test message".getBytes(StandardCharsets.UTF_8);
    private static final String IMPERSONATED_DN = "CN=Impersonated User";

    @Test
    void issuerMustHaveBasicConstraints() throws Exception {
        Store cipher, clone;

        cipher = memory();
        clone = memory();

        Identity senderId = SECON.identity(keystore, "alice_pss_256", pw);
        Identity recipientId = SECON.identity(keystore, "bob_pss_256", pw);

        Subscriber recipient = subscriber(recipientId, SECON.directory(keystore));

        X509Certificate recipientCert = recipientId.certificate();
        byte[] signed = signedUnderEnrolledLeaf(senderId.privateKey(), senderId.certificate());
        byte[] signedAndEncrypted = encryptTo(recipientCert, signed);

        cipher.content(signedAndEncrypted);

        assertThrows(SeconException.class, () -> copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone)));
    }

    private static byte[] signedUnderEnrolledLeaf(PrivateKey leafKey, X509Certificate leafCert) throws Exception {
        X500Name issuer = X500Name.getInstance(leafCert.getSubjectX500Principal().getEncoded());
        KeyPair signing = generateRsa();
        X509Certificate forged = mintCertificate(new X500Name(IMPERSONATED_DN), signing.getPublic(), issuer, leafKey);
        return sign(forged, signing.getPrivate());
    }

    private static X509Certificate mintCertificate(X500Name subject, PublicKey subjectKey,
                                                   X500Name issuer, PrivateKey issuerKey) throws Exception {
        long day = 24L * 60 * 60 * 1000;
        Date from = new Date(System.currentTimeMillis() - day);
        Date to = new Date(System.currentTimeMillis() + day);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(1000), from, to, subject, subjectKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static byte[] sign(X509Certificate signerCert, PrivateKey signerKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerKey);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                        .build(signer, signerCert));
        gen.addCertificate(new JcaX509CertificateHolder(signerCert));
        return gen.generate(new CMSProcessableByteArray(CONTENT), true).getEncoded();
    }

    private static byte[] encryptTo(X509Certificate recipient, byte[] inner) throws Exception {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
        return gen.generate(
                new CMSProcessableByteArray(inner),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build()
        ).getEncoded();
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static Callable<InputStream> input(Source source) {
        return callable(source.input());
    }

    private static Callable<OutputStream> output(Sink sink) {
        return callable(sink.output());
    }

}