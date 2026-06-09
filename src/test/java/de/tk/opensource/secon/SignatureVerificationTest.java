package de.tk.opensource.secon;

import global.namespace.fun.io.api.Sink;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.api.Store;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.*;
import static global.namespace.fun.io.bios.BIOS.memory;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignatureVerificationTest {

    @Test
    void throwErrorForMessagesWithEmptySignatures() throws Exception {
        final Callable<char[]> pw = "secret"::toCharArray;
        final KeyStore ks = keyStore(() -> SignatureVerificationTest.class.getResourceAsStream("keystore.p12"), pw);

        Identity recipientId = identity(ks, "bob_pss_256", pw);
        final Subscriber recipient = subscriber(recipientId, directory(ks));

        // create message with empty signature
        byte[] encryptedMessageWithEmptySignature = encrypt(recipientId.certificate(), emptySignature("unsigned message"));

        Store cipher = memory();
        Store clone = memory();
        cipher.content(encryptedMessageWithEmptySignature);

        assertThrows(SeconException.class, () -> copy(recipient.decryptAndVerifyFrom(input(cipher)), output(clone)));
    }

    private static byte[] emptySignature(String message) throws Exception {
        CMSSignedDataGenerator gen = new  CMSSignedDataGenerator();
        return gen.generate(new CMSProcessableByteArray(message.getBytes(StandardCharsets.UTF_8)), true).getEncoded();
    }

    private static byte[] encrypt(X509Certificate certificate, byte[] payload) throws Exception {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate).setProvider("BC"));
        return gen.generate(new CMSProcessableByteArray(payload), new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build()).getEncoded();
    }

    private static Callable<InputStream> input(Source source) {return callable(source.input());}

    private static Callable<OutputStream> output(Sink sink) {
        return callable(sink.output());
    }

}
