package de.tk.opensource.secon;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Utility class for certificate related operations.
 *
 * @author  Wolfgang Schmiesing
 */
final class Certificates {

    static boolean isCA(X509Certificate p) {
        return p.getBasicConstraints() >= 0;
    }

    static boolean signedBy(X509Certificate cert, X509Certificate issuer) {
        try {
            verify(cert, issuer);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean selfSigned(X509Certificate cert) {
        return signedBy(cert, cert);
    }

    static void verify(X509Certificate cert, X509Certificate issuer) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        cert.verify(issuer.getPublicKey());
    }


}
