/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.bc.BcKeyTransRecipientInfoGenerator;

/**
 * Erzeugt die Empfänger-Infos für einen mit RSAES-OEAP verschlüsselten Content-Encryption-Key. Der symmetrische
 * Schlüssel wird mit dem öffentlichen Schlüssel des Empfängers verschlüsselt.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class OAEPTransRecipientInfoGenerator extends BcKeyTransRecipientInfoGenerator {

	/**
	 * @param   recipientCert  Zertifikat des Nachrichtenempfängers
	 * @param   algorithm      Algorithmus-OID für RSAES-OAEP
	 *
	 * @throws  CertificateEncodingException
	 * @throws  IOException
	 */
	public OAEPTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmIdentifier algorithm)
		throws CertificateEncodingException, IOException
	{
		super(
			new JcaX509CertificateHolder(recipientCert),
			new OAEPAsymmetricKeyWrapper(algorithm, recipientCert.getPublicKey())
		);
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
