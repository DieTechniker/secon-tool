/*--- (C) 1999-2020 Techniker Krankenkasse ---*/

package de.tk.sys.security.cms.padding;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;

/**
 * Erzeugt einen {@link Signer} der eine Signatur mittels RSASSA-PSS erzeugen kann.
 *
 * @author  Wolfgang Schmiesing (P224488, IT.IN.FRW)
 */
public class PSSContentSignerBuilder extends BcContentSignerBuilder {

	/**
	 * @param  signature  Signatur-Algorithmus
	 * @param  digest     Hash-Algorithmus
	 */
	public PSSContentSignerBuilder(AlgorithmIdentifier signature, AlgorithmIdentifier digest) {
		super(signature, digest);
	}

	@Override
	protected Signer createSigner(
		AlgorithmIdentifier paramAlgorithmIdentifier1,
		AlgorithmIdentifier paramAlgorithmIdentifier2
	) throws OperatorCreationException
	{
		return new PSSSigner(new RSAEngine(), DigestFactory.getDigest("SHA-256"), 32);
	}

}

/*--- Formatiert nach TK Code Konventionen vom 05.03.2002 ---*/
