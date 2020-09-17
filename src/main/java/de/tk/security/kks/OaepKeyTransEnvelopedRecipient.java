/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of kks-encryption
 * (see https://github.com/DieTechniker/kks-encryption).
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
package de.tk.security.kks;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

import java.security.PrivateKey;

/**
 * @author Wolfgang Schmiesing (P224488, IT.IN.FRW)
 * @author Christian Schlichtherle
 */
final class OaepKeyTransEnvelopedRecipient extends BcRSAKeyTransEnvelopedRecipient {

    private final AsymmetricKeyParameter key;

    OaepKeyTransEnvelopedRecipient(PrivateKey key) throws Exception {
        this(PrivateKeyFactory.createKey(key.getEncoded()));
    }

    OaepKeyTransEnvelopedRecipient(AsymmetricKeyParameter key) {
        super(key);
        this.key = key;
    }

    @Override
    protected CipherParameters extractSecretKey(
            AlgorithmIdentifier keyEncryptionAlgorithm,
            AlgorithmIdentifier encryptedKeyAlgorithm,
            byte[] encryptedEncryptionKey
    ) throws CMSException {
        AsymmetricKeyUnwrapper unwrapper = new OaepAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, key);
        try {
            return getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
        } catch (OperatorException e) {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }

    private static CipherParameters getBcKey(GenericKey key) {
        if ((key.getRepresentation() instanceof CipherParameters)) {
            return (CipherParameters) key.getRepresentation();
        }

        if ((key.getRepresentation() instanceof byte[])) {
            return new KeyParameter((byte[]) key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
