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
