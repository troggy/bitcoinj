/**
 * Copyright 2014 Kosta Korenkov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.bitcoin.signers;

import com.google.bitcoin.core.*;
import com.google.bitcoin.crypto.ChildNumber;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>This signer may be used as a template for creating custom multisig transaction signers.</p>
 * <p>
 * Concrete implementations have to implement {@link #getSignature(com.google.bitcoin.core.Sha256Hash, java.util.List)}
 * method returning signature and public key of keypair used to created that signature.
 * It's up to custom implementation where to locate signatures: it may be a network connection,
 * some local API or something else.
 * </p>
 */
public abstract class CustomTransactionSigner extends AbstractTransactionSigner {

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void signInputs(Transaction tx, @Nullable KeyParameter aesKey) {
        int numInputs = tx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getConnectedOutput();
            if (txOut == null) {
                continue;
            }

            checkArgument(txOut.getScriptPubKey().isPayToScriptHash(), "CustomTransactionSigner works only with P2SH transactions");
            Script inputScript = txIn.getScriptSig();
            checkNotNull(inputScript);
            Script redeemScript = getRedeemScript(inputScript);
            Sha256Hash sighash = tx.hashForSignature(i, redeemScript, Transaction.SigHash.ALL, false);
            SignatureAndKey sigKey = getSignature(sighash, txIn.getDerivationPath());
            TransactionSignature txSig = new TransactionSignature(sigKey.sig, Transaction.SigHash.ALL, false);
            int pos = getKeyPosition(txIn, sigKey.pubKey, inputScript);
            if (pos < 0)
                throw new RuntimeException("Redeem script doesn't contain our key"); // This should not happen
            inputScript = inputScript.addSignature(pos, txSig, true);
            txIn.setScriptSig(inputScript);
        }
    }

    protected abstract SignatureAndKey getSignature(Sha256Hash sighash, List<ChildNumber> derivationPath);

    public class SignatureAndKey {
        public ECKey.ECDSASignature sig;
        public ECKey pubKey;

        public SignatureAndKey(ECKey.ECDSASignature sig, ECKey pubKey) {
            this.sig = sig;
            this.pubKey = pubKey;
        }
    }

}



