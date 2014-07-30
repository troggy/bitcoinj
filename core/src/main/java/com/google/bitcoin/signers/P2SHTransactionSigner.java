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
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>This signer may be used as starting point for creating custom P2SH transaction signers.</p>
 * <p>
 * It tries to sign each input for a given transaction with provided keys. In case of failure (e.g. provided key has no
 * private bytes), it falls back to call abstract {@link #getTheirSignature(com.google.bitcoin.core.Sha256Hash, com.google.bitcoin.core.ECKey)}.
 * It's up to custom implementation where to locate signatures for missing private keys: it may be a network connection,
 * some local API or something else.
 * </p>
 */
public abstract class P2SHTransactionSigner implements TransactionSigner {

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public TransactionSignature[][] signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData) {
        int numInputs = tx.getInputs().size();
        int numSigs = redeemData.values().iterator().next().getKeys().size();
        TransactionSignature[][] signatures = new TransactionSignature[numInputs][numSigs];
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getOutpoint().getConnectedOutput();
            if (!redeemData.containsKey(txOut))
                continue;
            checkArgument(txOut.getScriptPubKey().isPayToScriptHash(), "TestP2SHTransactionSigner works only with P2SH transactions");
            Script redeemScript = redeemData.get(txOut).getRedeemScript();
            Sha256Hash sighash = tx.hashForSignature(i, redeemScript, Transaction.SigHash.ALL, false);
            List<ECKey> keys = redeemData.get(txOut).getKeys();
            // no need to calculate all signatures for N of M transaction, we need only minimum number required to spend
            int treshold = redeemScript.getNumberOfSignaturesRequiredToSpend();
            for (int j = 0; j < treshold; j++) {
                ECKey key = keys.get(j);
                try {
                    signatures[i][j] = new TransactionSignature(key.sign(sighash), Transaction.SigHash.ALL, false);
                } catch (ECKey.KeyIsEncryptedException e) {
                    throw e;
                } catch (ECKey.MissingPrivateKeyException e) {
                    // if key has no private key bytes, we asking signing server to provide signature for it
                    signatures[i][j] = new TransactionSignature(getTheirSignature(sighash, key), Transaction.SigHash.ALL, false);
                }
            }
        }

        return signatures;
    }

    protected abstract ECKey.ECDSASignature getTheirSignature(Sha256Hash sighash, ECKey theirKey);
}
