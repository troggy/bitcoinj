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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>{@link TransactionSigner} implementation for signing pay-to-address and pay-to-pubkey transaction inputs. It always
 * uses {@link com.google.bitcoin.core.Transaction.SigHash#ALL} signing mode.</p>
 *
 * <p>This class expects single key to be provided for each TransactionOutput, otherwise it will throw an exception
 * (as it isn't able to sign multisig or P2SH transaction inputs).
 */
public class SimpleTransactionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(SimpleTransactionSigner.class);

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public TransactionSignature[][] signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData) {
        for (RedeemData constituent : redeemData.values()) {
            checkArgument(constituent.getRedeemScript() == null, "SimpleTransactionSigner doesn't work with P2SH transactions");
            checkArgument(constituent.getKeys().size() == 1, "SimpleTransactionSigner doesn't work with multisig transactions");
        }

        int numInputs = tx.getInputs().size();
        TransactionSignature[][] signatures = new TransactionSignature[numInputs][1];
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getOutpoint().getConnectedOutput();
            if (!redeemData.containsKey(txOut))
                continue;
            ECKey key = redeemData.get(txOut).getKeys().get(0);
            byte[] connectedPubKeyScript = txIn.getOutpoint().getConnectedPubKeyScript();
            try {
                signatures[i][0] = tx.calculateSignature(i, key, connectedPubKeyScript, Transaction.SigHash.ALL, false);
            } catch (ECKey.KeyIsEncryptedException e) {
                throw e;
            } catch (ECKey.MissingPrivateKeyException e) {
                // Create a dummy signature to ensure the transaction is of the correct size when we try to ensure
                // the right fee-per-kb is attached. If the wallet doesn't have the privkey, the user is assumed to
                // be doing something special and that they will replace the dummy signature with a real one later.
                signatures[i][0] = TransactionSignature.dummy();
                log.info("Used dummy signature for txIn {} due to failure during signing (most likely missing privkey)", i);
            }
        }
        return signatures;
    }
}
