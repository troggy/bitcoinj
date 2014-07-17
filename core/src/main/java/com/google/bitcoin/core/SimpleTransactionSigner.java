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
package com.google.bitcoin.core;

import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>{@link TransactionSigner} implementation for signing pay-to-address and pay-to-pubkey transaction inputs. It always
 * uses {@link Transaction.SigHash#ALL} signing mode.</p>
 *
 * <p>This class expects single key to be provided for each TransactionOutput, otherwise it will throw an exception
 * (as it isn't able to sign multisig or P2SH transaction inputs).
 */
public class SimpleTransactionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(SimpleTransactionSigner.class);

    @Override
    public void signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData) {
        for (RedeemData constituent : redeemData.values()) {
            checkArgument(constituent.getRedeemScript() == null, "SimpleTransactionSigner doesn't work with P2SH transactions");
            checkArgument(constituent.getKeys().size() == 1, "SimpleTransactionSigner doesn't work with multisig transactions");
        }
        int numInputs = tx.getInputs().size();
        TransactionSignature[] signatures = new TransactionSignature[numInputs];
        ECKey[] signingKeys = new ECKey[numInputs];
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getOutpoint().getConnectedOutput();
            //kkorenkov todo: the checks below duplicate those in Wallet.signTransaction. Consider refactoring
            // We don't have the connected txOut, we assume it was signed already and move on
            if (txOut == null) {
                log.warn("Missing connected txOut, assuming txIn {} is already signed.", i);
                continue;
            }
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard txOut types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getOutpoint().getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends txOut, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }
            if (txIn.getScriptBytes().length != 0)
                log.warn("Re-signing an already signed transaction! Be sure this is what you want.");
            // Find the signing key we'll need to use.
            checkArgument(redeemData.get(txOut).getKeys().size() == 1, "Should have exactly one key to sign");
            ECKey key = redeemData.get(txOut).getKeys().get(0);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            // The anyoneCanPay feature isn't used at the moment.
            byte[] connectedPubKeyScript = txIn.getOutpoint().getConnectedPubKeyScript();
            try {
                signatures[i] = tx.calculateSignature(i, key, connectedPubKeyScript, Transaction.SigHash.ALL, false);
            } catch (ECKey.KeyIsEncryptedException e) {
                throw e;
            } catch (ECKey.MissingPrivateKeyException e) {
                // Create a dummy signature to ensure the transaction is of the correct size when we try to ensure
                // the right fee-per-kb is attached. If the wallet doesn't have the privkey, the user is assumed to
                // be doing something special and that they will replace the dummy signature with a real one later.
                signatures[i] = TransactionSignature.dummy();
                log.info("Used dummy signature for txIn {} due to failure during signing (most likely missing privkey)", i);
            }
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder: the script consists:
        // 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction) and the complete
        //    public key needed to sign for the connected output. The output script checks the provided pubkey hashes
        //    to the address and then checks the signature.
        // 2) For pay-to-key outputs: just a signature.
        for (int i = 0; i < tx.getInputs().size(); i++) {
            if (signatures[i] == null)
                continue;
            TransactionInput input = tx.getInput(i);
            final TransactionOutput connectedOutput = input.getOutpoint().getConnectedOutput();
            checkNotNull(connectedOutput);  // Quiet static analysis: is never null here but cannot be statically proven
            Script scriptPubKey = connectedOutput.getScriptPubKey();
            if (scriptPubKey.isSentToAddress()) {
                input.setScriptSig(ScriptBuilder.createInputScript(signatures[i], signingKeys[i]));
            } else if (scriptPubKey.isSentToRawPubKey()) {
                input.setScriptSig(ScriptBuilder.createInputScript(signatures[i]));
            } else {
                // Should be unreachable - if we don't recognize the type of script we're trying to sign for, we should
                // have failed above when fetching the key to sign with.
                throw new RuntimeException("Do not understand script type: " + scriptPubKey);
            }
        }
    }
}
