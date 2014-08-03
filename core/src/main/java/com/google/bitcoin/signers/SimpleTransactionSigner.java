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

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.ScriptException;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.wallet.MultisigKeyBag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

/**
 * <p>{@link TransactionSigner} implementation for signing pay-to-address and pay-to-pubkey transaction inputs. It always
 * uses {@link com.google.bitcoin.core.Transaction.SigHash#ALL} signing mode.</p>
 * <p/>
 * <p>This class expects single key to be provided for each TransactionOutput, otherwise it will throw an exception
 * (as it isn't able to sign multisig or P2SH transaction inputs).
 */
public class SimpleTransactionSigner extends AbstractTransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(SimpleTransactionSigner.class);

    private MultisigKeyBag keyBag;

    public SimpleTransactionSigner(MultisigKeyBag keyBag) {
        this.keyBag = keyBag;
    }

    @Override
    public boolean isReady() {
        return true;
    }


    @Override
    public byte[] serialize() {
        return new byte[0];
    }

    @Override
    public void signInputs(Transaction tx, @Nullable KeyParameter aesKey) {
        int numInputs = tx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            if (txIn.getConnectedOutput() == null) {
                log.warn("Missing connected output, assuming input {} is already signed.", i);
                continue;
            }
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }


            ECKey key = txIn.getOutpoint().getConnectedKey(keyBag).maybeDecrypt(aesKey);
            if (key == null)
                continue;
            boolean isP2SH = txIn.getConnectedOutput().getScriptPubKey().isPayToScriptHash();
            Script inputScript = txIn.getScriptSig();
            byte[] script;
            if (isP2SH) {
                script = getRedeemScript(inputScript).getProgram();
            } else {
                script = txIn.getOutpoint().getConnectedPubKeyScript();
            }
            TransactionSignature signature;
            try {
                signature = tx.calculateSignature(i, key, script, Transaction.SigHash.ALL, false);
                int index = getKeyPosition(txIn, key, inputScript);
                if (index < 0)
                    throw new RuntimeException("Input script doesn't contain our key"); // This should not happen
                inputScript = inputScript.addSignature(index, signature, isP2SH);
                txIn.setScriptSig(inputScript);
                if (key instanceof DeterministicKey)
                    txIn.setDerivationPath(((DeterministicKey)key).getPath());
            } catch (ECKey.KeyIsEncryptedException e) {
                throw e;
            } catch (ECKey.MissingPrivateKeyException e) {
                // do nothing. Assuming it will be signed by other TransactionSigner.
            }
        }
    }

}
