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
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptChunk;

import java.util.Arrays;
import java.util.List;

public abstract class AbstractTransactionSigner implements TransactionSigner {
    protected int getKeyPosition(TransactionInput txIn, ECKey key, Script inputScript) {
        List<byte[]> pubKeys;
        boolean isP2SH = txIn.getConnectedOutput().getScriptPubKey().isPayToScriptHash();
        if (isP2SH) {
            Script redeemScript = getRedeemScript(inputScript);
            pubKeys = redeemScript.getPubKeys();
            for (int i = 0; i < pubKeys.size(); i++) {
                byte[] pubKey = pubKeys.get(i);
                if (Arrays.equals(pubKey, key.getPubKey()))
                    return i;
            }
            return -1;
        } else {
            return 0;
        }
    }

    protected Script getRedeemScript(Script inputScript) {
        List<ScriptChunk> chunks = inputScript.getChunks();
        byte[] program = chunks.get(chunks.size() - 1).data;
        return new Script(program);
    }
}
