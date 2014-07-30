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
package com.google.bitcoin.testing;

import com.google.bitcoin.core.RedeemData;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.signers.TransactionSigner;

import java.util.Map;

public class DummyTransactionSigner implements TransactionSigner {
    private boolean isReady;
    private byte[] data;

    public DummyTransactionSigner(boolean ready, byte[] data) {
        this.isReady = ready;
        this.data = data;
    }

    @Override
    public boolean isReady() {
        return isReady;
    }

    @Override
    public byte[] serialize() {
        return data;
    }

    @Override
    public TransactionSignature[][] signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData) {
        return new TransactionSignature[0][];
    }
}
