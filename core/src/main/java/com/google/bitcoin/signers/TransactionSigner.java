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

import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.wallet.KeyBag;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

/**
 * <p>Implementations of this interface provide signatures for given transaction.</p>
 * <p></p>
 */
public interface TransactionSigner {

    /**
     * Returns true if this signer is ready to be used.
     */
    boolean isReady();

    /**
     * Returns byte array of data representing state of this signer
     */
    byte[] serialize();

    /**
     * Signs given transaction's inputs. Signer may locate needed local keys through provided {@link KeyBag}
     */
    void signInputs(Transaction tx, @Nullable KeyParameter aesKey);

}
