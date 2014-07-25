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

import java.util.Map;

/**
 * <p>Implementations of this interface provide signatures for given transaction.</p>
 * <p></p>
 */
public interface TransactionSigner {

    /**
     * Returns array of signatures for given transaction's inputs. Resulting array is made two-dimensional (array of tuples)
     * to facilitate signing of P2SH inputs.
     */
    TransactionSignature[][] signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData);
}
