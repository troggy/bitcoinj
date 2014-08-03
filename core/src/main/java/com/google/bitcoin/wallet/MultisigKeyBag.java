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
package com.google.bitcoin.wallet;

import com.google.bitcoin.core.ECKey;

import javax.annotation.Nullable;

public interface MultisigKeyBag extends KeyBag {

    /**
     * Locates private key from the keychain given the hash of the script. This is needed when finding out which
     * key we need to use to locally sign a P2SH transaction input. It is assumed that wallet should not have
     * more than one private key for single P2SH tx for security reasons.
     *
     * Returns ECKey object or null if no such key was found.
     */
    @Nullable
    ECKey findPrivateKeyFromScriptHash(byte[] scriptHash);

}
