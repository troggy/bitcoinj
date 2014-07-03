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

import com.google.bitcoin.script.Script;

import javax.annotation.Nullable;
import java.util.List;

/**
 * SignatureAssembly is an object aggregating essentials to sign transactions.
 *<ul>
 * <li><b>simple tx</b>a single key to sign</li>
 * <li><b>p2sh tx</b>uses a redeemscript to sign</li>
 * <li><b>multi-sig tx</b>uses multiple keys to sign</li>
 *</ul>
 */
public class SigningAssembly {
    @Nullable private Script redeemScript;
    private List<ECKey> keys;

    private SigningAssembly(Script redeemScript, List<ECKey> keys) {
        this.redeemScript = redeemScript;
        this.keys = keys;
    }

    public static SigningAssembly of(Script redeemScript, List<ECKey> keys) {
        return new SigningAssembly(redeemScript, keys);
    }

    @Nullable
    public Script getRedeemScript() {
        return redeemScript;
    }

    public List<ECKey> getKeys() {
        return keys;
    }
}
