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
 * <p>This class aggregates data required to spend transaction output.</p>
 *
 * <p>Depending on type of output script it could contain:</p>
 *<ul>
 * <li><b>pay-to-address or pay-to-pubkey tx</b> - a single key used to sign, no redeem script</li>
 * <li><b>P2SH tx</b> - multiple keys and redeem script</li>
 * <li><b>Multisig tx</b> - multiple keys, no redeem script</li>
 *</ul>
 */
public class RedeemData {
    @Nullable private Script redeemScript;
    private List<ECKey> keys;

    private RedeemData(Script redeemScript, List<ECKey> keys) {
        this.redeemScript = redeemScript;
        this.keys = keys;
    }

    public static RedeemData of(Script redeemScript, List<ECKey> keys) {
        return new RedeemData(redeemScript, keys);
    }

    @Nullable
    public Script getRedeemScript() {
        return redeemScript;
    }

    public List<ECKey> getKeys() {
        return keys;
    }
}
