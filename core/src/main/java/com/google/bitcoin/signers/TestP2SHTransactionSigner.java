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
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * This signer tries to sign inputs with keys it has. If key has no private bytes, signers asks mock server
 * to provide signature. Mock server is an instance of https://github.com/troggy/bitcoinj-test-signer running on
 * localhost at port 8080.
 *  //todo: add N of M sigs support where N < M. Currently always creates M sigs
 *  //todo: vend partner's xpub for marriage purposes
 */
public class TestP2SHTransactionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(TestP2SHTransactionSigner.class);

    @Override
    public TransactionSignature[][] signInputs(Transaction tx, Map<TransactionOutput, RedeemData> redeemData) {
        int numInputs = tx.getInputs().size();
        int numSigs = redeemData.values().iterator().next().getKeys().size();
        TransactionSignature[][] signatures = new TransactionSignature[numInputs][numSigs];
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getOutpoint().getConnectedOutput();
            if (!redeemData.containsKey(txOut))
                continue;
            checkArgument(txOut.getScriptPubKey().isPayToScriptHash(), "TestP2SHTransactionSigner works only with P2SH transactions");
            Script redeemScript = redeemData.get(txOut).getRedeemScript();
            Sha256Hash sighash = tx.hashForSignature(i, redeemScript, Transaction.SigHash.ALL, false);
            List<ECKey> keys = redeemData.get(txOut).getKeys();
            for (int j = 0; j < keys.size(); j++) {
                ECKey key = keys.get(j);
                try {
                    signatures[i][j] = new TransactionSignature(key.sign(sighash), Transaction.SigHash.ALL, false);
                } catch (ECKey.KeyIsEncryptedException e) {
                    throw e;
                } catch (ECKey.MissingPrivateKeyException e) {
                    // if key has no private key bytes, we asking signing server to provide signature for it
                    signatures[i][j] = new TransactionSignature(getTheirSignature(sighash, key), Transaction.SigHash.ALL, false);
                }
            }
        }

        return signatures;
    }

    private ECKey.ECDSASignature getTheirSignature(Sha256Hash sighash, ECKey theirKey) {
        try {
            URL url = new URL("http://localhost:8080/signer/sign");

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");

            DataOutputStream writer = new DataOutputStream(connection.getOutputStream());
            writer.writeBytes("sighash=" + URLEncoder.encode(sighash.toString(), "UTF-8")
                    + "&keypath=" + URLEncoder.encode(((DeterministicKey) theirKey).getPathAsString(), "UTF-8"));
            writer.close();

            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream in = connection.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
                byte[] buf = new byte[1024];
                int count;
                while ((count = in.read(buf)) != -1)
                    out.write(buf, 0, count);
                return ECKey.ECDSASignature.decodeFromDER(out.toByteArray());
            } else {
                throw new RuntimeException("Couldn't get their's signature. Server responds with "
                        + connection.getResponseCode() + " " + connection.getResponseMessage());
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
