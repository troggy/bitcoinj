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
import java.util.HashMap;
import java.util.Map;

/**
 * This signer tries to sign inputs with keys it has. If key has no private bytes, signer asks mock server
 * to provide signature. Mock server is an instance of https://github.com/troggy/bitcoinj-test-signer running on
 * localhost at port 8080.
 */
public class TestP2SHTransactionSigner extends P2SHTransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(TestP2SHTransactionSigner.class);

    public DeterministicKey getPartnerWatchKey() {
        byte[] xpubBytes = new HttpClient().request("GET", "http://localhost:8080/signer/xpub", null);
        DeterministicKey key = DeterministicKey.deserializeB58(null, new String(xpubBytes));
        log.debug("Partner's watch key: {}", key);
        return key;
    }

    @Override
    protected ECKey.ECDSASignature getTheirSignature(Sha256Hash sighash, ECKey theirKey) {
        Map<String, String> params = new HashMap<String, String>();
        params.put("sighash", sighash.toString());
        params.put("keypath", ((DeterministicKey) theirKey).getPathAsString());
        byte[] sig = new HttpClient().request("POST", "http://localhost:8080/signer/sign", params);
        return ECKey.ECDSASignature.decodeFromDER(sig);
    }

    class HttpClient {

        public byte[] request(String method, String urlString, Map<String, String> data) {
            try {
                URL url = new URL(urlString);

                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod(method);

                if (data != null && !data.isEmpty()) {
                    connection.setDoOutput(true);
                    DataOutputStream writer = new DataOutputStream(connection.getOutputStream());
                    StringBuilder payload = new StringBuilder();
                    for (Map.Entry<String, String> param : data.entrySet()) {
                        if (payload.length() > 0)
                            payload.append("&");
                        payload.append(param.getKey()).append("=").append(URLEncoder.encode(param.getValue(), "UTF-8"));
                    }
                    writer.writeBytes(payload.toString());
                    writer.close();
                }

                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
                if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    InputStream in = connection.getInputStream();
                    byte[] buf = new byte[1024];
                    int count;
                    while ((count = in.read(buf)) != -1)
                        out.write(buf, 0, count);
                } else {
                    throw new RuntimeException("Server responds with "
                            + connection.getResponseCode() + " " + connection.getResponseMessage());
                }
                return out.toByteArray();
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
    }
}
