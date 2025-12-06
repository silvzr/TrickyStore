/*
 * Copyright (C) 2024 TrickyStore
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.a13e300.tricky_store.keystore.core;

import android.security.keystore.KeyProperties;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.TrickyStoreUtils;
import io.github.a13e300.tricky_store.keystore.XMLParser;
import top.qwq2333.ohmykeymint.IOhMyKsService;

/**
 * Manages KeyBox instances loaded from XML configuration.
 * 
 * This class handles:
 * - Parsing keybox XML files
 * - Converting PEM-encoded keys to Java KeyPair
 * - Storing keyboxes by algorithm type
 * - Synchronizing with OhMyKeyMint service
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/attestation#attestation-keys">Attestation Keys</a>
 */
public final class KeyBoxManager {
    
    private static final KeyBoxManager INSTANCE = new KeyBoxManager();
    
    private final Map<String, KeyBox> keyboxes = new HashMap<>();
    private final CertificateFactory certificateFactory;
    
    private KeyBoxManager() {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CertificateFactory", e);
        }
    }
    
    /**
     * @return The singleton instance
     */
    public static KeyBoxManager getInstance() {
        return INSTANCE;
    }
    
    /**
     * Checks if any keyboxes are loaded.
     * @return true if at least one keybox is available
     */
    public boolean hasKeyboxes() {
        return !keyboxes.isEmpty();
    }
    
    /**
     * Gets the keybox for a specific algorithm.
     * @param algorithm The algorithm (EC or RSA)
     * @return The KeyBox or null if not found
     */
    public KeyBox getKeyBox(String algorithm) {
        return keyboxes.get(algorithm);
    }
    
    /**
     * Gets the EC keybox.
     * @return The EC KeyBox or null
     */
    public KeyBox getEcKeyBox() {
        return keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
    }
    
    /**
     * Gets the RSA keybox.
     * @return The RSA KeyBox or null
     */
    public KeyBox getRsaKeyBox() {
        return keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
    }
    
    /**
     * Clears all loaded keyboxes.
     */
    public void clearKeyboxes() {
        keyboxes.clear();
        Logger.i("KeyBoxManager: Cleared all keyboxes");
    }
    
    /**
     * Loads keyboxes from XML configuration data.
     *
     * @param xmlData The XML configuration string, or null to clear
     * @param ohMyKsService Optional OhMyKeyMint service to synchronize with
     */
    public void loadFromXml(String xmlData, IOhMyKsService ohMyKsService) {
        keyboxes.clear();
        
        if (xmlData == null || xmlData.isEmpty()) {
            Logger.i("KeyBoxManager: No XML data, keyboxes cleared");
            return;
        }
        
        try {
            XMLParser xmlParser = new XMLParser(xmlData);
            
            int numberOfKeyboxes = Integer.parseInt(
                    Objects.requireNonNull(xmlParser.obtainPath(
                            "AndroidAttestation.NumberOfKeyboxes").get("text")));
            
            for (int i = 0; i < numberOfKeyboxes; i++) {
                loadKeybox(xmlParser, i, ohMyKsService);
            }
            
            Logger.i("KeyBoxManager: Loaded " + numberOfKeyboxes + " keyboxes");
            
        } catch (Exception e) {
            Logger.e("KeyBoxManager: Failed to load XML", e);
            keyboxes.clear();
        }
    }
    
    /**
     * Loads a single keybox from the XML parser.
     */
    private void loadKeybox(XMLParser xmlParser, int index, IOhMyKsService ohMyKsService) {
        try {
            String keyboxAlgorithm = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[" + index + "]").get("algorithm");
                    
            String privateKeyPem = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[" + index + "].PrivateKey").get("text");
                    
            int numberOfCertificates = Integer.parseInt(
                    Objects.requireNonNull(xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + index + "].CertificateChain.NumberOfCertificates").get("text")));
            
            // Load certificate chain
            LinkedList<Certificate> certificateChain = new LinkedList<>();
            for (int j = 0; j < numberOfCertificates; j++) {
                Map<String, String> certData = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + index + "].CertificateChain.Certificate[" + j + "]");
                certificateChain.add(parseCertificate(certData.get("text")));
            }
            
            // Parse key pair
            PEMKeyPair pemKeyPair = parseKeyPair(privateKeyPem);
            KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
            
            // Determine algorithm
            String algorithm = keyboxAlgorithm.equalsIgnoreCase("ecdsa") 
                    ? KeyProperties.KEY_ALGORITHM_EC 
                    : KeyProperties.KEY_ALGORITHM_RSA;
            
            // Store keybox
            KeyBox keyBox = new KeyBox(pemKeyPair, keyPair, certificateChain, algorithm);
            keyboxes.put(algorithm, keyBox);
            
            Logger.i("KeyBoxManager: Loaded " + algorithm + " keybox with " + numberOfCertificates + " certificates");
            
            // Sync with OhMyKeyMint if available
            if (ohMyKsService != null) {
                syncWithOhMyKeyMint(ohMyKsService, keyboxAlgorithm, privateKeyPem, 
                        xmlParser, index, numberOfCertificates);
            }
            
        } catch (Exception e) {
            Logger.e("KeyBoxManager: Failed to load keybox at index " + index, e);
        }
    }
    
    /**
     * Synchronizes loaded keybox with OhMyKeyMint service.
     */
    private void syncWithOhMyKeyMint(IOhMyKsService ohMyKsService, String algorithm,
            String privateKeyPem, XMLParser xmlParser, int index, int numberOfCertificates) {
        try {
            List<android.hardware.security.keymint.Certificate> certList = new java.util.ArrayList<>();
            
            for (int j = 0; j < numberOfCertificates; j++) {
                Map<String, String> certData = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + index + "].CertificateChain.Certificate[" + j + "]");
                        
                android.hardware.security.keymint.Certificate cert = 
                        new android.hardware.security.keymint.Certificate();
                cert.encodedCertificate = Base64.getDecoder().decode(
                        TrickyStoreUtils.parsePemToBase64(certData.get("text")));
                certList.add(cert);
            }
            
            byte[] keyBytes = Base64.getDecoder().decode(
                    TrickyStoreUtils.parsePemToBase64(privateKeyPem));
            
            if (algorithm.equalsIgnoreCase("ecdsa")) {
                ohMyKsService.updateEcKeybox(keyBytes, certList);
            } else if (algorithm.equalsIgnoreCase("rsa")) {
                ohMyKsService.updateRsaKeybox(keyBytes, certList);
            }
            
            Logger.d("KeyBoxManager: Synced " + algorithm + " keybox with OhMyKeyMint");
            
        } catch (Exception e) {
            Logger.e("KeyBoxManager: Failed to sync with OhMyKeyMint", e);
        }
    }
    
    /**
     * Parses a PEM-encoded key pair.
     */
    private PEMKeyPair parseKeyPair(String keyPem) throws Exception {
        try (PEMParser parser = new PEMParser(
                new StringReader(TrickyStoreUtils.trimLine(keyPem)))) {
            return (PEMKeyPair) parser.readObject();
        }
    }
    
    /**
     * Parses a PEM-encoded certificate.
     */
    private Certificate parseCertificate(String certPem) throws Exception {
        try (PemReader reader = new PemReader(
                new StringReader(TrickyStoreUtils.trimLine(certPem)))) {
            return certificateFactory.generateCertificate(
                    new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }
}
