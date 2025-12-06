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

package io.github.a13e300.tricky_store.keystore.service;

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.Tag;
import android.system.keystore2.Authorization;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.keystore.attestation.AttestationCertificateGenerator;
import io.github.a13e300.tricky_store.keystore.core.KeyBoxManager;
import io.github.a13e300.tricky_store.keystore.core.KeyGenParameters;
import io.github.a13e300.tricky_store.keystore.generator.KeyPairGeneratorHelper;

/**
 * Main service class for simulating Android KeyStore operations.
 * 
 * This class orchestrates:
 * - Key generation with proper attestation
 * - Key storage and retrieval
 * - Certificate chain management
 * 
 * It follows the Android Keystore2 IKeystoreSecurityLevel interface semantics.
 * 
 * @see <a href="https://developer.android.com/privacy-and-security/keystore">Android Keystore System</a>
 */
public final class KeyStoreService {
    
    private static final KeyStoreService INSTANCE = new KeyStoreService();
    
    private final KeyPairGeneratorHelper keyPairGenerator;
    private final AttestationCertificateGenerator attestationGenerator;
    private final KeyBoxManager keyBoxManager;
    
    // Key storage
    private final ConcurrentHashMap<KeyId, KeyInfo> generatedKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<ImportKey, ImportedKeyInfo> importedKeys = new ConcurrentHashMap<>();
    
    private KeyStoreService() {
        this.keyPairGenerator = KeyPairGeneratorHelper.getInstance();
        this.attestationGenerator = AttestationCertificateGenerator.getInstance();
        this.keyBoxManager = KeyBoxManager.getInstance();
    }
    
    /**
     * @return The singleton instance
     */
    public static KeyStoreService getInstance() {
        return INSTANCE;
    }
    
    /**
     * Checks if the service is properly initialized with keyboxes.
     * @return true if keyboxes are loaded
     */
    public boolean isAvailable() {
        return keyBoxManager.hasKeyboxes();
    }
    
    /**
     * Generates a new key pair and returns the key metadata.
     *
     * @param callingUid The calling application's UID
     * @param descriptor The key descriptor specifying alias and namespace
     * @param attestationKeyDescriptor Optional attestation key descriptor
     * @param params The key generation parameters
     * @param securityLevel The target security level
     * @return The key metadata including certificate chain
     */
    public KeyMetadata generateKey(
            int callingUid,
            KeyDescriptor descriptor,
            KeyDescriptor attestationKeyDescriptor,
            KeyParameter[] params,
            int securityLevel) {
        
        if (!isAvailable()) {
            Logger.e("KeyStoreService: No keyboxes available");
            return null;
        }
        
        try {
            // Parse parameters
            KeyGenParameters keyGenParams = new KeyGenParameters(params);
            
            // Generate key pair
            KeyPair keyPair = keyPairGenerator.generateKeyPair(keyGenParams);
            if (keyPair == null) {
                Logger.e("KeyStoreService: Failed to generate key pair");
                return null;
            }
            
            // Generate certificate chain with attestation
            List<Certificate> chain = attestationGenerator.generateCertificateChain(
                    keyPair, keyGenParams, callingUid);
            if (chain == null || chain.isEmpty()) {
                Logger.e("KeyStoreService: Failed to generate certificate chain");
                return null;
            }
            
            // Build key entry response
            KeyEntryResponse response = buildKeyEntryResponse(
                    descriptor, chain, keyGenParams, securityLevel);
            
            // Store the key
            KeyId keyId = new KeyId(callingUid, descriptor.alias);
            KeyInfo keyInfo = new KeyInfo(keyId, keyPair, chain, response);
            generatedKeys.put(keyId, keyInfo);
            
            Logger.i("KeyStoreService: Generated key for UID=" + callingUid + 
                    " alias=" + descriptor.alias);
            
            return response.metadata;
            
        } catch (Exception e) {
            Logger.e("KeyStoreService: Failed to generate key", e);
            return null;
        }
    }
    
    /**
     * Gets a previously generated key.
     *
     * @param callingUid The calling UID
     * @param alias The key alias
     * @return The key entry response or null
     */
    public KeyEntryResponse getKey(int callingUid, String alias) {
        KeyId keyId = new KeyId(callingUid, alias);
        KeyInfo keyInfo = generatedKeys.get(keyId);
        return keyInfo != null ? keyInfo.response() : null;
    }
    
    /**
     * Gets key info for creating operations.
     *
     * @param callingUid The calling UID
     * @param nspace The namespace ID
     * @return List of matching key infos
     */
    public List<KeyInfo> getKeysByNamespace(int callingUid, long nspace) {
        return generatedKeys.values().stream()
                .filter(k -> k.keyId.uid == callingUid && 
                        k.response.metadata != null &&
                        k.response.metadata.key != null &&
                        k.response.metadata.key.nspace == nspace)
                .toList();
    }
    
    /**
     * Deletes a generated key.
     *
     * @param callingUid The calling UID
     * @param alias The key alias
     */
    public void deleteKey(int callingUid, String alias) {
        KeyId keyId = new KeyId(callingUid, alias);
        generatedKeys.remove(keyId);
        Logger.d("KeyStoreService: Deleted key UID=" + callingUid + " alias=" + alias);
    }
    
    /**
     * Prepares for key import by storing the private key.
     *
     * @param callingUid The calling UID
     * @param callingPid The calling PID
     * @param privateKey The private key being imported
     * @param onComplete Callback when import is finalized
     */
    public void prepareImport(int callingUid, int callingPid, 
            PrivateKey privateKey, Runnable onComplete) {
        ImportKey key = new ImportKey(callingUid, callingPid);
        importedKeys.put(key, new ImportedKeyInfo(privateKey, null, onComplete));
    }
    
    /**
     * Finalizes key import with certificate.
     *
     * @param callingUid The calling UID
     * @param callingPid The calling PID
     * @param certificate The public certificate
     */
    public void finalizeImport(int callingUid, int callingPid, Certificate certificate) {
        ImportKey key = new ImportKey(callingUid, callingPid);
        ImportedKeyInfo info = importedKeys.get(key);
        if (info != null) {
            importedKeys.put(key, new ImportedKeyInfo(info.privateKey, certificate, info.onComplete));
            if (info.onComplete != null) {
                info.onComplete.run();
            }
        }
    }
    
    /**
     * Gets imported key info.
     */
    public ImportedKeyInfo getImportedKey(int callingUid, int callingPid) {
        return importedKeys.get(new ImportKey(callingUid, callingPid));
    }
    
    /**
     * Deletes imported key info.
     */
    public void deleteImportedKey(int callingUid, int callingPid) {
        importedKeys.remove(new ImportKey(callingUid, callingPid));
    }
    
    /**
     * Builds a KeyEntryResponse from generated key data.
     */
    private KeyEntryResponse buildKeyEntryResponse(
            KeyDescriptor descriptor,
            List<Certificate> chain,
            KeyGenParameters params,
            int securityLevel) throws Exception {
        
        KeyEntryResponse response = new KeyEntryResponse();
        KeyMetadata metadata = new KeyMetadata();
        
        // Set security level
        metadata.keySecurityLevel = securityLevel;
        
        // Set key descriptor
        KeyDescriptor keyDesc = new KeyDescriptor();
        keyDesc.domain = descriptor.domain;
        keyDesc.nspace = descriptor.nspace;
        keyDesc.alias = descriptor.alias;
        metadata.key = keyDesc;
        
        // Set certificate and chain
        if (!chain.isEmpty()) {
            metadata.certificate = chain.get(0).getEncoded();
            
            if (chain.size() > 1) {
                java.io.ByteArrayOutputStream chainOutput = new java.io.ByteArrayOutputStream();
                for (int i = 1; i < chain.size(); i++) {
                    chainOutput.write(chain.get(i).getEncoded());
                }
                metadata.certificateChain = chainOutput.toByteArray();
            }
        }
        
        // Build authorizations
        metadata.authorizations = buildAuthorizations(params, securityLevel);
        
        response.metadata = metadata;
        return response;
    }
    
    /**
     * Builds authorization array from parameters.
     */
    private Authorization[] buildAuthorizations(KeyGenParameters params, int securityLevel) {
        java.util.ArrayList<Authorization> auths = new java.util.ArrayList<>();
        
        // Purposes
        for (int purpose : params.getPurposes()) {
            Authorization auth = new Authorization();
            auth.securityLevel = securityLevel;
            auth.keyParameter = new KeyParameter();
            auth.keyParameter.tag = Tag.PURPOSE;
            auth.keyParameter.value = KeyParameterValue.keyPurpose(purpose);
            auths.add(auth);
        }
        
        // Digests
        for (int digest : params.getDigests()) {
            Authorization auth = new Authorization();
            auth.securityLevel = securityLevel;
            auth.keyParameter = new KeyParameter();
            auth.keyParameter.tag = Tag.DIGEST;
            auth.keyParameter.value = KeyParameterValue.digest(digest);
            auths.add(auth);
        }
        
        // Algorithm
        Authorization algoAuth = new Authorization();
        algoAuth.securityLevel = securityLevel;
        algoAuth.keyParameter = new KeyParameter();
        algoAuth.keyParameter.tag = Tag.ALGORITHM;
        algoAuth.keyParameter.value = KeyParameterValue.algorithm(params.getAlgorithm());
        auths.add(algoAuth);
        
        // Key size
        Authorization sizeAuth = new Authorization();
        sizeAuth.securityLevel = securityLevel;
        sizeAuth.keyParameter = new KeyParameter();
        sizeAuth.keyParameter.tag = Tag.KEY_SIZE;
        sizeAuth.keyParameter.value = KeyParameterValue.integer(params.getKeySize());
        auths.add(sizeAuth);
        
        // EC Curve for EC keys
        if (params.getAlgorithm() == Algorithm.EC) {
            Authorization curveAuth = new Authorization();
            curveAuth.securityLevel = securityLevel;
            curveAuth.keyParameter = new KeyParameter();
            curveAuth.keyParameter.tag = Tag.EC_CURVE;
            curveAuth.keyParameter.value = KeyParameterValue.ecCurve(params.getEcCurve());
            auths.add(curveAuth);
        }
        
        // No auth required
        if (params.isNoAuthRequired()) {
            Authorization noAuthAuth = new Authorization();
            noAuthAuth.securityLevel = securityLevel;
            noAuthAuth.keyParameter = new KeyParameter();
            noAuthAuth.keyParameter.tag = Tag.NO_AUTH_REQUIRED;
            noAuthAuth.keyParameter.value = KeyParameterValue.boolValue(true);
            auths.add(noAuthAuth);
        }
        
        return auths.toArray(new Authorization[0]);
    }
    
    // Record classes for key identification
    
    public record KeyId(int uid, String alias) {}
    
    public record KeyInfo(KeyId keyId, KeyPair keyPair, List<Certificate> chain, 
            KeyEntryResponse response) {}
    
    public record ImportKey(int uid, int pid) {}
    
    public record ImportedKeyInfo(PrivateKey privateKey, Certificate certificate, 
            Runnable onComplete) {}
}
