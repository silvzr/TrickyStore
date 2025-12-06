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

package io.github.a13e300.tricky_store;

import android.system.keystore2.KeyEntryResponse;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Cache for storing generated and imported keys.
 * 
 * This class maintains two types of key storage:
 * 1. Imported keys - keyed by UID/PID, naturally dropped when app exits
 * 2. Generated keys - keyed by UID/alias for persistent access
 */
public final class KeyCache {
    
    private static final KeyCache INSTANCE = new KeyCache();
    
    // Imported keys storage
    private final ConcurrentHashMap<Owner, ImportedKeyInfo> importedKeys = new ConcurrentHashMap<>();
    
    // Generated keys storage
    private final ConcurrentHashMap<KeyId, KeyInfo> generatedKeys = new ConcurrentHashMap<>();
    
    private KeyCache() {}
    
    public static KeyCache getInstance() {
        return INSTANCE;
    }
    
    // ==================== Imported Keys ====================
    
    /**
     * Gets an imported key by owner.
     */
    public ImportedKeyInfo getImportedKey(int uid, int pid) {
        return importedKeys.get(new Owner(uid, pid));
    }
    
    /**
     * Pre-imports a key (before certificate is available).
     */
    public void preImportKey(int uid, int pid, PrivateKey privateKey, Runnable onFinish) {
        importedKeys.put(new Owner(uid, pid), 
            new ImportedKeyInfo(privateKey, onFinish, null));
    }
    
    /**
     * Deletes an imported key.
     */
    public void deleteImportedKey(int uid, int pid) {
        importedKeys.remove(new Owner(uid, pid));
    }
    
    /**
     * Finalizes an imported key with its certificate.
     */
    public void finalizeImportedKey(int uid, int pid, Certificate cert) {
        Owner owner = new Owner(uid, pid);
        ImportedKeyInfo info = importedKeys.get(owner);
        if (info == null) return;
        
        importedKeys.put(owner, new ImportedKeyInfo(info.privateKey, info.onFinish, cert));
        
        // Invoke completion callback
        if (info.onFinish != null) {
            info.onFinish.run();
        }
    }
    
    // ==================== Generated Keys ====================
    
    /**
     * Stores a generated key.
     */
    public void putKey(int uid, String alias, KeyPair keyPair, 
            List<Certificate> chain, KeyEntryResponse response) {
        KeyId keyId = new KeyId(uid, alias);
        generatedKeys.put(keyId, new KeyInfo(keyId, keyPair, chain, response));
    }
    
    /**
     * Stores a generated key with existing KeyInfo.
     */
    public void putKey(KeyId keyId, KeyInfo info) {
        generatedKeys.put(keyId, info);
    }
    
    /**
     * Gets key infos by namespace.
     */
    public List<KeyInfo> getInfoByNamespace(int callingUid, long nspace) {
        return generatedKeys.values().stream()
            .filter(info -> info.keyId.uid == callingUid && 
                    info.response != null &&
                    info.response.metadata != null &&
                    info.response.metadata.key != null &&
                    info.response.metadata.key.nspace == nspace)
            .collect(Collectors.toList());
    }
    
    /**
     * Gets a key response by UID and alias.
     */
    public KeyEntryResponse getKeyResponse(int uid, String alias) {
        KeyInfo info = generatedKeys.get(new KeyId(uid, alias));
        return info != null ? info.response : null;
    }
    
    /**
     * Gets a key pair and chain by UID and alias.
     */
    public KeyPairChain getKeyPairChain(int uid, String alias) {
        KeyInfo info = generatedKeys.get(new KeyId(uid, alias));
        return info != null ? new KeyPairChain(info.keyPair, info.chain) : null;
    }
    
    /**
     * Deletes a key by UID and alias.
     */
    public void deleteKey(int uid, String alias) {
        generatedKeys.remove(new KeyId(uid, alias));
    }
    
    /**
     * Deletes a key by KeyId.
     */
    public void deleteKey(KeyId keyId) {
        generatedKeys.remove(keyId);
    }
    
    // ==================== Record Classes ====================
    
    /**
     * Owner identifier for imported keys.
     */
    public record Owner(int uid, int pid) {}
    
    /**
     * Key identifier for generated keys.
     */
    public record KeyId(int uid, String alias) {}
    
    /**
     * Information about an imported key.
     */
    public record ImportedKeyInfo(
        PrivateKey privateKey,
        Runnable onFinish,
        Certificate certificate
    ) {}
    
    /**
     * Information about a generated key.
     */
    public record KeyInfo(
        KeyId keyId,
        KeyPair keyPair,
        List<Certificate> chain,
        KeyEntryResponse response
    ) {}
    
    /**
     * KeyPair and certificate chain tuple.
     */
    public record KeyPairChain(KeyPair keyPair, List<Certificate> chain) {}
}
