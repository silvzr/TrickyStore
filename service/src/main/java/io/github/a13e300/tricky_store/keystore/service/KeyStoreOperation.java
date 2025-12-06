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
import android.hardware.security.keymint.Digest;
import android.system.keystore2.IKeystoreOperation;

import java.security.PrivateKey;
import java.security.Signature;

import io.github.a13e300.tricky_store.Logger;

/**
 * Implementation of IKeystoreOperation for cryptographic operations.
 * 
 * This class handles signing operations using generated or imported keys.
 * It follows the Android Keystore2 IKeystoreOperation interface.
 * 
 * @see <a href="https://developer.android.com/privacy-and-security/keystore#sign-verify">Sign and Verify</a>
 */
public class KeyStoreOperation extends IKeystoreOperation.Stub {
    
    private final Signature signature;
    private final String algorithm;
    private volatile boolean aborted = false;
    
    /**
     * Creates a new signing operation.
     *
     * @param privateKey The private key to use for signing
     * @param algorithm The key algorithm (EC or RSA)
     * @param digest The digest algorithm
     */
    public KeyStoreOperation(PrivateKey privateKey, int algorithm, int digest) {
        this.algorithm = buildSignatureAlgorithm(algorithm, digest);
        
        try {
            Logger.d("KeyStoreOperation: Creating operation with algorithm " + this.algorithm);
            this.signature = Signature.getInstance(this.algorithm);
            this.signature.initSign(privateKey);
        } catch (Exception e) {
            Logger.e("KeyStoreOperation: Failed to initialize signature", e);
            throw new RuntimeException("Failed to initialize signature operation", e);
        }
    }
    
    /**
     * Creates a new signing operation with explicit algorithm name.
     *
     * @param privateKey The private key to use for signing
     * @param algorithmName The full signature algorithm name (e.g., "SHA256withECDSA")
     */
    public KeyStoreOperation(PrivateKey privateKey, String algorithmName) {
        this.algorithm = algorithmName;
        
        try {
            Logger.d("KeyStoreOperation: Creating operation with algorithm " + algorithmName);
            this.signature = Signature.getInstance(algorithmName);
            this.signature.initSign(privateKey);
        } catch (Exception e) {
            Logger.e("KeyStoreOperation: Failed to initialize signature", e);
            throw new RuntimeException("Failed to initialize signature operation", e);
        }
    }
    
    /**
     * Updates AAD (Additional Authenticated Data) - not used for signing.
     */
    @Override
    public void updateAad(byte[] aadInput) {
        // AAD is only used for AEAD operations (AES-GCM), not signing
        Logger.d("KeyStoreOperation: updateAad called (ignored for signing)");
    }
    
    /**
     * Updates the operation with data to be signed.
     *
     * @param input The data to add to the signature
     * @return null for signing operations (output comes from finish)
     */
    @Override
    public byte[] update(byte[] input) {
        checkNotAborted();
        
        if (input == null || input.length == 0) {
            Logger.d("KeyStoreOperation: update called with empty input");
            return null;
        }
        
        try {
            Logger.d("KeyStoreOperation: update called with " + input.length + " bytes");
            signature.update(input);
            return null; // Signing operations don't produce output until finish
        } catch (Exception e) {
            Logger.e("KeyStoreOperation: Failed to update signature", e);
            throw new RuntimeException("Signature update failed", e);
        }
    }
    
    /**
     * Finishes the signing operation.
     *
     * @param input Optional final input data
     * @param existingSignature Existing signature for verification (unused for signing)
     * @return The signature bytes
     */
    @Override
    public byte[] finish(byte[] input, byte[] existingSignature) {
        checkNotAborted();
        
        try {
            // Add any final input
            if (input != null && input.length > 0) {
                Logger.d("KeyStoreOperation: finish called with " + input.length + " bytes");
                signature.update(input);
            }
            
            // Generate signature
            byte[] result = signature.sign();
            Logger.d("KeyStoreOperation: Generated signature of " + result.length + " bytes");
            
            return result;
        } catch (Exception e) {
            Logger.e("KeyStoreOperation: Failed to finish signature", e);
            throw new RuntimeException("Signature finish failed", e);
        }
    }
    
    /**
     * Aborts the operation.
     */
    @Override
    public void abort() {
        Logger.d("KeyStoreOperation: abort called");
        aborted = true;
    }
    
    /**
     * Checks if the operation has been aborted.
     */
    private void checkNotAborted() {
        if (aborted) {
            throw new IllegalStateException("Operation has been aborted");
        }
    }
    
    /**
     * Builds the JCA signature algorithm name from KeyMint constants.
     */
    private static String buildSignatureAlgorithm(int algorithm, int digest) {
        String digestName = getDigestName(digest);
        String algoSuffix = getAlgorithmSuffix(algorithm);
        
        return digestName + "with" + algoSuffix;
    }
    
    /**
     * Gets the digest name for JCA.
     */
    private static String getDigestName(int digest) {
        return switch (digest) {
            case Digest.NONE -> "NONEwith";
            case Digest.MD5 -> "MD5";
            case Digest.SHA1 -> "SHA1";
            case Digest.SHA_2_224 -> "SHA224";
            case Digest.SHA_2_256 -> "SHA256";
            case Digest.SHA_2_384 -> "SHA384";
            case Digest.SHA_2_512 -> "SHA512";
            default -> "SHA256";
        };
    }
    
    /**
     * Gets the algorithm suffix for JCA.
     */
    private static String getAlgorithmSuffix(int algorithm) {
        return switch (algorithm) {
            case Algorithm.EC -> "ECDSA";
            case Algorithm.RSA -> "RSA";
            default -> "ECDSA";
        };
    }
    
    /**
     * Creates an operation for a given key and parameters.
     *
     * @param privateKey The private key
     * @param keyAlgorithm The key algorithm name (e.g., "EC", "RSA")
     * @param digestHint Optional digest hint (uses SHA256 if not specified)
     * @return The operation instance
     */
    public static KeyStoreOperation create(PrivateKey privateKey, String keyAlgorithm, 
            int digestHint) {
        String digestName = getDigestName(digestHint);
        
        String algoSuffix;
        if (keyAlgorithm.contains("EC") || keyAlgorithm.equals("ECDSA")) {
            algoSuffix = "ECDSA";
        } else if (keyAlgorithm.contains("RSA")) {
            algoSuffix = "RSA";
        } else {
            algoSuffix = "ECDSA";
        }
        
        return new KeyStoreOperation(privateKey, digestName + "with" + algoSuffix);
    }
}
