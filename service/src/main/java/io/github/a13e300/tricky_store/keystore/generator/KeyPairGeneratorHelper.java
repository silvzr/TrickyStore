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

package io.github.a13e300.tricky_store.keystore.generator;

import android.hardware.security.keymint.Algorithm;
import android.security.keystore.KeyProperties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.keystore.core.KeyGenParameters;

/**
 * Generates cryptographic key pairs using BouncyCastle provider.
 * 
 * Supports:
 * - EC keys with various curves (P-224, P-256, P-384, P-521, Curve25519)
 * - RSA keys with configurable size and public exponent
 * 
 * @see <a href="https://developer.android.com/privacy-and-security/keystore#generate-key">Key Generation</a>
 */
public final class KeyPairGeneratorHelper {
    
    private static final KeyPairGeneratorHelper INSTANCE = new KeyPairGeneratorHelper();
    
    private KeyPairGeneratorHelper() {
        initializeBouncyCastle();
    }
    
    /**
     * @return The singleton instance
     */
    public static KeyPairGeneratorHelper getInstance() {
        return INSTANCE;
    }
    
    /**
     * Initializes BouncyCastle security provider.
     */
    private void initializeBouncyCastle() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Generates a key pair based on the provided parameters.
     *
     * @param params The key generation parameters
     * @return The generated KeyPair, or null on failure
     */
    public KeyPair generateKeyPair(KeyGenParameters params) {
        if (params == null) {
            Logger.e("KeyPairGeneratorHelper: Null parameters");
            return null;
        }
        
        try {
            return switch (params.getAlgorithm()) {
                case Algorithm.EC -> generateEcKeyPair(params);
                case Algorithm.RSA -> generateRsaKeyPair(params);
                default -> {
                    Logger.e("KeyPairGeneratorHelper: Unsupported algorithm " + params.getAlgorithm());
                    yield null;
                }
            };
        } catch (Exception e) {
            Logger.e("KeyPairGeneratorHelper: Failed to generate key pair", e);
            return null;
        }
    }
    
    /**
     * Generates an EC key pair.
     *
     * @param params The key generation parameters
     * @return The generated EC KeyPair
     * @throws Exception if key generation fails
     */
    public KeyPair generateEcKeyPair(KeyGenParameters params) throws Exception {
        String curveName = params.getEcCurveName();
        Logger.d("KeyPairGeneratorHelper: Generating EC key with curve " + curveName);
        
        // Ensure BouncyCastle is properly initialized
        initializeBouncyCastle();
        
        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                "ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        
        return kpg.generateKeyPair();
    }
    
    /**
     * Generates an RSA key pair.
     *
     * @param params The key generation parameters
     * @return The generated RSA KeyPair
     * @throws Exception if key generation fails
     */
    public KeyPair generateRsaKeyPair(KeyGenParameters params) throws Exception {
        int keySize = params.getKeySize();
        if (keySize < 1) keySize = 2048;
        
        Logger.d("KeyPairGeneratorHelper: Generating RSA key with size " + keySize);
        
        // Ensure BouncyCastle is properly initialized
        initializeBouncyCastle();
        
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                keySize, params.getRsaPublicExponent());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                "RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        
        return kpg.generateKeyPair();
    }
    
    /**
     * Gets the algorithm name for a given algorithm constant.
     *
     * @param algorithm The algorithm constant from KeyMint
     * @return The algorithm string name
     */
    public static String getAlgorithmName(int algorithm) {
        return switch (algorithm) {
            case Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC;
            case Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA;
            case Algorithm.AES -> KeyProperties.KEY_ALGORITHM_AES;
            case Algorithm.HMAC -> KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
            case Algorithm.TRIPLE_DES -> "DESede";
            default -> "Unknown";
        };
    }
    
    /**
     * Gets the signature algorithm name for signing operations.
     *
     * @param algorithm The key algorithm constant
     * @param digest The digest algorithm (optional, defaults to SHA256)
     * @return The signature algorithm name (e.g., "SHA256withECDSA")
     */
    public static String getSignatureAlgorithm(int algorithm, int digest) {
        String digestName = getDigestName(digest);
        
        return switch (algorithm) {
            case Algorithm.EC -> digestName + "withECDSA";
            case Algorithm.RSA -> digestName + "withRSA";
            default -> "SHA256withECDSA";
        };
    }
    
    /**
     * Gets the digest algorithm name.
     */
    private static String getDigestName(int digest) {
        return switch (digest) {
            case android.hardware.security.keymint.Digest.MD5 -> "MD5";
            case android.hardware.security.keymint.Digest.SHA1 -> "SHA1";
            case android.hardware.security.keymint.Digest.SHA_2_224 -> "SHA224";
            case android.hardware.security.keymint.Digest.SHA_2_256 -> "SHA256";
            case android.hardware.security.keymint.Digest.SHA_2_384 -> "SHA384";
            case android.hardware.security.keymint.Digest.SHA_2_512 -> "SHA512";
            default -> "SHA256";
        };
    }
}
