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

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.Digest;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.PaddingMode;
import android.hardware.security.keymint.Tag;
import android.security.keymaster.KeymasterDefs;

import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import io.github.a13e300.tricky_store.Logger;

/**
 * Encapsulates key generation parameters following Android KeyMint/Keymaster specifications.
 * 
 * This class translates between Android's KeyParameter tags and the actual cryptographic
 * parameters needed for key generation and certificate creation.
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/tags">Authorization Tags</a>
 */
public final class KeyGenParameters {
    
    // Algorithm parameters
    private int algorithm = Algorithm.EC;
    private int keySize = 256;
    
    // EC-specific parameters
    private int ecCurve = EcCurve.P_256;
    private String ecCurveName = "secp256r1";
    
    // RSA-specific parameters
    private BigInteger rsaPublicExponent = BigInteger.valueOf(65537L);
    
    // Certificate parameters
    private BigInteger certificateSerial;
    private Date certificateNotBefore;
    private Date certificateNotAfter;
    private X500Name certificateSubject;
    
    // Key purposes and authorizations
    private final List<Integer> purposes = new ArrayList<>();
    private final List<Integer> digests = new ArrayList<>();
    private final List<Integer> paddingModes = new ArrayList<>();
    
    // Attestation parameters
    private byte[] attestationChallenge;
    private byte[] attestationApplicationId;
    
    // ID attestation parameters
    private byte[] attestationIdBrand;
    private byte[] attestationIdDevice;
    private byte[] attestationIdProduct;
    private byte[] attestationIdManufacturer;
    private byte[] attestationIdModel;
    private byte[] attestationIdSerial;
    private byte[] attestationIdImei;
    private byte[] attestationIdSecondImei;
    private byte[] attestationIdMeid;
    
    // Security settings
    private boolean noAuthRequired = true;
    private boolean rollbackResistance = false;
    private boolean earlyBootOnly = false;
    private boolean deviceUniqueAttestation = false;
    private int origin = 0; // Generated
    
    /**
     * Default constructor with sensible defaults for EC P-256 keys.
     */
    public KeyGenParameters() {
        this.certificateNotBefore = new Date();
        this.certificateNotAfter = new Date(System.currentTimeMillis() + 25L * 365 * 24 * 3600 * 1000);
        this.certificateSerial = BigInteger.valueOf(System.currentTimeMillis());
        this.certificateSubject = new X500Name("CN=Android Keystore Key");
    }
    
    /**
     * Constructs KeyGenParameters from KeyMint KeyParameter array.
     * This parses the Android KeyMint tag format.
     *
     * @param params Array of KeyParameter from KeyMint/Keystore2
     */
    public KeyGenParameters(KeyParameter[] params) {
        this();
        if (params == null) return;
        
        for (KeyParameter kp : params) {
            parseKeyParameter(kp);
        }
        
        // Set EC curve name based on curve value
        updateEcCurveName();
    }
    
    /**
     * Parses a single KeyParameter and updates internal state.
     */
    private void parseKeyParameter(KeyParameter kp) {
        if (kp == null || kp.value == null) return;
        
        try {
            switch (kp.tag) {
                case Tag.ALGORITHM:
                    algorithm = kp.value.getAlgorithm();
                    break;
                    
                case Tag.KEY_SIZE:
                    keySize = kp.value.getInteger();
                    break;
                    
                case Tag.EC_CURVE:
                    ecCurve = kp.value.getEcCurve();
                    updateEcCurveName();
                    break;
                    
                case Tag.RSA_PUBLIC_EXPONENT:
                    rsaPublicExponent = BigInteger.valueOf(kp.value.getLongInteger());
                    break;
                    
                case Tag.CERTIFICATE_SERIAL:
                    certificateSerial = new BigInteger(kp.value.getBlob());
                    break;
                    
                case Tag.CERTIFICATE_NOT_BEFORE:
                    certificateNotBefore = new Date(kp.value.getDateTime());
                    break;
                    
                case Tag.CERTIFICATE_NOT_AFTER:
                    certificateNotAfter = new Date(kp.value.getDateTime());
                    break;
                    
                case Tag.CERTIFICATE_SUBJECT:
                    certificateSubject = new X500Name(
                            new X500Principal(kp.value.getBlob()).getName());
                    break;
                    
                case Tag.PURPOSE:
                    purposes.add(kp.value.getKeyPurpose());
                    break;
                    
                case Tag.DIGEST:
                    digests.add(kp.value.getDigest());
                    break;
                    
                case Tag.PADDING:
                    paddingModes.add(kp.value.getPaddingMode());
                    break;
                    
                case Tag.NO_AUTH_REQUIRED:
                    noAuthRequired = true;
                    break;
                    
                case Tag.ROLLBACK_RESISTANCE:
                    rollbackResistance = true;
                    break;
                    
                case Tag.EARLY_BOOT_ONLY:
                    earlyBootOnly = true;
                    break;
                    
                case Tag.DEVICE_UNIQUE_ATTESTATION:
                    deviceUniqueAttestation = true;
                    break;
                    
                case Tag.ATTESTATION_CHALLENGE:
                    attestationChallenge = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_APPLICATION_ID:
                    attestationApplicationId = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_BRAND:
                    attestationIdBrand = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_DEVICE:
                    attestationIdDevice = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_PRODUCT:
                    attestationIdProduct = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_MANUFACTURER:
                    attestationIdManufacturer = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_MODEL:
                    attestationIdModel = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_SERIAL:
                    attestationIdSerial = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_IMEI:
                    attestationIdImei = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_SECOND_IMEI:
                    attestationIdSecondImei = kp.value.getBlob();
                    break;
                    
                case Tag.ATTESTATION_ID_MEID:
                    attestationIdMeid = kp.value.getBlob();
                    break;
                    
                default:
                    Logger.d("KeyGenParameters: Unhandled tag " + kp.tag);
            }
        } catch (Exception e) {
            Logger.e("KeyGenParameters: Error parsing tag " + kp.tag, e);
        }
    }
    
    /**
     * Updates EC curve name based on curve constant.
     */
    private void updateEcCurveName() {
        ecCurveName = getEcCurveNameFromConstant(ecCurve);
    }
    
    /**
     * Maps EC curve constant to OpenSSL curve name.
     */
    private static String getEcCurveNameFromConstant(int curve) {
        return switch (curve) {
            case EcCurve.P_224 -> "secp224r1";
            case EcCurve.P_256 -> "secp256r1";
            case EcCurve.P_384 -> "secp384r1";
            case EcCurve.P_521 -> "secp521r1";
            case EcCurve.CURVE_25519 -> "curve25519";
            default -> "secp256r1";
        };
    }
    
    /**
     * Sets EC curve name based on key size for legacy Keymaster 1.0 support.
     */
    public void setEcCurveFromKeySize(int keySize) {
        this.keySize = keySize;
        this.ecCurveName = switch (keySize) {
            case 224 -> "secp224r1";
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> "secp256r1";
        };
        this.ecCurve = switch (keySize) {
            case 224 -> EcCurve.P_224;
            case 256 -> EcCurve.P_256;
            case 384 -> EcCurve.P_384;
            case 521 -> EcCurve.P_521;
            default -> EcCurve.P_256;
        };
    }
    
    /**
     * Checks if this key is for signing purposes.
     */
    public boolean isSigningKey() {
        return purposes.contains(KeyPurpose.SIGN) || 
               purposes.contains(KeyPurpose.ATTEST_KEY);
    }
    
    /**
     * Checks if attestation is requested.
     */
    public boolean hasAttestationChallenge() {
        return attestationChallenge != null && attestationChallenge.length > 0;
    }
    
    /**
     * Checks if ID attestation is requested.
     */
    public boolean hasIdAttestation() {
        return attestationIdBrand != null || attestationIdDevice != null ||
               attestationIdProduct != null || attestationIdManufacturer != null ||
               attestationIdModel != null || attestationIdSerial != null ||
               attestationIdImei != null || attestationIdMeid != null;
    }
    
    // Getters
    public int getAlgorithm() { return algorithm; }
    public int getKeySize() { return keySize; }
    public int getEcCurve() { return ecCurve; }
    public String getEcCurveName() { return ecCurveName; }
    public BigInteger getRsaPublicExponent() { return rsaPublicExponent; }
    public BigInteger getCertificateSerial() { return certificateSerial; }
    public Date getCertificateNotBefore() { return certificateNotBefore; }
    public Date getCertificateNotAfter() { return certificateNotAfter; }
    public X500Name getCertificateSubject() { return certificateSubject; }
    public List<Integer> getPurposes() { return purposes; }
    public List<Integer> getDigests() { return digests; }
    public List<Integer> getPaddingModes() { return paddingModes; }
    public byte[] getAttestationChallenge() { return attestationChallenge; }
    public byte[] getAttestationApplicationId() { return attestationApplicationId; }
    public byte[] getAttestationIdBrand() { return attestationIdBrand; }
    public byte[] getAttestationIdDevice() { return attestationIdDevice; }
    public byte[] getAttestationIdProduct() { return attestationIdProduct; }
    public byte[] getAttestationIdManufacturer() { return attestationIdManufacturer; }
    public byte[] getAttestationIdModel() { return attestationIdModel; }
    public byte[] getAttestationIdSerial() { return attestationIdSerial; }
    public byte[] getAttestationIdImei() { return attestationIdImei; }
    public byte[] getAttestationIdSecondImei() { return attestationIdSecondImei; }
    public byte[] getAttestationIdMeid() { return attestationIdMeid; }
    public boolean isNoAuthRequired() { return noAuthRequired; }
    public boolean isRollbackResistance() { return rollbackResistance; }
    public boolean isEarlyBootOnly() { return earlyBootOnly; }
    public boolean isDeviceUniqueAttestation() { return deviceUniqueAttestation; }
    public int getOrigin() { return origin; }
    
    // Setters for legacy support
    public void setAlgorithm(int algorithm) { this.algorithm = algorithm; }
    public void setKeySize(int keySize) { this.keySize = keySize; }
    public void setEcCurve(int ecCurve) { this.ecCurve = ecCurve; updateEcCurveName(); }
    public void setRsaPublicExponent(BigInteger exp) { this.rsaPublicExponent = exp; }
    public void setCertificateNotBefore(Date date) { this.certificateNotBefore = date; }
    public void setCertificateNotAfter(Date date) { this.certificateNotAfter = date; }
    public void setCertificateSubject(X500Name subject) { this.certificateSubject = subject; }
    public void setAttestationChallenge(byte[] challenge) { this.attestationChallenge = challenge; }
    
    public void addPurpose(int purpose) { 
        if (!purposes.contains(purpose)) purposes.add(purpose); 
    }
    
    public void addDigest(int digest) { 
        if (!digests.contains(digest)) digests.add(digest); 
    }
}
