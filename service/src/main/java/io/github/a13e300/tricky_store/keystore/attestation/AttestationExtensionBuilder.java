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

package io.github.a13e300.tricky_store.keystore.attestation;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.TrickyStoreUtils;
import io.github.a13e300.tricky_store.keystore.core.KeyGenParameters;

/**
 * Builds the ASN.1 attestation extension for key attestation certificates.
 * 
 * The attestation extension follows the schema defined at:
 * https://source.android.com/docs/security/features/keystore/attestation#schema
 * 
 * KeyDescription ::= SEQUENCE {
 *     attestationVersion         INTEGER,
 *     attestationSecurityLevel   SecurityLevel,
 *     keyMintVersion             INTEGER,
 *     keyMintSecurityLevel       SecurityLevel,
 *     attestationChallenge       OCTET_STRING,
 *     uniqueId                   OCTET_STRING,
 *     softwareEnforced           AuthorizationList,
 *     hardwareEnforced           AuthorizationList,
 * }
 */
public final class AttestationExtensionBuilder {
    
    private final KeyGenParameters params;
    private final int callingUid;
    
    // Attestation version and security level
    private int attestationVersion = AttestationTags.ATTESTATION_VERSION_KEYMINT_4;
    private int attestationSecurityLevel = AttestationTags.SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    private int keyMintVersion = AttestationTags.ATTESTATION_VERSION_KEYMINT_4;
    private int keyMintSecurityLevel = AttestationTags.SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    
    /**
     * Creates a new attestation extension builder.
     *
     * @param params The key generation parameters
     * @param callingUid The UID of the calling application
     */
    public AttestationExtensionBuilder(KeyGenParameters params, int callingUid) {
        this.params = params;
        this.callingUid = callingUid;
    }
    
    /**
     * Sets the attestation version.
     */
    public AttestationExtensionBuilder setAttestationVersion(int version) {
        this.attestationVersion = version;
        return this;
    }
    
    /**
     * Sets the security levels for attestation.
     */
    public AttestationExtensionBuilder setSecurityLevel(int securityLevel) {
        this.attestationSecurityLevel = securityLevel;
        this.keyMintSecurityLevel = securityLevel;
        return this;
    }
    
    /**
     * Builds the attestation extension.
     *
     * @return The X.509 Extension containing attestation data
     */
    public Extension build() {
        try {
            ASN1Encodable[] softwareEnforced = buildSoftwareEnforcedList();
            ASN1Encodable[] hardwareEnforced = buildHardwareEnforcedList();
            
            ASN1OctetString keyDescription = buildKeyDescription(
                    softwareEnforced, hardwareEnforced);
            
            return new Extension(
                    new ASN1ObjectIdentifier(AttestationTags.ATTESTATION_OID),
                    false,
                    keyDescription);
                    
        } catch (Exception e) {
            Logger.e("AttestationExtensionBuilder: Failed to build extension", e);
            return null;
        }
    }
    
    /**
     * Builds the software-enforced authorization list.
     */
    private ASN1Encodable[] buildSoftwareEnforcedList() throws Exception {
        List<ASN1Encodable> encodables = new ArrayList<>();
        
        // Attestation Application ID
        byte[] applicationId = buildAttestationApplicationId();
        if (applicationId != null) {
            encodables.add(new DERTaggedObject(true, 
                    AttestationTags.ATTESTATION_APPLICATION_ID, 
                    new DEROctetString(applicationId)));
        }
        
        // Creation DateTime
        encodables.add(new DERTaggedObject(true, 
                AttestationTags.CREATION_DATE_TIME, 
                new ASN1Integer(System.currentTimeMillis())));
        
        return encodables.toArray(new ASN1Encodable[0]);
    }
    
    /**
     * Builds the hardware-enforced authorization list.
     */
    private ASN1Encodable[] buildHardwareEnforcedList() {
        List<ASN1TaggedEntry> entries = new ArrayList<>();
        
        // Purpose
        if (!params.getPurposes().isEmpty()) {
            entries.add(new ASN1TaggedEntry(AttestationTags.PURPOSE, 
                    new DERSet(toIntegerArray(params.getPurposes()))));
        }
        
        // Algorithm
        entries.add(new ASN1TaggedEntry(AttestationTags.ALGORITHM, 
                new ASN1Integer(params.getAlgorithm())));
        
        // Key size
        entries.add(new ASN1TaggedEntry(AttestationTags.KEY_SIZE, 
                new ASN1Integer(params.getKeySize())));
        
        // Digest
        if (!params.getDigests().isEmpty()) {
            entries.add(new ASN1TaggedEntry(AttestationTags.DIGEST, 
                    new DERSet(toIntegerArray(params.getDigests()))));
        }
        
        // EC Curve (for EC keys)
        if (params.getAlgorithm() == android.hardware.security.keymint.Algorithm.EC) {
            entries.add(new ASN1TaggedEntry(AttestationTags.EC_CURVE, 
                    new ASN1Integer(params.getEcCurve())));
        }
        
        // RSA public exponent (for RSA keys)
        if (params.getAlgorithm() == android.hardware.security.keymint.Algorithm.RSA) {
            entries.add(new ASN1TaggedEntry(AttestationTags.RSA_PUBLIC_EXPONENT, 
                    new ASN1Integer(params.getRsaPublicExponent())));
        }
        
        // No auth required
        if (params.isNoAuthRequired()) {
            entries.add(new ASN1TaggedEntry(AttestationTags.NO_AUTH_REQUIRED, 
                    DERNull.INSTANCE));
        }
        
        // Origin
        entries.add(new ASN1TaggedEntry(AttestationTags.ORIGIN, 
                new ASN1Integer(params.getOrigin())));
        
        // Root of Trust
        ASN1Sequence rootOfTrust = buildRootOfTrust();
        entries.add(new ASN1TaggedEntry(AttestationTags.ROOT_OF_TRUST, rootOfTrust));
        
        // OS Version
        entries.add(new ASN1TaggedEntry(AttestationTags.OS_VERSION, 
                new ASN1Integer(TrickyStoreUtils.getOsVersion())));
        
        // OS Patch Level
        entries.add(new ASN1TaggedEntry(AttestationTags.OS_PATCH_LEVEL, 
                new ASN1Integer(TrickyStoreUtils.getPatchLevel())));
        
        // Vendor Patch Level
        entries.add(new ASN1TaggedEntry(AttestationTags.VENDOR_PATCH_LEVEL, 
                new ASN1Integer(TrickyStoreUtils.getPatchLevelLong())));
        
        // Boot Patch Level
        entries.add(new ASN1TaggedEntry(AttestationTags.BOOT_PATCH_LEVEL, 
                new ASN1Integer(TrickyStoreUtils.getPatchLevelLong())));
        
        // Module Hash (KeyMint 4.0+)
        byte[] moduleHash = TrickyStoreUtils.getModuleHash();
        if (moduleHash != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.MODULE_HASH, 
                    new DEROctetString(moduleHash)));
        }
        
        // Add ID attestation tags if present
        addIdAttestationTags(entries);
        
        // Sort by tag number as required by DER encoding
        entries.sort(Comparator.comparingInt(e -> e.tag));
        
        return entries.stream()
                .map(e -> new DERTaggedObject(true, e.tag, e.value))
                .toArray(ASN1Encodable[]::new);
    }
    
    /**
     * Adds ID attestation tags if present in parameters.
     */
    private void addIdAttestationTags(List<ASN1TaggedEntry> entries) {
        if (params.getAttestationIdBrand() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_BRAND, 
                    new DEROctetString(params.getAttestationIdBrand())));
        }
        
        if (params.getAttestationIdDevice() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_DEVICE, 
                    new DEROctetString(params.getAttestationIdDevice())));
        }
        
        if (params.getAttestationIdProduct() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_PRODUCT, 
                    new DEROctetString(params.getAttestationIdProduct())));
        }
        
        if (params.getAttestationIdSerial() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_SERIAL, 
                    new DEROctetString(params.getAttestationIdSerial())));
        }
        
        if (params.getAttestationIdImei() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_IMEI, 
                    new DEROctetString(params.getAttestationIdImei())));
        }
        
        if (params.getAttestationIdMeid() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_MEID, 
                    new DEROctetString(params.getAttestationIdMeid())));
        }
        
        if (params.getAttestationIdManufacturer() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_MANUFACTURER, 
                    new DEROctetString(params.getAttestationIdManufacturer())));
        }
        
        if (params.getAttestationIdModel() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_MODEL, 
                    new DEROctetString(params.getAttestationIdModel())));
        }
        
        if (params.getAttestationIdSecondImei() != null) {
            entries.add(new ASN1TaggedEntry(AttestationTags.ATTESTATION_ID_SECOND_IMEI, 
                    new DEROctetString(params.getAttestationIdSecondImei())));
        }
    }
    
    /**
     * Builds the RootOfTrust sequence.
     *
     * RootOfTrust ::= SEQUENCE {
     *     verifiedBootKey            OCTET_STRING,
     *     deviceLocked               BOOLEAN,
     *     verifiedBootState          VerifiedBootState,
     *     verifiedBootHash           OCTET_STRING,
     * }
     */
    private ASN1Sequence buildRootOfTrust() {
        byte[] verifiedBootKey = TrickyStoreUtils.getBootKey();
        byte[] verifiedBootHash = TrickyStoreUtils.getBootHash();
        
        ASN1Encodable[] rootOfTrustElements = {
                new DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,  // deviceLocked = true
                new ASN1Enumerated(AttestationTags.VERIFIED_BOOT_VERIFIED),
                new DEROctetString(verifiedBootHash)
        };
        
        return new DERSequence(rootOfTrustElements);
    }
    
    /**
     * Builds the attestation application ID.
     */
    private byte[] buildAttestationApplicationId() {
        try {
            return AttestationApplicationIdBuilder.build(callingUid);
        } catch (Exception e) {
            Logger.e("AttestationExtensionBuilder: Failed to build application ID", e);
            return null;
        }
    }
    
    /**
     * Builds the complete KeyDescription structure.
     */
    private ASN1OctetString buildKeyDescription(
            ASN1Encodable[] softwareEnforced, 
            ASN1Encodable[] hardwareEnforced) throws IOException {
        
        // Get attestation challenge
        byte[] challenge = params.getAttestationChallenge();
        if (challenge == null) {
            challenge = new byte[0];
        }
        
        ASN1Encodable[] keyDescriptionElements = {
                new ASN1Integer(attestationVersion),
                new ASN1Enumerated(attestationSecurityLevel),
                new ASN1Integer(keyMintVersion),
                new ASN1Enumerated(keyMintSecurityLevel),
                new DEROctetString(challenge),
                new DEROctetString(new byte[0]),  // uniqueId - empty
                new DERSequence(softwareEnforced),
                new DERSequence(hardwareEnforced)
        };
        
        ASN1Sequence keyDescription = new DERSequence(keyDescriptionElements);
        return new DEROctetString(keyDescription);
    }
    
    /**
     * Converts a list of integers to ASN.1 integer array.
     */
    private static ASN1Encodable[] toIntegerArray(List<Integer> list) {
        return list.stream()
                .map(ASN1Integer::new)
                .toArray(ASN1Encodable[]::new);
    }
    
    /**
     * Helper class for tagged ASN.1 entries.
     */
    private record ASN1TaggedEntry(int tag, ASN1Encodable value) {}
}
