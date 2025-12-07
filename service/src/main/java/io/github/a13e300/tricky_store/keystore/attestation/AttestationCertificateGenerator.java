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

import android.hardware.security.keymint.Algorithm;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.TrickyStoreUtils;
import io.github.a13e300.tricky_store.keystore.core.KeyBox;
import io.github.a13e300.tricky_store.keystore.core.KeyBoxManager;
import io.github.a13e300.tricky_store.keystore.core.KeyGenParameters;

/**
 * Generates attestation certificates for simulated hardware-backed keys.
 * 
 * This class handles:
 * - Creating leaf certificates signed by the keybox intermediate CA
 * - Embedding attestation extensions with proper device state
 * - Building complete certificate chains
 * - Modifying existing certificate chains to inject attestation data
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/attestation#attestation-certificate">Attestation Certificate</a>
 */
public final class AttestationCertificateGenerator {
    
    private static final AttestationCertificateGenerator INSTANCE = new AttestationCertificateGenerator();
    private static final ASN1ObjectIdentifier ATTESTATION_OID = 
            new ASN1ObjectIdentifier(AttestationTags.ATTESTATION_OID);
    
    private final CertificateFactory certificateFactory;
    
    private AttestationCertificateGenerator() {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CertificateFactory", e);
        }
    }
    
    /**
     * @return The singleton instance
     */
    public static AttestationCertificateGenerator getInstance() {
        return INSTANCE;
    }
    
    /**
     * Generates a complete certificate chain for a newly generated key.
     *
     * @param keyPair The generated key pair
     * @param params The key generation parameters
     * @param callingUid The calling application's UID
     * @return The certificate chain with attestation, or null on failure
     */
    public List<Certificate> generateCertificateChain(
            KeyPair keyPair, KeyGenParameters params, int callingUid) {
        
        try {
            // Get appropriate keybox based on algorithm
            KeyBox keyBox = getKeyBoxForAlgorithm(params.getAlgorithm());
            if (keyBox == null) {
                Logger.e("AttestationCertificateGenerator: No keybox for algorithm " + 
                        params.getAlgorithm());
                return null;
            }
            
            // Build attestation extension if challenge is present
            Extension attestationExtension = null;
            if (params.hasAttestationChallenge()) {
                attestationExtension = new AttestationExtensionBuilder(params, callingUid)
                        .build();
            }
            
            // Generate leaf certificate
            X509Certificate leafCert = generateLeafCertificate(
                    keyPair.getPublic(), 
                    keyBox.getKeyPair(), 
                    keyBox.getIssuerCertificate(),
                    params,
                    attestationExtension);
            
            // Build complete chain
            List<Certificate> chain = new ArrayList<>();
            chain.add(leafCert);
            chain.addAll(keyBox.getCertificateChain());
            
            return chain;
            
        } catch (Exception e) {
            Logger.e("AttestationCertificateGenerator: Failed to generate chain", e);
            return null;
        }
    }
    
    /**
     * Generates certificate chain for a legacy Keymaster 1.0 style request.
     * Returns the chain as list of DER-encoded byte arrays.
     *
     * @param keyPair The generated key pair
     * @param params The key generation parameters
     * @param callingUid The calling application's UID
     * @return List of DER-encoded certificates, or null on failure
     */
    public List<byte[]> generateCertificateChainBytes(
            KeyPair keyPair, KeyGenParameters params, int callingUid) {
        
        List<Certificate> chain = generateCertificateChain(keyPair, params, callingUid);
        if (chain == null) return null;
        
        try {
            List<byte[]> encodedChain = new ArrayList<>();
            for (Certificate cert : chain) {
                encodedChain.add(cert.getEncoded());
            }
            return encodedChain;
        } catch (Exception e) {
            Logger.e("AttestationCertificateGenerator: Failed to encode chain", e);
            return null;
        }
    }
    
    /**
     * Hacks an existing certificate chain to replace the attestation extension
     * and re-sign with the loaded keybox.
     *
     * @param existingChain The existing certificate chain
     * @return The modified certificate chain, or the original on failure
     */
    public Certificate[] hackCertificateChain(Certificate[] existingChain) {
        if (existingChain == null || existingChain.length == 0) {
            Logger.e("AttestationCertificateGenerator: Empty chain to hack");
            return existingChain;
        }
        
        try {
            X509Certificate leafCert = (X509Certificate) existingChain[0];
            
            // Check if certificate has attestation extension
            byte[] extensionValue = leafCert.getExtensionValue(ATTESTATION_OID.getId());
            if (extensionValue == null) {
                return existingChain;
            }
            
            // Get keybox for this algorithm
            KeyBox keyBox = getKeyBoxForAlgorithm(leafCert.getPublicKey().getAlgorithm());
            if (keyBox == null) {
                Logger.e("AttestationCertificateGenerator: No keybox for " + 
                        leafCert.getPublicKey().getAlgorithm());
                return existingChain;
            }
            
            // Parse and modify attestation extension
            X509CertificateHolder leafHolder = new X509CertificateHolder(leafCert.getEncoded());
            Extension originalExt = leafHolder.getExtension(ATTESTATION_OID);
            Extension modifiedExt = modifyAttestationExtension(originalExt);
            
            // Build new leaf certificate
            X509Certificate newLeafCert = rebuildLeafCertificate(
                    leafHolder, keyBox, modifiedExt);
            
            // Build new chain with keybox certificates
            List<Certificate> newChain = new ArrayList<>();
            newChain.add(newLeafCert);
            newChain.addAll(keyBox.getCertificateChain());
            
            return newChain.toArray(new Certificate[0]);
            
        } catch (Exception e) {
            Logger.e("AttestationCertificateGenerator: Failed to hack chain", e);
            return existingChain;
        }
    }
    
    /**
     * Hacks a single certificate (leaf) to replace attestation data.
     * Used for Keystore 1.0 USER_CERTIFICATE requests.
     *
     * @param certificate The certificate bytes
     * @param alias The key alias
     * @param uid The calling UID
     * @return The modified certificate bytes, or original on failure
     */
    public byte[] hackLeafCertificate(byte[] certificate, String alias, int uid) {
        if (certificate == null) return null;
        
        try {
            X509Certificate cert = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(certificate));
            
            // Check for attestation extension
            byte[] extensionValue = cert.getExtensionValue(ATTESTATION_OID.getId());
            if (extensionValue == null) {
                return certificate;
            }
            
            // Get keybox for this algorithm
            KeyBox keyBox = getKeyBoxForAlgorithm(cert.getPublicKey().getAlgorithm());
            if (keyBox == null) {
                return certificate;
            }
            
            // Parse and modify
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extension originalExt = holder.getExtension(ATTESTATION_OID);
            Extension modifiedExt = modifyAttestationExtension(originalExt);
            
            // Rebuild
            X509Certificate newCert = rebuildLeafCertificate(holder, keyBox, modifiedExt);
            return newCert.getEncoded();
            
        } catch (Exception e) {
            Logger.e("AttestationCertificateGenerator: Failed to hack leaf", e);
            return certificate;
        }
    }
    
    /**
     * Gets the CA certificate bytes for a given algorithm.
     * Used for Keystore 1.0 CA_CERTIFICATE requests.
     */
    public byte[] getCaChainBytes(String algorithm) {
        KeyBox keyBox = KeyBoxManager.getInstance().getKeyBox(algorithm);
        if (keyBox == null) return null;
        
        try {
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            for (Certificate cert : keyBox.getCertificateChain()) {
                output.write(cert.getEncoded());
            }
            return output.toByteArray();
        } catch (Exception e) {
            Logger.e("AttestationCertificateGenerator: Failed to get CA chain", e);
            return null;
        }
    }
    
    /**
     * Gets the keybox for a given algorithm constant.
     */
    private KeyBox getKeyBoxForAlgorithm(int algorithm) {
        String algoName = switch (algorithm) {
            case Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC;
            case Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA;
            default -> null;
        };
        
        return algoName != null ? KeyBoxManager.getInstance().getKeyBox(algoName) : null;
    }
    
    /**
     * Gets the keybox for a given algorithm name.
     */
    private KeyBox getKeyBoxForAlgorithm(String algorithm) {
        if (algorithm.contains("EC") || algorithm.contains("ECDSA")) {
            return KeyBoxManager.getInstance().getEcKeyBox();
        } else if (algorithm.contains("RSA")) {
            return KeyBoxManager.getInstance().getRsaKeyBox();
        }
        return null;
    }
    
    /**
     * Generates a leaf certificate signed by the keybox.
     */
    private X509Certificate generateLeafCertificate(
            PublicKey publicKey,
            KeyPair signingKeyPair,
            Certificate issuerCert,
            KeyGenParameters params,
            Extension attestationExtension) throws Exception {
        
        X509CertificateHolder issuerHolder = new X509CertificateHolder(issuerCert.getEncoded());
        X500Name issuer = issuerHolder.getSubject();
        
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                params.getCertificateSerial(),
                params.getCertificateNotBefore(),
                params.getCertificateNotAfter(),
                params.getCertificateSubject(),
                publicKey);
        
        // Add key usage
        KeyUsage keyUsage = determineKeyUsage(params);
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        
        // Add attestation extension if present
        if (attestationExtension != null) {
            builder.addExtension(attestationExtension);
        }
        
        // Determine signature algorithm
        String sigAlgorithm = getSignatureAlgorithm(params.getAlgorithm());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgorithm)
                .build(signingKeyPair.getPrivate());
        
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
    
    /**
     * Rebuilds a leaf certificate with modified attestation extension.
     */
    private X509Certificate rebuildLeafCertificate(
            X509CertificateHolder original,
            KeyBox keyBox,
            Extension attestationExtension) throws Exception {
        
        X509CertificateHolder issuerHolder = new X509CertificateHolder(
                keyBox.getIssuerCertificate().getEncoded());
        
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuerHolder.getSubject(),
                original.getSerialNumber(),
                original.getNotBefore(),
                original.getNotAfter(),
                original.getSubject(),
                original.getSubjectPublicKeyInfo());
        
        // Add attestation extension
        builder.addExtension(attestationExtension);
        
        // Copy other extensions
        for (ASN1ObjectIdentifier oid : original.getExtensions().getExtensionOIDs()) {
            if (!oid.equals(ATTESTATION_OID)) {
                builder.addExtension(original.getExtension(oid));
            }
        }
        
        // Sign with keybox key
        String sigAlgorithm = keyBox.getAlgorithm().equals(KeyProperties.KEY_ALGORITHM_EC) 
                ? "SHA256withECDSA" : "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgorithm)
                .build(keyBox.getKeyPair().getPrivate());
        
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
    
    /**
     * Modifies an attestation extension to fix root of trust.
     */
    private Extension modifyAttestationExtension(Extension original) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(
                original.getExtnValue().getOctets());
        ASN1Encodable[] elements = sequence.toArray();
        
        // Element [7] is hardwareEnforced AuthorizationList
        ASN1Sequence hardwareEnforced = (ASN1Sequence) elements[7];
        ASN1EncodableVector newHwEnforced = new ASN1EncodableVector();
        
        // Process hardware enforced elements, replacing root of trust
        for (ASN1Encodable encodable : hardwareEnforced) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) encodable;
            
            if (tagged.getTagNo() == AttestationTags.ROOT_OF_TRUST) {
                // Replace with our root of trust
                ASN1Sequence newRootOfTrust = buildRootOfTrust();
                newHwEnforced.add(new DERTaggedObject(true, 
                        AttestationTags.ROOT_OF_TRUST, newRootOfTrust));
            } else {
                newHwEnforced.add(tagged);
            }
        }
        
        // Sort by tag number for DER compliance
        List<ASN1TaggedObject> sortedTags = new ArrayList<>();
        for (int i = 0; i < newHwEnforced.size(); i++) {
            sortedTags.add((ASN1TaggedObject) newHwEnforced.get(i));
        }
        sortedTags.sort(Comparator.comparingInt(ASN1TaggedObject::getTagNo));
        ASN1EncodableVector sortedHwEnforced = new ASN1EncodableVector();
        for (ASN1TaggedObject tag : sortedTags) {
            sortedHwEnforced.add(tag);
        }
        
        // Rebuild sequence
        elements[7] = new DERSequence(sortedHwEnforced);
        ASN1Sequence newSequence = new DERSequence(elements);
        
        return new Extension(ATTESTATION_OID, false, 
                new DEROctetString(newSequence));
    }
    
    /**
     * Builds a valid root of trust.
     */
    private ASN1Sequence buildRootOfTrust() {
        byte[] bootKey = TrickyStoreUtils.getBootKey();
        byte[] bootHash = TrickyStoreUtils.getBootHash();
        
        ASN1Encodable[] elements = {
                new DEROctetString(bootKey),
                ASN1Boolean.TRUE,
                new ASN1Enumerated(AttestationTags.VERIFIED_BOOT_VERIFIED),
                new DEROctetString(bootHash)
        };
        
        return new DERSequence(elements);
    }
    
    /**
     * Determines key usage based on key purposes.
     */
    private KeyUsage determineKeyUsage(KeyGenParameters params) {
        List<Integer> purposes = params.getPurposes();
        
        // Check if encryption/decryption purposes
        if (purposes.contains(0) || purposes.contains(1)) { // ENCRYPT or DECRYPT
            return new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
        }
        
        // Default to signing
        return new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
    }
    
    /**
     * Gets the signature algorithm for certificate signing.
     */
    private String getSignatureAlgorithm(int algorithm) {
        return switch (algorithm) {
            case Algorithm.EC -> "SHA256withECDSA";
            case Algorithm.RSA -> "SHA256withRSA";
            default -> "SHA256withECDSA";
        };
    }
}
