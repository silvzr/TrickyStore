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

package io.github.a13e300.tricky_store.keystore.util;

import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import io.github.a13e300.tricky_store.Logger;

/**
 * Utility class for certificate operations.
 * 
 * Provides methods for:
 * - Converting between Certificate and byte[] formats
 * - Extracting certificate chains from KeyEntryResponse
 * - Building certificate chains for storage
 */
public final class CertificateUtils {
    
    private static final String TAG = "CertificateUtils";
    private static CertificateFactory certificateFactory;
    
    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            Logger.e(TAG + ": Failed to initialize CertificateFactory", e);
        }
    }
    
    private CertificateUtils() {}
    
    /**
     * Converts raw bytes to an X509Certificate.
     *
     * @param bytes The DER-encoded certificate bytes
     * @return The X509Certificate or null on failure
     */
    public static X509Certificate toCertificate(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        
        try {
            return (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Logger.w(TAG + ": Failed to parse certificate");
            return null;
        }
    }
    
    /**
     * Converts raw bytes to a collection of X509Certificates.
     *
     * @param bytes The DER-encoded certificates (concatenated)
     * @return Collection of certificates or empty collection on failure
     */
    @SuppressWarnings("unchecked")
    public static Collection<X509Certificate> toCertificates(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new ArrayList<>();
        }
        
        try {
            return (Collection<X509Certificate>) certificateFactory.generateCertificates(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Logger.w(TAG + ": Failed to parse certificate chain");
            return new ArrayList<>();
        }
    }
    
    /**
     * Converts certificates to concatenated DER-encoded bytes.
     *
     * @param certificates The certificates to encode
     * @return The encoded bytes or null on failure
     */
    public static byte[] toBytes(Collection<Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return null;
        
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            for (Certificate cert : certificates) {
                output.write(cert.getEncoded());
            }
            return output.toByteArray();
        } catch (Exception e) {
            Logger.w(TAG + ": Failed to encode certificates");
            return null;
        }
    }
    
    /**
     * Converts certificates to a list of individually encoded byte arrays.
     *
     * @param certificates The certificates to encode
     * @return List of encoded certificate bytes or null on failure
     */
    public static List<byte[]> toBytesList(Collection<Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) return null;
        
        try {
            List<byte[]> chain = new ArrayList<>();
            for (Certificate cert : certificates) {
                chain.add(cert.getEncoded());
            }
            return chain;
        } catch (Exception e) {
            Logger.w(TAG + ": Failed to encode certificates");
            return null;
        }
    }
    
    /**
     * Extracts the certificate chain from a KeyEntryResponse.
     *
     * @param response The key entry response
     * @return Array of certificates (leaf first) or null
     */
    public static Certificate[] getCertificateChain(KeyEntryResponse response) {
        if (response == null || response.metadata == null || 
                response.metadata.certificate == null) {
            return null;
        }
        
        X509Certificate leaf = toCertificate(response.metadata.certificate);
        if (leaf == null) return null;
        
        if (response.metadata.certificateChain != null) {
            Collection<X509Certificate> chainCerts = toCertificates(
                    response.metadata.certificateChain);
            Certificate[] chain = new Certificate[chainCerts.size() + 1];
            chain[0] = leaf;
            int i = 1;
            for (X509Certificate cert : chainCerts) {
                chain[i++] = cert;
            }
            return chain;
        } else {
            return new Certificate[]{leaf};
        }
    }
    
    /**
     * Stores a certificate chain in a KeyEntryResponse.
     *
     * @param response The response to update
     * @param chain The certificate chain (leaf first)
     */
    public static void putCertificateChain(KeyEntryResponse response, Certificate[] chain) 
            throws Exception {
        if (response.metadata == null) {
            response.metadata = new KeyMetadata();
        }
        putCertificateChain(response.metadata, chain);
    }
    
    /**
     * Stores a certificate chain in KeyMetadata.
     *
     * @param metadata The metadata to update
     * @param chain The certificate chain (leaf first)
     */
    public static void putCertificateChain(KeyMetadata metadata, Certificate[] chain) 
            throws Exception {
        if (chain == null || chain.length == 0) return;
        
        // Store leaf certificate
        metadata.certificate = chain[0].getEncoded();
        
        // Store rest of chain if present
        if (chain.length > 1) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            for (int i = 1; i < chain.length; i++) {
                output.write(chain[i].getEncoded());
            }
            metadata.certificateChain = output.toByteArray();
        }
    }
    
    /**
     * Stores a certificate chain (as List) in KeyMetadata.
     *
     * @param metadata The metadata to update
     * @param chain The certificate chain (leaf first)
     */
    public static void putCertificateChain(KeyMetadata metadata, List<Certificate> chain) 
            throws Exception {
        if (chain == null || chain.isEmpty()) return;
        putCertificateChain(metadata, chain.toArray(new Certificate[0]));
    }
}
