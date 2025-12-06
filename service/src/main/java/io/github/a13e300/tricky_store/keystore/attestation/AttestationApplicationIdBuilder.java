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

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import io.github.a13e300.tricky_store.Config;
import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.TrickyStoreUtils;

/**
 * Builds the AttestationApplicationId structure for key attestation.
 * 
 * The AttestationApplicationId reflects Android's belief about which apps
 * are allowed to use the key material. It includes package names, versions,
 * and signature digests.
 * 
 * AttestationApplicationId ::= SEQUENCE {
 *     package_infos     SET OF AttestationPackageInfo,
 *     signature_digests SET OF OCTET_STRING,
 * }
 * 
 * AttestationPackageInfo ::= SEQUENCE {
 *     package_name      OCTET_STRING,
 *     version           INTEGER,
 * }
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid">AttestationApplicationId</a>
 */
public final class AttestationApplicationIdBuilder {
    
    // Index constants for AttestationApplicationId structure
    private static final int PACKAGE_INFOS_INDEX = 0;
    private static final int SIGNATURE_DIGESTS_INDEX = 1;
    
    // Index constants for AttestationPackageInfo structure
    private static final int PACKAGE_NAME_INDEX = 0;
    private static final int VERSION_INDEX = 1;
    
    private AttestationApplicationIdBuilder() {}
    
    /**
     * Builds the AttestationApplicationId for a given UID.
     *
     * @param uid The calling application's UID
     * @return The DER-encoded AttestationApplicationId
     * @throws Exception if building fails
     */
    public static byte[] build(int uid) throws Exception {
        var pm = Config.getInstance().getPackageManager();
        if (pm == null) {
            throw new IllegalStateException("PackageManager not available");
        }
        
        // Get packages for this UID
        String[] packages = pm.getPackagesForUid(uid);
        if (packages == null || packages.length == 0) {
            Logger.w("AttestationApplicationIdBuilder: No packages found for UID " + uid);
            packages = new String[0];
        }
        
        // Build package info structures
        ASN1Encodable[] packageInfoArray = new ASN1Encodable[packages.length];
        Set<DigestWrapper> signatureDigests = new HashSet<>();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        int userId = uid / 100000;
        
        for (int i = 0; i < packages.length; i++) {
            String packageName = packages[i];
            
            // Get package info with signatures
            PackageInfo pkgInfo = TrickyStoreUtils.getPackageInfoCompat(
                    pm, packageName, PackageManager.GET_SIGNATURES, userId);
            
            // Build AttestationPackageInfo
            packageInfoArray[i] = buildPackageInfo(packageName, pkgInfo);
            
            // Collect signature digests
            if (pkgInfo.signatures != null) {
                for (var sig : pkgInfo.signatures) {
                    byte[] sigDigest = digest.digest(sig.toByteArray());
                    signatureDigests.add(new DigestWrapper(sigDigest));
                }
            }
        }
        
        // Build signature digests array
        ASN1Encodable[] signatureDigestArray = new ASN1Encodable[signatureDigests.size()];
        int idx = 0;
        for (DigestWrapper wrapper : signatureDigests) {
            signatureDigestArray[idx++] = new DEROctetString(wrapper.digest());
        }
        
        // Build final AttestationApplicationId structure
        ASN1Encodable[] applicationIdElements = new ASN1Encodable[2];
        applicationIdElements[PACKAGE_INFOS_INDEX] = new DERSet(packageInfoArray);
        applicationIdElements[SIGNATURE_DIGESTS_INDEX] = new DERSet(signatureDigestArray);
        
        return new DERSequence(applicationIdElements).getEncoded();
    }
    
    /**
     * Builds an AttestationPackageInfo structure.
     */
    private static ASN1Encodable buildPackageInfo(String packageName, PackageInfo pkgInfo) {
        ASN1Encodable[] elements = new ASN1Encodable[2];
        
        // Package name as OCTET_STRING
        elements[PACKAGE_NAME_INDEX] = new DEROctetString(
                packageName.getBytes(StandardCharsets.UTF_8));
        
        // Version as INTEGER
        long versionCode = pkgInfo != null ? pkgInfo.getLongVersionCode() : 0;
        elements[VERSION_INDEX] = new ASN1Integer(versionCode);
        
        return new DERSequence(elements);
    }
    
    /**
     * Wrapper for digest bytes to enable proper Set comparison.
     */
    private record DigestWrapper(byte[] digest) {
        @Override
        public boolean equals(Object o) {
            if (o instanceof DigestWrapper other) {
                return Arrays.equals(digest, other.digest);
            }
            return false;
        }
        
        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }
}
