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

/**
 * Defines the ASN.1 tag numbers for the Key Attestation extension.
 * 
 * These tag numbers correspond to the Android KeyMint/Keymaster authorization tags
 * as defined in the attestation extension schema (OID 1.3.6.1.4.1.11129.2.1.17).
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/attestation#schema">Attestation Schema</a>
 */
public final class AttestationTags {
    
    private AttestationTags() {}
    
    /** OID for Android Key Attestation extension */
    public static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    
    // AuthorizationList tags
    
    /** Tag for key purpose (SIGN, ENCRYPT, etc.) - SET OF INTEGER */
    public static final int PURPOSE = 1;
    
    /** Tag for key algorithm (EC, RSA, etc.) - INTEGER */
    public static final int ALGORITHM = 2;
    
    /** Tag for key size in bits - INTEGER */
    public static final int KEY_SIZE = 3;
    
    /** Tag for block mode (CBC, GCM, etc.) - SET OF INTEGER */
    public static final int BLOCK_MODE = 4;
    
    /** Tag for digest algorithm - SET OF INTEGER */
    public static final int DIGEST = 5;
    
    /** Tag for padding mode - SET OF INTEGER */
    public static final int PADDING = 6;
    
    /** Tag for caller nonce - NULL */
    public static final int CALLER_NONCE = 7;
    
    /** Tag for minimum MAC length - INTEGER */
    public static final int MIN_MAC_LENGTH = 8;
    
    /** Tag for EC curve - INTEGER */
    public static final int EC_CURVE = 10;
    
    /** Tag for RSA public exponent - INTEGER */
    public static final int RSA_PUBLIC_EXPONENT = 200;
    
    /** Tag for MGF digest - SET OF INTEGER (KeyMint 1.0+) */
    public static final int MGF_DIGEST = 203;
    
    /** Tag for rollback resistance - NULL (Keymaster 3.0+) */
    public static final int ROLLBACK_RESISTANCE = 303;
    
    /** Tag for early boot only - NULL (Keymaster 4.1+) */
    public static final int EARLY_BOOT_ONLY = 305;
    
    /** Tag for active date time - INTEGER */
    public static final int ACTIVE_DATE_TIME = 400;
    
    /** Tag for origination expire date time - INTEGER */
    public static final int ORIGINATION_EXPIRE_DATE_TIME = 401;
    
    /** Tag for usage expire date time - INTEGER */
    public static final int USAGE_EXPIRE_DATE_TIME = 402;
    
    /** Tag for usage count limit - INTEGER */
    public static final int USAGE_COUNT_LIMIT = 405;
    
    /** Tag for user secure ID - INTEGER */
    public static final int USER_SECURE_ID = 502;
    
    /** Tag for no auth required - NULL */
    public static final int NO_AUTH_REQUIRED = 503;
    
    /** Tag for user auth type - INTEGER */
    public static final int USER_AUTH_TYPE = 504;
    
    /** Tag for auth timeout - INTEGER */
    public static final int AUTH_TIMEOUT = 505;
    
    /** Tag for allow while on body - NULL */
    public static final int ALLOW_WHILE_ON_BODY = 506;
    
    /** Tag for trusted user presence required - NULL (Keymaster 3.0+) */
    public static final int TRUSTED_USER_PRESENCE_REQ = 507;
    
    /** Tag for trusted confirmation required - NULL (Keymaster 3.0+) */
    public static final int TRUSTED_CONFIRMATION_REQ = 508;
    
    /** Tag for unlocked device required - NULL (Keymaster 3.0+) */
    public static final int UNLOCKED_DEVICE_REQ = 509;
    
    /** Tag for creation date time - INTEGER */
    public static final int CREATION_DATE_TIME = 701;
    
    /** Tag for key origin - INTEGER */
    public static final int ORIGIN = 702;
    
    /** Tag for root of trust - SEQUENCE */
    public static final int ROOT_OF_TRUST = 704;
    
    /** Tag for OS version - INTEGER */
    public static final int OS_VERSION = 705;
    
    /** Tag for OS patch level - INTEGER */
    public static final int OS_PATCH_LEVEL = 706;
    
    /** Tag for attestation application ID - OCTET STRING */
    public static final int ATTESTATION_APPLICATION_ID = 709;
    
    /** Tag for attestation ID brand - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_BRAND = 710;
    
    /** Tag for attestation ID device - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_DEVICE = 711;
    
    /** Tag for attestation ID product - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_PRODUCT = 712;
    
    /** Tag for attestation ID serial - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_SERIAL = 713;
    
    /** Tag for attestation ID IMEI - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_IMEI = 714;
    
    /** Tag for attestation ID MEID - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_MEID = 715;
    
    /** Tag for attestation ID manufacturer - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_MANUFACTURER = 716;
    
    /** Tag for attestation ID model - OCTET STRING (Keymaster 2.0+) */
    public static final int ATTESTATION_ID_MODEL = 717;
    
    /** Tag for vendor patch level - INTEGER (Keymaster 3.0+) */
    public static final int VENDOR_PATCH_LEVEL = 718;
    
    /** Tag for boot patch level - INTEGER (Keymaster 3.0+) */
    public static final int BOOT_PATCH_LEVEL = 719;
    
    /** Tag for device unique attestation - NULL (Keymaster 4.1+) */
    public static final int DEVICE_UNIQUE_ATTESTATION = 720;
    
    /** Tag for second IMEI - OCTET STRING (KeyMint 3.0+) */
    public static final int ATTESTATION_ID_SECOND_IMEI = 723;
    
    /** Tag for module hash - OCTET STRING (KeyMint 4.0+) */
    public static final int MODULE_HASH = 724;
    
    // Attestation version constants
    
    /** Keymaster 2.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMASTER_2 = 1;
    
    /** Keymaster 3.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMASTER_3 = 2;
    
    /** Keymaster 4.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMASTER_4 = 3;
    
    /** Keymaster 4.1 attestation version */
    public static final int ATTESTATION_VERSION_KEYMASTER_41 = 4;
    
    /** KeyMint 1.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMINT_1 = 100;
    
    /** KeyMint 2.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMINT_2 = 200;
    
    /** KeyMint 3.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMINT_3 = 300;
    
    /** KeyMint 4.0 attestation version */
    public static final int ATTESTATION_VERSION_KEYMINT_4 = 400;
    
    // Security level constants
    
    /** Software-only security level */
    public static final int SECURITY_LEVEL_SOFTWARE = 0;
    
    /** TEE (Trusted Execution Environment) security level */
    public static final int SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    
    /** StrongBox security level */
    public static final int SECURITY_LEVEL_STRONGBOX = 2;
    
    // Key origin constants
    
    /** Key was generated by the device */
    public static final int ORIGIN_GENERATED = 0;
    
    /** Key was derived */
    public static final int ORIGIN_DERIVED = 1;
    
    /** Key was imported */
    public static final int ORIGIN_IMPORTED = 2;
    
    /** Reserved origin */
    public static final int ORIGIN_RESERVED = 3;
    
    /** Key was securely imported */
    public static final int ORIGIN_SECURELY_IMPORTED = 4;
    
    // Verified boot state constants
    
    /** Verified boot state - verified (GREEN) */
    public static final int VERIFIED_BOOT_VERIFIED = 0;
    
    /** Verified boot state - self-signed (YELLOW) */
    public static final int VERIFIED_BOOT_SELF_SIGNED = 1;
    
    /** Verified boot state - unverified (ORANGE) */
    public static final int VERIFIED_BOOT_UNVERIFIED = 2;
    
    /** Verified boot state - failed (RED) */
    public static final int VERIFIED_BOOT_FAILED = 3;
}
