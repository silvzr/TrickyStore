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

import android.content.pm.IPackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemProperties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;

/**
 * Utility class providing various helper methods for TrickyStore.
 */
public final class TrickyStoreUtils {
    
    private static final Pattern BEGIN_PATTERN = Pattern.compile("-----BEGIN.*?-----");
    private static final Pattern END_PATTERN = Pattern.compile("-----END.*?-----");
    
    private static byte[] bootHashCache;
    private static byte[] bootKeyCache;
    private static byte[] moduleHashCache;
    private static List<DERTaggedObject> telephonyInfosCache;
    private static List<PackageVersionPair> apexInfosCache;
    
    private TrickyStoreUtils() {}
    
    /**
     * Gets the transaction code for a method from an AIDL stub class.
     */
    public static int getTransactCode(Class<?> clazz, String method) {
        try {
            Field field = clazz.getDeclaredField("TRANSACTION_" + method);
            field.setAccessible(true);
            return field.getInt(null);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get transaction code for " + method, e);
        }
    }
    
    /**
     * Gets the boot hash from system properties or generates a random one.
     */
    public static synchronized byte[] getBootHash() {
        if (bootHashCache == null) {
            bootHashCache = getBootHashFromProp();
            if (bootHashCache == null) {
                bootHashCache = randomBytes();
            }
        }
        return bootHashCache;
    }
    
    /**
     * Gets the boot key (currently generates random bytes).
     */
    public static synchronized byte[] getBootKey() {
        if (bootKeyCache == null) {
            bootKeyCache = randomBytes();
        }
        return bootKeyCache;
    }
    
    /**
     * Reads boot hash from system property.
     */
    private static byte[] getBootHashFromProp() {
        String b = SystemProperties.get("ro.boot.vbmeta.digest", null);
        if (b == null || b.length() != 64) return null;
        return hexStringToByteArray(b);
    }
    
    /**
     * Generates random bytes.
     */
    public static byte[] randomBytes() {
        byte[] bytes = new byte[32];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Gets the patch level in short format (YYYYMM).
     */
    public static int getPatchLevel() {
        try {
            return convertPatchLevel(Config.getInstance().getDevConfig().getSecurityPatch(), false);
        } catch (Exception e) {
            return convertPatchLevel(Build.VERSION.SECURITY_PATCH, false);
        }
    }
    
    /**
     * Gets the patch level in long format (YYYYMMDD).
     */
    public static int getPatchLevelLong() {
        try {
            return convertPatchLevel(Config.getInstance().getDevConfig().getSecurityPatch(), true);
        } catch (Exception e) {
            return convertPatchLevel(Build.VERSION.SECURITY_PATCH, false);
        }
    }
    
    /**
     * Gets the OS version code.
     */
    public static int getOsVersion() {
        int ver = Config.getInstance().getDevConfig().getOsVersion();
        if (ver > 0) {
            return getOsVersionCode(ver);
        }
        return getOsVersionCode(Build.VERSION.SDK_INT);
    }
    
    private static int getOsVersionCode(int sdkInt) {
        return switch (sdkInt) {
            case Build.VERSION_CODES.VANILLA_ICE_CREAM -> 150000;
            case Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> 140000;
            case Build.VERSION_CODES.TIRAMISU -> 130000;
            case Build.VERSION_CODES.S_V2 -> 120100;
            case Build.VERSION_CODES.S -> 120000;
            case Build.VERSION_CODES.Q -> 110000;
            default -> 150000;
        };
    }
    
    /**
     * Converts a patch level string to integer format.
     */
    public static int convertPatchLevel(String patchLevel, boolean longFormat) {
        try {
            String[] parts = patchLevel.split("-");
            if (longFormat) {
                return Integer.parseInt(parts[0]) * 10000 + 
                       Integer.parseInt(parts[1]) * 100 + 
                       Integer.parseInt(parts[2]);
            } else {
                return Integer.parseInt(parts[0]) * 100 + Integer.parseInt(parts[1]);
            }
        } catch (Exception e) {
            Logger.e("Invalid patch level: " + patchLevel, e);
            return 202404;
        }
    }
    
    /**
     * Gets package info with compatibility for different API levels.
     */
    public static PackageInfo getPackageInfoCompat(IPackageManager pm, String name, long flags, int userId) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                return pm.getPackageInfo(name, flags, userId);
            } else {
                return pm.getPackageInfo(name, (int) flags, userId);
            }
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Gets APEX package information.
     */
    public static synchronized List<PackageVersionPair> getApexInfos() {
        if (apexInfosCache == null) {
            apexInfosCache = new ArrayList<>();
            IPackageManager pm = Config.getInstance().getPackageManager();
            if (pm != null) {
                try {
                    List<PackageInfo> packages;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        packages = pm.getInstalledPackages(
                            (long) PackageManager.MATCH_APEX, 0).getList();
                    } else {
                        packages = pm.getInstalledPackages(
                            PackageManager.MATCH_APEX, 0).getList();
                    }
                    for (PackageInfo info : packages) {
                        apexInfosCache.add(new PackageVersionPair(
                            info.packageName, info.getLongVersionCode()));
                    }
                    // Sort lexicographically to comply with AOSP requirements
                    apexInfosCache.sort((a, b) -> a.packageName.compareTo(b.packageName));
                } catch (Exception e) {
                    Logger.e("Failed to get APEX info", e);
                }
            }
        }
        return apexInfosCache;
    }
    
    /**
     * Gets the module hash for attestation.
     */
    public static synchronized byte[] getModuleHash() {
        if (moduleHashCache == null) {
            try {
                List<ASN1Encodable> encodables = new ArrayList<>();
                List<PackageVersionPair> apexInfos = getApexInfos();
                if (apexInfos != null) {
                    for (PackageVersionPair info : apexInfos) {
                        encodables.add(new DEROctetString(info.packageName.getBytes()));
                        encodables.add(new ASN1Integer(info.versionCode));
                    }
                }
                DERSequence sequence = new DERSequence(
                    encodables.toArray(new ASN1Encodable[0]));
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(sequence.getEncoded());
                moduleHashCache = digest.digest();
            } catch (Exception e) {
                Logger.e("Failed to compute module hash", e);
                moduleHashCache = randomBytes();
            }
        }
        return moduleHashCache;
    }
    
    /**
     * Gets telephony info tags for attestation.
     */
    public static synchronized List<DERTaggedObject> getTelephonyInfos() {
        if (telephonyInfosCache == null) {
            telephonyInfosCache = new ArrayList<>();
            DeviceConfig config = Config.getInstance().getDevConfig();
            
            telephonyInfosCache.add(toTaggedObject(config.getImei(), 714));
            telephonyInfosCache.add(toTaggedObject(config.getMeid(), 715));
            telephonyInfosCache.add(toTaggedObject(config.getImei2(), 723));
            telephonyInfosCache.add(toTaggedObject(config.getSerial(), 713));
            telephonyInfosCache.add(toTaggedObject(config.getBrand(), 710));
            telephonyInfosCache.add(toTaggedObject(config.getDevice(), 711));
            telephonyInfosCache.add(toTaggedObject(config.getProduct(), 712));
            telephonyInfosCache.add(toTaggedObject(config.getManufacturer(), 716));
            telephonyInfosCache.add(toTaggedObject(config.getModel(), 717));
        }
        return telephonyInfosCache;
    }
    
    /**
     * Converts a string to DER octet string.
     */
    public static DEROctetString toDER(String value) {
        return new DEROctetString(value.getBytes());
    }
    
    /**
     * Creates a tagged object from a DER octet string.
     */
    public static DERTaggedObject toTaggedObject(String value, int tag) {
        return new DERTaggedObject(true, tag, toDER(value));
    }
    
    /**
     * Trims and joins lines.
     */
    public static String trimLine(String str) {
        String[] lines = str.trim().split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            sb.append(lines[i].trim());
            if (i < lines.length - 1) {
                sb.append("\n");
            }
        }
        return sb.toString();
    }
    
    /**
     * Parses PEM to Base64 string.
     */
    public static String parsePemToBase64(String str) {
        String result = trimLine(str);
        result = BEGIN_PATTERN.matcher(result).replaceAll("");
        result = END_PATTERN.matcher(result).replaceAll("");
        return result.replace("\n", "");
    }
    
    /**
     * Converts a Parcelable to byte array.
     */
    public static byte[] toBytes(Parcelable parcelable) {
        Parcel parcel = Parcel.obtain();
        try {
            parcelable.writeToParcel(parcel, 0);
            return parcel.marshall();
        } finally {
            parcel.recycle();
        }
    }
    
    /**
     * Converts hex string to byte array.
     */
    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Converts byte array to hex string.
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    // Data classes
    
    public record PackageVersionPair(String packageName, long versionCode) {}
}
