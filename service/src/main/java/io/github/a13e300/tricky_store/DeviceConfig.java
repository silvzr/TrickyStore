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

import android.os.Build;
import android.os.SystemProperties;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Device configuration settings.
 * 
 * This class holds all configurable device properties used for attestation.
 */
public final class DeviceConfig {
    
    // General settings
    private String securityPatch;
    private int osVersion;
    private boolean autoResetProps;
    
    // Device properties
    private String brand;
    private String device;
    private String product;
    private String manufacturer;
    private String model;
    private String serial;
    
    // Telephony properties
    private String meid;
    private String imei;
    private String imei2;
    
    // App config
    private boolean generateKeyEnabled;
    private boolean createOperationEnabled;
    private boolean importKeyEnabled;
    
    // Additional per-app config
    private Map<String, AppConfig> additionalAppConfig;
    
    public DeviceConfig() {
        // Initialize with default values from system
        this.securityPatch = Build.VERSION.SECURITY_PATCH;
        this.osVersion = Build.VERSION.SDK_INT;
        this.autoResetProps = true;
        
        this.brand = Build.BRAND;
        this.device = Build.DEVICE;
        this.product = Build.PRODUCT;
        this.manufacturer = Build.MANUFACTURER;
        this.model = Build.MODEL;
        this.serial = SystemProperties.get("ro.serialno", "");
        
        this.meid = SystemProperties.get("ro.ril.oem.imei", "");
        this.imei = SystemProperties.get("ro.ril.oem.meid", "");
        this.imei2 = SystemProperties.get("ro.ril.oem.imei2", "");
        
        this.generateKeyEnabled = true;
        this.createOperationEnabled = false;
        this.importKeyEnabled = true;
        
        this.additionalAppConfig = new HashMap<>();
    }
    
    /**
     * Loads configuration from a TOML file.
     */
    public static DeviceConfig loadFromFile(File file) {
        DeviceConfig config = new DeviceConfig();
        
        if (!file.exists()) {
            return config;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            String currentSection = "";
            
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                
                // Skip comments and empty lines
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                // Section header
                if (line.startsWith("[") && line.endsWith("]")) {
                    currentSection = line.substring(1, line.length() - 1);
                    continue;
                }
                
                // Key-value pair
                int eqIdx = line.indexOf('=');
                if (eqIdx > 0) {
                    String key = line.substring(0, eqIdx).trim();
                    String value = line.substring(eqIdx + 1).trim();
                    
                    // Remove quotes if present
                    if (value.startsWith("\"") && value.endsWith("\"")) {
                        value = value.substring(1, value.length() - 1);
                    }
                    
                    config.setValue(currentSection, key, value);
                }
            }
        } catch (IOException e) {
            Logger.e("Failed to load config file", e);
        }
        
        return config;
    }
    
    private void setValue(String section, String key, String value) {
        switch (section) {
            case "generalSettings" -> {
                switch (key) {
                    case "securityPatch" -> this.securityPatch = value;
                    case "osVersion" -> this.osVersion = parseIntSafe(value, Build.VERSION.SDK_INT);
                    case "autoResetProps" -> this.autoResetProps = Boolean.parseBoolean(value);
                }
            }
            case "deviceProps" -> {
                switch (key) {
                    case "brand" -> this.brand = value;
                    case "device" -> this.device = value;
                    case "product" -> this.product = value;
                    case "manufacturer" -> this.manufacturer = value;
                    case "model" -> this.model = value;
                    case "serial" -> this.serial = value;
                    case "meid" -> this.meid = value;
                    case "imei" -> this.imei = value;
                    case "imei2" -> this.imei2 = value;
                }
            }
            case "globalConfig" -> {
                switch (key) {
                    case "generateKey" -> this.generateKeyEnabled = Boolean.parseBoolean(value);
                    case "createOperation" -> this.createOperationEnabled = Boolean.parseBoolean(value);
                    case "importKey" -> this.importKeyEnabled = Boolean.parseBoolean(value);
                }
            }
        }
    }
    
    /**
     * Saves configuration to a TOML file.
     */
    public void saveToFile(File file) {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write("[generalSettings]\n");
            writer.write("# YYYY-MM-DD\n");
            writer.write("securityPatch = \"" + securityPatch + "\"\n");
            writer.write("# SDK Version (i.e.: 35 for Android 15)\n");
            writer.write("osVersion = " + osVersion + "\n");
            writer.write("# Auto reset the security patch props on startup\n");
            writer.write("autoResetProps = " + autoResetProps + "\n\n");
            
            writer.write("# Remember to override the corresponding system properties when modifying the following values\n");
            writer.write("[deviceProps]\n");
            writer.write("brand = \"" + brand + "\"\n");
            writer.write("device = \"" + device + "\"\n");
            writer.write("product = \"" + product + "\"\n");
            writer.write("manufacturer = \"" + manufacturer + "\"\n");
            writer.write("model = \"" + model + "\"\n");
            writer.write("serial = \"" + serial + "\"\n");
            writer.write("meid = \"" + meid + "\"\n");
            writer.write("imei = \"" + imei + "\"\n");
            writer.write("imei2 = \"" + imei2 + "\"\n\n");
            
            writer.write("[globalConfig]\n");
            writer.write("generateKey = " + generateKeyEnabled + "\n");
            writer.write("createOperation = " + createOperationEnabled + "\n");
            writer.write("importKey = " + importKeyEnabled + "\n\n");
            
            writer.write("# Disable specific module function for specific app.\n");
            writer.write("# Do not modify if you know nothing about it.\n");
            writer.write("[additionalAppConfig]\n");
            
        } catch (IOException e) {
            Logger.e("Failed to save config file", e);
        }
    }
    
    private static int parseIntSafe(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    // Getters
    
    public String getSecurityPatch() { return securityPatch; }
    public int getOsVersion() { return osVersion; }
    public boolean isAutoResetProps() { return autoResetProps; }
    
    public String getBrand() { return brand; }
    public String getDevice() { return device; }
    public String getProduct() { return product; }
    public String getManufacturer() { return manufacturer; }
    public String getModel() { return model; }
    public String getSerial() { return serial; }
    
    public String getMeid() { return meid; }
    public String getImei() { return imei; }
    public String getImei2() { return imei2; }
    
    public boolean isGenerateKeyEnabled() { return generateKeyEnabled; }
    public boolean isCreateOperationEnabled() { return createOperationEnabled; }
    public boolean isImportKeyEnabled() { return importKeyEnabled; }
    
    public AppConfig getAppConfig(String packageName) {
        return additionalAppConfig.getOrDefault(packageName, 
            new AppConfig(generateKeyEnabled, createOperationEnabled, importKeyEnabled));
    }
    
    // Setters
    
    public void setSecurityPatch(String securityPatch) { this.securityPatch = securityPatch; }
    public void setOsVersion(int osVersion) { this.osVersion = osVersion; }
    public void setAutoResetProps(boolean autoResetProps) { this.autoResetProps = autoResetProps; }
    
    /**
     * Per-app configuration record.
     */
    public record AppConfig(
        boolean generateKey,
        boolean createOperation,
        boolean importKey
    ) {}
}
