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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.MessageDigest;

/**
 * Main entry point for TrickyStore daemon.
 */
public final class Main {
    
    private Main() {}
    
    public static void main(String[] args) {
        verifySelf();
        Logger.i("Welcome to TrickyStore!");
        
        while (true) {
            try {
                if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q || 
                    Build.VERSION.SDK_INT == Build.VERSION_CODES.R) {
                    // Android 10/11 - use Keystore 1.0
                    if (!Keystore1Interceptor.getInstance().tryRunKeystoreInterceptor()) {
                        Thread.sleep(1000);
                        continue;
                    }
                } else {
                    // Android 12+ - use Keystore 2.0
                    if (!KeystoreInterceptor.getInstance().tryRunKeystoreInterceptor()) {
                        Thread.sleep(1000);
                        continue;
                    }
                }
                
                Config.getInstance().initialize();
                
                // Keep running
                while (true) {
                    Thread.sleep(1000000);
                }
                
            } catch (InterruptedException e) {
                Logger.e("Main loop interrupted", e);
            }
        }
    }
    
    private static void verifySelf() {
        if (BuildConfig.DEBUG) return;
        
        try {
            File prop = new File("./module.prop");
            String canonicalPath = prop.getCanonicalPath();
            
            if (!canonicalPath.equals("/data/adb/modules/tricky_store/module.prop")) {
                throw new RuntimeException("Wrong directory: " + canonicalPath);
            }
            
            // Read module properties
            java.util.Map<String, String> kv = new java.util.HashMap<>();
            try (BufferedReader reader = new BufferedReader(new FileReader(prop))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        kv.put(parts[0], parts[1]);
                    }
                }
            }
            
            // Calculate checksum
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(kv.get("id").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(kv.get("name").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(kv.get("version").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(kv.get("versionCode").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(kv.get("author").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(kv.get("description").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String checksum = bytesToHex(md.digest());
            
            if (!checksum.equals(BuildConfig.CHECKSUM)) {
                Logger.e("Unverified module files! (" + checksum + " != " + BuildConfig.CHECKSUM + ")");
                
                // Write corrupted marker
                try (FileWriter writer = new FileWriter(prop)) {
                    for (java.util.Map.Entry<String, String> entry : kv.entrySet()) {
                        String k = entry.getKey();
                        String v = entry.getValue();
                        switch (k) {
                            case "description" -> writer.write("description=×Module files corrupted, please re-download it from github.com/qwq233/TrickyStore\n");
                            case "author" -> writer.write("author=5ec1cff, James Clef\n");
                            default -> writer.write(k + "=" + v + "\n");
                        }
                    }
                }
                
                new File("./remove").createNewFile();
                System.exit(1);
            }
            
            Logger.d("Verify success!");
            
        } catch (Exception e) {
            Logger.e("Error while verifying self", e);
            System.exit(1);
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
