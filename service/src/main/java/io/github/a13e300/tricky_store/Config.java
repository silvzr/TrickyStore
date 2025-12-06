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
import android.os.Build;
import android.os.FileObserver;
import android.os.IBinder;
import android.os.IInterface;
import android.os.ServiceManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import io.github.a13e300.tricky_store.keystore.CertHack;
import io.github.a13e300.tricky_store.keystore.core.KeyBoxManager;
import top.qwq2333.ohmykeymint.IOhMyKsService;
import top.qwq2333.ohmykeymint.IOhMySecurityLevel;

/**
 * Central configuration manager for TrickyStore.
 * 
 * Manages:
 * - Target packages for key spoofing
 * - Keybox configuration
 * - Device configuration
 * - Service connections
 */
public final class Config {
    
    private static final Config INSTANCE = new Config();
    
    private static final String CONFIG_PATH = "/data/adb/tricky_store";
    private static final String TARGET_FILE = "target.txt";
    private static final String KEYBOX_FILE = "keybox.xml";
    private static final String DEV_CONFIG_FILE = "devconfig.toml";
    
    // Default packages that always need key generation
    private static final List<String> DEFAULT_GENERATE_PACKAGES = Arrays.asList(
        "com.google.android.gsf",
        "com.google.android.gms",
        "com.android.vending"
    );
    
    private final File root;
    private final Set<String> hackPackages = new HashSet<>();
    private final Set<String> generatePackages = new HashSet<>();
    
    private DeviceConfig devConfig;
    private IPackageManager packageManager;
    private IOhMyKsService ohMyKsService;
    
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    
    private FileObserver configObserver;
    
    private Config() {
        this.root = new File(CONFIG_PATH);
        this.devConfig = new DeviceConfig();
    }
    
    public static Config getInstance() {
        return INSTANCE;
    }
    
    /**
     * Initializes the configuration system.
     */
    public void initialize() {
        root.mkdirs();
        
        // Load target packages
        File targetFile = new File(root, TARGET_FILE);
        if (targetFile.exists()) {
            updateTargetPackages(targetFile);
        } else {
            Logger.e("target.txt file not found, please put it to " + targetFile);
        }
        
        // Load keybox
        File keyboxFile = new File(root, KEYBOX_FILE);
        if (!keyboxFile.exists()) {
            Logger.e("keybox file not found, please put it to " + keyboxFile);
        } else {
            updateKeyBox(keyboxFile);
        }
        
        // Load device config
        File devConfigFile = new File(root, DEV_CONFIG_FILE);
        parseDevConfig(devConfigFile);
        
        // Start file observer
        startConfigObserver();
    }
    
    private void startConfigObserver() {
        configObserver = new FileObserver(root, 
                FileObserver.CLOSE_WRITE | FileObserver.DELETE | 
                FileObserver.MOVED_FROM | FileObserver.MOVED_TO) {
            @Override
            public void onEvent(int event, String path) {
                if (path == null) return;
                
                File file = null;
                if (event == FileObserver.CLOSE_WRITE || event == FileObserver.MOVED_TO) {
                    file = new File(root, path);
                }
                
                switch (path) {
                    case TARGET_FILE -> updateTargetPackages(file);
                    case KEYBOX_FILE -> updateKeyBox(file);
                    case DEV_CONFIG_FILE -> parseDevConfig(file);
                }
            }
        };
        configObserver.startWatching();
    }
    
    private void updateTargetPackages(File file) {
        try {
            synchronized (hackPackages) {
                hackPackages.clear();
            }
            synchronized (generatePackages) {
                generatePackages.clear();
                generatePackages.addAll(DEFAULT_GENERATE_PACKAGES);
            }
            
            if (file == null || !file.exists()) return;
            
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    
                    if (line.endsWith("!")) {
                        String pkg = line.substring(0, line.length() - 1).trim();
                        synchronized (generatePackages) {
                            generatePackages.add(pkg);
                        }
                    } else {
                        synchronized (hackPackages) {
                            hackPackages.add(line);
                        }
                    }
                }
            }
            
            Logger.i("Updated hack packages: " + hackPackages + 
                    ", generate packages: " + generatePackages);
            
        } catch (IOException e) {
            Logger.e("Failed to update target files", e);
        }
    }
    
    private void updateKeyBox(File file) {
        try {
            // Read content from file
            String content = null;
            if (file != null && file.exists()) {
                content = readFileContent(file);
            }
            
            // Update legacy CertHack for backward compatibility
            CertHack.readFromXml(content, getOhMyKsService());
            
            // Update new KeyBoxManager
            KeyBoxManager.getInstance().loadFromXml(content, getOhMyKsService());
            if (content != null) {
                Logger.i("KeyBoxManager: Loaded keybox from " + file.getAbsolutePath());
            }
        } catch (Exception e) {
            Logger.e("Failed to update keybox", e);
        }
    }
    
    private void parseDevConfig(File file) {
        try {
            if (file == null) return;
            
            // Stop watching during write to prevent recursive calls
            if (configObserver != null) {
                configObserver.stopWatching();
            }
            
            if (!file.exists()) {
                file.createNewFile();
                devConfig = new DeviceConfig();
                devConfig.saveToFile(file);
            } else {
                devConfig = DeviceConfig.loadFromFile(file);
                // Save back in case there are new options
                devConfig.saveToFile(file);
            }
            
            resetProp();
            
            if (configObserver != null) {
                configObserver.startWatching();
            }
        } catch (IOException e) {
            Logger.e("Failed to parse dev config", e);
        }
    }
    
    private void resetProp() {
        if (!devConfig.isAutoResetProps()) return;
        
        executor.execute(() -> {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{
                    "su", "-c", "resetprop", 
                    "ro.build.version.security_patch", 
                    devConfig.getSecurityPatch()
                });
                if (p.waitFor() == 0) {
                    Logger.d("resetprop security_patch from " + 
                            Build.VERSION.SECURITY_PATCH + " to " + 
                            devConfig.getSecurityPatch());
                }
            } catch (Exception e) {
                Logger.e("Failed to reset prop", e);
            }
        });
    }
    
    private String readFileContent(File file) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }
    
    // ==================== Package Manager ====================
    
    private final IBinder.DeathRecipient pmDeathRecipient = new IBinder.DeathRecipient() {
        @Override
        public void binderDied() {
            if (packageManager instanceof IInterface) {
                ((IInterface) packageManager).asBinder().unlinkToDeath(this, 0);
            }
            packageManager = null;
        }
    };
    
    public IPackageManager getPackageManager() {
        if (packageManager == null) {
            IBinder binder = ServiceManager.getService("package");
            if (binder != null) {
                try {
                    binder.linkToDeath(pmDeathRecipient, 0);
                } catch (Exception e) {
                    Logger.e("Failed to link PM death", e);
                }
                packageManager = IPackageManager.Stub.asInterface(binder);
            }
        }
        return packageManager;
    }
    
    // ==================== OhMyKeyService ====================
    
    private final IBinder.DeathRecipient omkDeathRecipient = new IBinder.DeathRecipient() {
        @Override
        public void binderDied() {
            Logger.e("OMK process exited. Reset OMK to null.");
            if (ohMyKsService instanceof IInterface) {
                ((IInterface) ohMyKsService).asBinder().unlinkToDeath(this, 0);
            }
            ohMyKsService = null;
        }
    };
    
    public IOhMyKsService getOhMyKsService() {
        if (ohMyKsService == null) {
            IBinder binder = ServiceManager.getService("omk");
            if (binder == null) return null;
            
            try {
                binder.linkToDeath(omkDeathRecipient, 0);
            } catch (Exception e) {
                Logger.e("Failed to link OMK death", e);
            }
            ohMyKsService = IOhMyKsService.Stub.asInterface(binder);
            updateKeyBox(new File(root, KEYBOX_FILE));
        }
        return ohMyKsService;
    }
    
    public IOhMySecurityLevel getOhMySecurityLevel(int securityLevel) {
        IOhMyKsService omk = getOhMyKsService();
        if (omk == null) return null;
        try {
            return omk.getOhMySecurityLevel(securityLevel);
        } catch (Exception e) {
            return null;
        }
    }
    
    // ==================== Package Checks ====================
    
    public boolean needHack(int callingUid) {
        // Currently disabled
        return false;
    }
    
    public boolean needGenerate(int callingUid) {
        try {
            synchronized (generatePackages) {
                synchronized (hackPackages) {
                    if (generatePackages.isEmpty() && hackPackages.isEmpty()) {
                        return false;
                    }
                }
            }
            
            IPackageManager pm = getPackageManager();
            if (pm == null) return false;
            
            String[] packages = pm.getPackagesForUid(callingUid);
            if (packages == null) return false;
            
            for (String pkg : packages) {
                synchronized (generatePackages) {
                    if (generatePackages.contains(pkg)) return true;
                }
                synchronized (hackPackages) {
                    if (hackPackages.contains(pkg)) return true;
                }
            }
            return false;
            
        } catch (Exception e) {
            Logger.e("Failed to get packages", e);
            return false;
        }
    }
    
    // ==================== Feature Checks ====================
    
    public boolean isGenerateKeyEnabled(int callingUid) {
        String packageName = getPackageNameByUid(callingUid);
        if (packageName != null) {
            DeviceConfig.AppConfig appConfig = devConfig.getAppConfig(packageName);
            if (!appConfig.generateKey()) return false;
        }
        return devConfig.isGenerateKeyEnabled();
    }
    
    public boolean isCreateOperationEnabled(int callingUid) {
        String packageName = getPackageNameByUid(callingUid);
        if (packageName != null) {
            DeviceConfig.AppConfig appConfig = devConfig.getAppConfig(packageName);
            if (!appConfig.createOperation()) return false;
        }
        return devConfig.isCreateOperationEnabled();
    }
    
    public boolean isImportKeyEnabled(int callingUid) {
        String packageName = getPackageNameByUid(callingUid);
        if (packageName != null) {
            DeviceConfig.AppConfig appConfig = devConfig.getAppConfig(packageName);
            if (!appConfig.importKey()) return false;
        }
        return devConfig.isImportKeyEnabled();
    }
    
    private String getPackageNameByUid(int uid) {
        try {
            IPackageManager pm = getPackageManager();
            if (pm == null) return null;
            String[] packages = pm.getPackagesForUid(uid);
            return (packages != null && packages.length > 0) ? packages[0] : null;
        } catch (Exception e) {
            return null;
        }
    }
    
    // ==================== Getters ====================
    
    public DeviceConfig getDevConfig() {
        return devConfig;
    }
}
