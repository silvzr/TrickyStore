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

import android.hardware.security.keymint.SecurityLevel;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceSpecificException;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.IKeystoreService;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.ResponseCode;

import java.security.cert.CertificateFactory;

import io.github.a13e300.tricky_store.binder.BinderInterceptor;
import top.qwq2333.ohmykeymint.CallerInfo;
import top.qwq2333.ohmykeymint.IOhMyKsService;

/**
 * Interceptor for IKeystoreService (Keystore 2.0).
 * 
 * Handles keystore operations for Android 12+.
 */
public final class KeystoreInterceptor extends BinderInterceptor {
    
    private static final KeystoreInterceptor INSTANCE = new KeystoreInterceptor();
    
    private static final String DESCRIPTOR = "android.system.keystore2.IKeystoreService";
    
    private final int getSecurityLevelTransaction;
    private final int getKeyEntryTransaction;
    private final int updateSubcomponentTransaction;
    private final int deleteKeyTransaction;
    
    private IBinder keystore;
    private SecurityLevelInterceptor teeInterceptor;
    private SecurityLevelInterceptor strongBoxInterceptor;
    
    private int triedCount = 0;
    private boolean injected = false;
    
    private KeystoreInterceptor() {
        getSecurityLevelTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "getSecurityLevel");
        getKeyEntryTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "getKeyEntry");
        updateSubcomponentTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "updateSubcomponent");
        deleteKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "deleteKey");
    }
    
    public static KeystoreInterceptor getInstance() {
        return INSTANCE;
    }
    
    @Override
    public Result onPreTransact(IBinder target, int code, int flags, 
            CallerInfo ctx, Parcel data) {
        
        int callingUid = (int) ctx.callingUid;
        int callingPid = (int) ctx.callingPid;
        
        if (!Config.getInstance().needGenerate(callingUid)) {
            return SKIP;
        }
        
        IOhMyKsService omk = Config.getInstance().getOhMyKsService();
        Logger.d("KeystoreInterceptor onPreTransact code=" + code);
        
        if (code == getKeyEntryTransaction) {
            return handleGetKeyEntry(data, ctx, callingUid, callingPid, omk);
        } else if (code == updateSubcomponentTransaction) {
            return handleUpdateSubcomponent(data, ctx, callingUid, callingPid, omk);
        } else if (code == deleteKeyTransaction) {
            return handleDeleteKey(data, ctx, callingUid, callingPid, omk);
        }
        
        return SKIP;
    }
    
    private Result handleGetKeyEntry(Parcel data, CallerInfo ctx, 
            int callingUid, int callingPid, IOhMyKsService omk) {
        try {
            Logger.d("KeystoreInterceptor getKeyEntryTransaction pre uid=" + 
                    callingUid + " pid=" + callingPid);
            
            if (!Config.getInstance().isGenerateKeyEnabled(callingUid)) {
                Logger.d("generateKey feature disabled for " + callingUid);
                return SKIP;
            }
            
            data.enforceInterface(DESCRIPTOR);
            KeyDescriptor descriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            
            if (descriptor == null) {
                Logger.d("descriptor is null, skipping");
                return SKIP;
            }
            
            Parcel reply = Parcel.obtain();
            
            if (omk != null) {
                KeyEntryResponse response = omk.getKeyEntry(ctx, descriptor);
                reply.writeNoException();
                reply.writeTypedObject(response, 0);
                return new OverrideReply(0, reply);
            }
            
            KeyEntryResponse response = KeyCache.getInstance()
                .getKeyResponse(callingUid, descriptor.alias);
            
            if (response != null) {
                Logger.i("generate key for uid=" + callingUid + 
                        " alias=" + descriptor.alias);
                reply.writeNoException();
                reply.writeTypedObject(response, 0);
            } else {
                Logger.d("key not found for uid=" + callingUid + 
                        " alias=" + descriptor.alias);
                
                // Skip system uid requests
                if (callingUid == 1000) {
                    Logger.d("system uid requesting generated key alias=" + 
                            descriptor.alias);
                    reply.recycle();
                    return SKIP;
                }
                
                reply.writeException(new ServiceSpecificException(
                    ResponseCode.KEY_NOT_FOUND,
                    "key not found for uid=" + callingUid + " alias=" + descriptor.alias
                ));
            }
            
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("getKeyEntry error", e);
            return SKIP;
        }
    }
    
    private Result handleUpdateSubcomponent(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMyKsService omk) {
        try {
            Logger.d("KeystoreInterceptor updateSubcomponent uid=" + 
                    callingUid + " pid=" + callingPid);
            
            if (!Config.getInstance().isImportKeyEnabled(callingUid)) {
                Logger.d("importKey feature disabled for " + callingUid);
                return SKIP;
            }
            
            data.enforceInterface(DESCRIPTOR);
            KeyDescriptor descriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            if (descriptor == null) return SKIP;
            
            byte[] publicCert = data.createByteArray();
            byte[] certificateChain = data.createByteArray();
            
            if (omk != null) {
                omk.updateSubcomponent(ctx, descriptor, publicCert, certificateChain);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                return new OverrideReply(0, reply);
            }
            
            if (certificateChain != null) {
                Logger.d("updateSubcomponent certificateChain sz=" + certificateChain.length);
            }
            
            if (publicCert != null) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                java.security.cert.Certificate cert = cf.generateCertificate(
                    new java.io.ByteArrayInputStream(publicCert));
                
                Logger.d("Certificate: " + cert);
                
                KeyCache.getInstance().finalizeImportedKey(callingUid, callingPid, cert);
                Logger.i("store public cert uid=" + callingUid + 
                        " alias=" + descriptor.alias + " sz=" + publicCert.length);
            }
            
        } catch (Exception e) {
            Logger.e("Failed to read updateSubcomponent data", e);
        }
        
        return SKIP;
    }
    
    private Result handleDeleteKey(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMyKsService omk) {
        try {
            Logger.d("KeystoreInterceptor deleteKeyTransaction uid=" + 
                    callingUid + " pid=" + callingPid);
            
            data.enforceInterface(DESCRIPTOR);
            KeyDescriptor keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            if (keyDescriptor == null) return SKIP;
            
            if (omk != null) {
                omk.deleteKey(ctx, keyDescriptor);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                return new OverrideReply(0, reply);
            }
            
            Logger.d("KeystoreInterceptor deleteKey uid=" + callingUid + 
                    " alias=" + keyDescriptor.alias);
            
            KeyCache.getInstance().deleteKey(callingUid, keyDescriptor.alias);
            KeyCache.getInstance().deleteImportedKey(callingUid, callingPid);
            
        } catch (Exception e) {
            Logger.e("deleteKey error", e);
        }
        
        return SKIP;
    }
    
    /**
     * Attempts to register the keystore interceptor.
     * 
     * @return true if successfully registered
     */
    public boolean tryRunKeystoreInterceptor() {
        Logger.i("Trying to register keystore interceptor (" + triedCount + ")...");
        
        IBinder binder = ServiceManager.getService(
            "android.system.keystore2.IKeystoreService/default");
        if (binder == null) return false;
        
        IBinder backdoor = getBinderBackdoor(binder);
        
        if (backdoor == null) {
            if (triedCount >= 3) {
                Logger.e("Tried injection but still has no backdoor, exit");
                System.exit(1);
            }
            
            if (!injected) {
                Logger.i("Trying to inject keystore...");
                try {
                    Process p = Runtime.getRuntime().exec(new String[]{
                        "/system/bin/sh", "-c",
                        "exec ./inject `pidof keystore2` libtricky_store.so entry"
                    });
                    if (p.waitFor() != 0) {
                        Logger.e("Failed to inject! Daemon exit");
                        System.exit(1);
                    }
                    injected = true;
                } catch (Exception e) {
                    Logger.e("Injection error", e);
                    System.exit(1);
                }
            }
            
            triedCount++;
            return false;
        }
        
        // Get security levels
        IKeystoreService ks = IKeystoreService.Stub.asInterface(binder);
        IKeystoreSecurityLevel tee = null;
        IKeystoreSecurityLevel strongBox = null;
        
        try {
            tee = ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT);
        } catch (Exception ignored) {}
        
        try {
            strongBox = ks.getSecurityLevel(SecurityLevel.STRONGBOX);
        } catch (Exception ignored) {}
        
        // Register interceptors
        keystore = binder;
        Logger.i("Register for Keystore " + keystore);
        registerBinderInterceptor(backdoor, binder, this);
        
        try {
            keystore.linkToDeath(new DeathRecipient(), 0);
        } catch (RemoteException e) {
            Logger.e("Failed to link death recipient", e);
        }
        
        if (tee != null) {
            Logger.i("Register for TEE SecurityLevel");
            teeInterceptor = new SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT);
            registerBinderInterceptor(backdoor, tee.asBinder(), teeInterceptor);
        } else {
            Logger.i("No TEE SecurityLevel found");
        }
        
        if (strongBox != null) {
            Logger.i("Register for StrongBox SecurityLevel");
            strongBoxInterceptor = new SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX);
            registerBinderInterceptor(backdoor, strongBox.asBinder(), strongBoxInterceptor);
        } else {
            Logger.i("No StrongBox SecurityLevel found");
        }
        
        return true;
    }
    
    private static class DeathRecipient implements IBinder.DeathRecipient {
        @Override
        public void binderDied() {
            Logger.d("Keystore exit, daemon restart");
            System.exit(0);
        }
    }
}
