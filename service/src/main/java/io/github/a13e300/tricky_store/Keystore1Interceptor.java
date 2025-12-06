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

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.security.Credentials;
import android.security.KeyStore;
import android.security.keymaster.ExportResult;
import android.security.keymaster.KeyCharacteristics;
import android.security.keymaster.KeymasterArguments;
import android.security.keymaster.KeymasterCertificateChain;
import android.security.keymaster.KeymasterDefs;
import android.security.keystore.IKeystoreCertificateChainCallback;
import android.security.keystore.IKeystoreExportKeyCallback;
import android.security.keystore.IKeystoreKeyCharacteristicsCallback;
import android.security.keystore.IKeystoreService;
import android.security.keystore.KeystoreResponse;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.github.a13e300.tricky_store.binder.BinderInterceptor;
import io.github.a13e300.tricky_store.keystore.CertHack;
import top.qwq2333.ohmykeymint.CallerInfo;

/**
 * Interceptor for IKeystoreService (Keystore 1.0).
 * 
 * Handles keystore operations for Android 10/11.
 */
public final class Keystore1Interceptor extends BinderInterceptor {
    
    private static final Keystore1Interceptor INSTANCE = new Keystore1Interceptor();
    
    private static final String DESCRIPTOR = "android.security.keystore.IKeystoreService";
    
    private final int getTransaction;
    private final int generateKeyTransaction;
    private final int getKeyCharacteristicsTransaction;
    private final int exportKeyTransaction;
    private final int attestKeyTransaction;
    
    private IBinder keystore;
    
    private final Map<KeyId, CertHack.KeyGenParameters> keyArguments = new HashMap<>();
    private final Map<KeyId, KeyPair> keyPairs = new HashMap<>();
    
    private int triedCount = 0;
    private boolean injected = false;
    
    private Keystore1Interceptor() {
        getTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "get");
        generateKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "generateKey");
        getKeyCharacteristicsTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "getKeyCharacteristics");
        exportKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "exportKey");
        attestKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreService.Stub.class, "attestKey");
    }
    
    public static Keystore1Interceptor getInstance() {
        return INSTANCE;
    }
    
    @Override
    public Result onPreTransact(IBinder target, int code, int flags,
            CallerInfo ctx, Parcel data) {
        
        int callingUid = (int) ctx.callingUid;
        int callingPid = (int) ctx.callingPid;
        
        if (!CertHack.canHack()) {
            return SKIP;
        }
        
        if (code == getTransaction) {
            if (Config.getInstance().needHack(callingUid)) {
                return CONTINUE;
            } else if (Config.getInstance().needGenerate(callingUid)) {
                return SKIP;
            }
        } else if (Config.getInstance().needGenerate(callingUid)) {
            if (code == generateKeyTransaction) {
                return handleGenerateKey(data, ctx, callingUid, callingPid);
            } else if (code == getKeyCharacteristicsTransaction) {
                return handleGetKeyCharacteristics(data, ctx, callingUid);
            } else if (code == exportKeyTransaction) {
                return handleExportKey(data, ctx, callingUid);
            } else if (code == attestKeyTransaction) {
                return handleAttestKey(data, ctx, callingUid);
            }
        }
        
        return SKIP;
    }
    
    private Result handleGenerateKey(Parcel data, CallerInfo ctx, 
            int callingUid, int callingPid) {
        try {
            data.enforceInterface(DESCRIPTOR);
            
            IKeystoreKeyCharacteristicsCallback callback = 
                IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder());
            String rawAlias = data.readString();
            String alias = rawAlias.split("_")[1];
            
            Logger.i("generateKeyTransaction uid=" + callingUid + " alias=" + alias);
            
            int check = data.readInt();
            KeymasterArguments kma = new KeymasterArguments();
            CertHack.KeyGenParameters kgp = new CertHack.KeyGenParameters();
            
            if (check == 1) {
                kma.readFromParcel(data);
                kgp.algorithm = kma.getEnum(KeymasterDefs.KM_TAG_ALGORITHM, 0);
                kgp.keySize = (int) kma.getUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 0);
                kgp.setEcCurveName(kgp.keySize);
                kgp.purpose = kma.getEnums(KeymasterDefs.KM_TAG_PURPOSE);
                kgp.digest = kma.getEnums(KeymasterDefs.KM_TAG_DIGEST);
                kgp.certificateNotBefore = kma.getDate(KeymasterDefs.KM_TAG_ACTIVE_DATETIME, new Date());
                
                if (kgp.algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
                    try {
                        Method getArgumentByTag = KeymasterArguments.class
                            .getDeclaredMethod("getArgumentByTag", int.class);
                        getArgumentByTag.setAccessible(true);
                        Object rsaArgument = getArgumentByTag.invoke(kma, 
                            KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT);
                        
                        Method getLongTagValue = KeymasterArguments.class
                            .getDeclaredMethod("getLongTagValue", Object.class);
                        getLongTagValue.setAccessible(true);
                        kgp.rsaPublicExponent = (BigInteger) getLongTagValue.invoke(kma, rsaArgument);
                    } catch (Exception e) {
                        Logger.e("Read rsaPublicExponent error", e);
                    }
                }
                
                keyArguments.put(new KeyId(callingUid, alias), kgp);
            }
            
            KeyCharacteristics kc = new KeyCharacteristics();
            kc.swEnforced = new KeymasterArguments();
            kc.hwEnforced = kma;
            
            KeystoreResponse ksr = createKeystoreResponse(KeyStore.NO_ERROR, "");
            callback.onFinished(ksr, kc);
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeInt(KeyStore.NO_ERROR);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("generateKeyTransaction error", e);
            return SKIP;
        }
    }
    
    private Result handleGetKeyCharacteristics(Parcel data, CallerInfo ctx, int callingUid) {
        try {
            data.enforceInterface(DESCRIPTOR);
            
            IKeystoreKeyCharacteristicsCallback callback = 
                IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder());
            String rawAlias = data.readString();
            String alias = rawAlias.split("_")[1];
            
            Logger.i("getKeyCharacteristicsTransaction uid=" + callingUid + " alias=" + alias);
            
            KeyCharacteristics kc = new KeyCharacteristics();
            KeymasterArguments kma = new KeymasterArguments();
            
            CertHack.KeyGenParameters kgp = keyArguments.get(new KeyId(callingUid, alias));
            if (kgp != null) {
                kma.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, kgp.algorithm);
            }
            
            kc.swEnforced = new KeymasterArguments();
            kc.hwEnforced = kma;
            
            KeystoreResponse ksr = createKeystoreResponse(KeyStore.NO_ERROR, "");
            callback.onFinished(ksr, kc);
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeInt(KeyStore.NO_ERROR);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("getKeyCharacteristicsTransaction error", e);
            return SKIP;
        }
    }
    
    private Result handleExportKey(Parcel data, CallerInfo ctx, int callingUid) {
        try {
            data.enforceInterface(DESCRIPTOR);
            
            IKeystoreExportKeyCallback callback = 
                IKeystoreExportKeyCallback.Stub.asInterface(data.readStrongBinder());
            String rawAlias = data.readString();
            String alias = rawAlias.split("_")[1];
            
            Logger.i("exportKeyTransaction uid=" + callingUid + " alias=" + alias);
            
            CertHack.KeyGenParameters kgp = keyArguments.get(new KeyId(callingUid, alias));
            if (kgp == null) return SKIP;
            
            KeyPair kp = CertHack.generateKeyPair(kgp);
            keyPairs.put(new KeyId(callingUid, alias), kp);
            
            ExportResult er = createExportResult(KeyStore.NO_ERROR, kp.getPublic().getEncoded());
            callback.onFinished(er);
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeInt(KeyStore.NO_ERROR);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("exportKeyTransaction error", e);
            return SKIP;
        }
    }
    
    private Result handleAttestKey(Parcel data, CallerInfo ctx, int callingUid) {
        try {
            data.enforceInterface(DESCRIPTOR);
            
            IKeystoreCertificateChainCallback callback = 
                IKeystoreCertificateChainCallback.Stub.asInterface(data.readStrongBinder());
            String rawAlias = data.readString();
            String alias = rawAlias.split("_")[1];
            
            Logger.i("attestKeyTransaction uid=" + callingUid + " alias=" + alias);
            
            int check = data.readInt();
            KeymasterArguments kma = new KeymasterArguments();
            
            if (check == 1) {
                kma.readFromParcel(data);
                byte[] attestationChallenge = kma.getBytes(
                    KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, new byte[0]);
                
                KeystoreResponse ksr = createKeystoreResponse(KeyStore.NO_ERROR, "");
                
                KeyId keyId = new KeyId(callingUid, alias);
                CertHack.KeyGenParameters ka = keyArguments.get(keyId);
                if (ka == null) return SKIP;
                
                ka.attestationChallenge = attestationChallenge;
                KeyPair kp = keyPairs.get(keyId);
                if (kp == null) return SKIP;
                
                List<byte[]> chain = CertHack.generateChain(callingUid, ka, kp);
                
                KeymasterCertificateChain kcc = new KeymasterCertificateChain(chain);
                callback.onFinished(ksr, kcc);
            }
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeInt(KeyStore.NO_ERROR);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("attestKeyTransaction error", e);
            return SKIP;
        }
    }
    
    @Override
    public Result onPostTransact(IBinder target, int code, int flags,
            CallerInfo ctx, Parcel data, Parcel reply, int resultCode) {
        
        int callingUid = (int) ctx.callingUid;
        int callingPid = (int) ctx.callingPid;
        
        if (target != keystore || code != getTransaction || reply == null) {
            return SKIP;
        }
        
        try {
            reply.readException();
        } catch (Exception e) {
            return SKIP;
        }
        
        try {
            Logger.d("Intercept post uid=" + callingUid + " pid=" + callingPid);
            
            data.enforceInterface(DESCRIPTOR);
            String alias = data.readString();
            if (alias == null) alias = "";
            
            byte[] response = reply.createByteArray();
            
            if (alias.startsWith(Credentials.USER_CERTIFICATE)) {
                String keyAlias = alias.split("_")[1];
                response = CertHack.hackCertificateChainUSR(response, keyAlias, callingUid);
                Logger.i("Hacked leaf of uid=" + callingUid);
                
                Parcel p = Parcel.obtain();
                p.writeNoException();
                p.writeByteArray(response);
                return new OverrideReply(0, p);
                
            } else if (alias.startsWith(Credentials.CA_CERTIFICATE)) {
                String keyAlias = alias.split("_")[1];
                response = CertHack.hackCertificateChainCA(response, keyAlias, callingUid);
                Logger.i("Hacked caList of uid=" + callingUid);
                
                Parcel p = Parcel.obtain();
                p.writeNoException();
                p.writeByteArray(response);
                return new OverrideReply(0, p);
            }
            
        } catch (Exception e) {
            Logger.e("Failed to hack certificate chain of uid=" + callingUid + 
                    " pid=" + callingPid, e);
        }
        
        return SKIP;
    }
    
    /**
     * Attempts to register the keystore interceptor.
     */
    public boolean tryRunKeystoreInterceptor() {
        Logger.i("Trying to register keystore interceptor (" + triedCount + ")...");
        
        IBinder binder = ServiceManager.getService("android.security.keystore");
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
                        "exec ./inject `pidof keystore` libtricky_store.so entry"
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
        
        keystore = binder;
        Logger.i("Register for Keystore " + keystore);
        registerBinderInterceptor(backdoor, binder, this);
        
        try {
            keystore.linkToDeath(new DeathRecipient(), 0);
        } catch (RemoteException e) {
            Logger.e("Failed to link death recipient", e);
        }
        
        return true;
    }
    
    private KeystoreResponse createKeystoreResponse(int responseCode, String message) {
        Parcel p = Parcel.obtain();
        try {
            p.writeInt(responseCode);
            p.writeString(message);
            p.setDataPosition(0);
            return KeystoreResponse.CREATOR.createFromParcel(p);
        } finally {
            p.recycle();
        }
    }
    
    private ExportResult createExportResult(int resultCode, byte[] exportData) {
        Parcel p = Parcel.obtain();
        try {
            p.writeInt(resultCode);
            p.writeByteArray(exportData);
            p.setDataPosition(0);
            return ExportResult.CREATOR.createFromParcel(p);
        } finally {
            p.recycle();
        }
    }
    
    private record KeyId(int uid, String alias) {}
    
    private static class DeathRecipient implements IBinder.DeathRecipient {
        @Override
        public void binderDied() {
            Logger.d("Keystore exit, daemon restart");
            System.exit(0);
        }
    }
}
