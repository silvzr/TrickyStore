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

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.Tag;
import android.os.IBinder;
import android.os.Parcel;
import android.system.keystore2.AuthenticatorSpec;
import android.system.keystore2.Authorization;
import android.util.Pair;
import android.system.keystore2.CreateOperationResponse;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import io.github.a13e300.tricky_store.binder.BinderInterceptor;
import io.github.a13e300.tricky_store.keystore.CertHack;
import io.github.a13e300.tricky_store.keystore.CertHack.KeyGenParameters;
import io.github.a13e300.tricky_store.keystore.util.CertificateUtils;
import top.qwq2333.ohmykeymint.CallerInfo;
import top.qwq2333.ohmykeymint.IOhMySecurityLevel;

/**
 * Interceptor for IKeystoreSecurityLevel operations.
 * 
 * Handles key generation, import, and cryptographic operations.
 */
public final class SecurityLevelInterceptor extends BinderInterceptor {
    
    private static final int createOperationTransaction;
    private static final int generateKeyTransaction;
    private static final int importKeyTransaction;
    private static final int importWrappedKeyTransaction;
    private static final int deleteKeyTransaction;
    
    static {
        createOperationTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreSecurityLevel.Stub.class, "createOperation");
        generateKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreSecurityLevel.Stub.class, "generateKey");
        importKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreSecurityLevel.Stub.class, "importKey");
        importWrappedKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreSecurityLevel.Stub.class, "importWrappedKey");
        deleteKeyTransaction = TrickyStoreUtils.getTransactCode(
            IKeystoreSecurityLevel.Stub.class, "deleteKey");
    }
    
    private final IKeystoreSecurityLevel original;
    private final int level;
    
    public SecurityLevelInterceptor(IKeystoreSecurityLevel original, int level) {
        this.original = original;
        this.level = level;
    }
    
    @Override
    public Result onPreTransact(IBinder target, int code, int flags,
            CallerInfo ctx, Parcel data) {
        
        int callingUid = (int) ctx.callingUid;
        int callingPid = (int) ctx.callingPid;
        
        Logger.d("SecurityLevelInterceptor onPreTransact code=" + code + 
                " uid=" + callingUid + " pid=" + callingPid);
        
        if (!Config.getInstance().needGenerate(callingUid)) {
            return SKIP;
        }
        
        IOhMySecurityLevel securityLevel = Config.getInstance().getOhMySecurityLevel(level);
        
        if (code == generateKeyTransaction) {
            return handleGenerateKey(data, ctx, callingUid, callingPid, securityLevel);
        } else if (code == importKeyTransaction) {
            return handleImportKey(data, ctx, callingUid, callingPid, securityLevel);
        } else if (code == createOperationTransaction) {
            return handleCreateOperation(data, ctx, callingUid, callingPid, securityLevel);
        } else if (code == importWrappedKeyTransaction) {
            return handleImportWrappedKey(data, ctx, callingUid, callingPid, securityLevel);
        } else if (code == deleteKeyTransaction) {
            return handleDeleteKey(data, ctx, callingUid, callingPid, securityLevel);
        } else {
            return SKIP;
        }
    }
    
    private Result handleGenerateKey(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMySecurityLevel securityLevel) {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            Logger.i("Intercept key gen uid=" + callingUid + " pid=" + callingPid);
            
            if (!Config.getInstance().isGenerateKeyEnabled(callingUid)) {
                Logger.d("generateKey feature disabled for " + callingUid);
                return SKIP;
            }
            
            KeyDescriptor keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            if (keyDescriptor == null) return SKIP;
            
            KeyDescriptor attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            KeyParameter[] params = data.createTypedArray(KeyParameter.CREATOR);
            int flags = data.readInt();
            byte[] entropy = data.createByteArray();
            
            KeyMetadata response;
            
            if (securityLevel != null) {
                response = (KeyMetadata) securityLevel.generateKey(ctx, keyDescriptor, 
                    attestationKeyDescriptor, params, flags, entropy);
            } else {
                KeyGenParameters kgp = new KeyGenParameters(params);
                
                // Generate key pair and certificate chain
                Pair<KeyPair, List<Certificate>> result = CertHack.generateKeyPair(
                    callingUid, keyDescriptor, attestationKeyDescriptor, kgp);
                if (result == null) return SKIP;
                
                KeyEntryResponse keyResponse = buildResponse(
                    result.second, kgp, 
                    attestationKeyDescriptor != null ? attestationKeyDescriptor : keyDescriptor);
                
                KeyCache.getInstance().putKey(callingUid, keyDescriptor.alias, 
                    result.first, result.second, keyResponse);
                
                response = keyResponse.metadata;
            }
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeTypedObject(response, 0);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("Parse key gen request error", e);
            return SKIP;
        }
    }
    
    private Result handleImportKey(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMySecurityLevel securityLevel) {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            
            if (!Config.getInstance().isImportKeyEnabled(callingUid)) {
                Logger.d("importKey feature disabled for " + callingUid);
                return SKIP;
            }
            
            KeyDescriptor keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            if (keyDescriptor == null) return SKIP;
            
            KeyDescriptor attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            KeyParameter[] params = data.createTypedArray(KeyParameter.CREATOR);
            int flags = data.readInt();
            byte[] keyData = data.createByteArray();
            
            if (securityLevel != null) {
                KeyMetadata response = (KeyMetadata) securityLevel.importKey(ctx, keyDescriptor,
                    attestationKeyDescriptor, params, flags, keyData);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                reply.writeTypedObject(response, 0);
                return new OverrideReply(0, reply);
            }
            
            KeyGenParameters kgp = new KeyGenParameters(params);
            
            // Only handle signing keys
            if (!hasSigningPurpose(kgp.getPurposes())) {
                Logger.i("Only signing key request is supported now");
                return SKIP;
            }
            
            // Parse private key
            PrivateKey privateKey;
            if (kgp.getAlgorithm() == Algorithm.EC) {
                privateKey = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(keyData));
            } else if (kgp.getAlgorithm() == Algorithm.RSA) {
                privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(keyData));
            } else {
                Logger.e("Unsupported algorithm " + kgp.getAlgorithm());
                return SKIP;
            }
            
            final KeyDescriptor finalKeyDescriptor = keyDescriptor;
            final KeyDescriptor finalAttestationKeyDescriptor = attestationKeyDescriptor;
            final KeyGenParameters finalKgp = kgp;
            
            KeyCache.getInstance().preImportKey(callingUid, callingPid, privateKey, () -> {
                KeyCache.ImportedKeyInfo info = KeyCache.getInstance()
                    .getImportedKey(callingUid, callingPid);
                if (info == null) return;
                
                Pair<KeyPair, List<Certificate>> result = CertHack.generateKeyPairWithImportedKey(
                    finalKeyDescriptor, finalKgp, 
                    () -> {
                        KeyCache.ImportedKeyInfo imported = KeyCache.getInstance()
                            .getImportedKey(callingUid, callingPid);
                        if (imported == null) return null;
                        return new Pair<>(imported.privateKey(), imported.certificate());
                    });
                
                if (result != null) {
                    KeyEntryResponse response = buildResponse(result.second, finalKgp,
                        finalAttestationKeyDescriptor != null ? 
                            finalAttestationKeyDescriptor : finalKeyDescriptor);
                    
                    KeyCache.getInstance().putKey(callingUid, finalKeyDescriptor.alias,
                        result.first, result.second, response);
                    
                    Logger.d("Imported key generated uid=" + callingUid + 
                            " alias=" + finalKeyDescriptor.alias);
                }
            });
            
            return SKIP;
            
        } catch (Exception e) {
            Logger.e("Import key error", e);
            return SKIP;
        }
    }
    
    private Result handleCreateOperation(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMySecurityLevel securityLevel) {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            Logger.d("createOperationTransaction uid=" + callingUid + " pid=" + callingPid);
            
            if (!Config.getInstance().isCreateOperationEnabled(callingUid)) {
                Logger.d("createOperation feature disabled for " + callingUid);
                return SKIP;
            }
            
            KeyDescriptor keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
            if (keyDescriptor == null) return SKIP;
            
            KeyParameter[] params = data.createTypedArray(KeyParameter.CREATOR);
            if (params == null) return SKIP;
            
            boolean force = data.readBoolean();
            KeyGenParameters kgp = new KeyGenParameters(params);
            
            if (securityLevel != null) {
                CreateOperationResponse response = (CreateOperationResponse) securityLevel.createOperation(ctx, keyDescriptor, params, force);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                reply.writeTypedObject(response, 0);
                return new OverrideReply(0, reply);
            }
            
            if (keyDescriptor.domain != 4) {
                throw new IllegalArgumentException("Unsupported domain " + keyDescriptor.domain);
            }
            
            if (!hasSigningPurpose(kgp.getPurposes())) {
                throw new IllegalArgumentException("Unsupported purpose");
            }
            
            String algorithm;
            if (kgp.getAlgorithm() == Algorithm.EC) {
                algorithm = "ECDSA";
            } else if (kgp.getAlgorithm() == Algorithm.RSA) {
                algorithm = "RSA";
            } else {
                throw new IllegalArgumentException("Unsupported algorithm " + kgp.getAlgorithm());
            }
            
            // Find the key
            List<KeyCache.KeyInfo> infos = KeyCache.getInstance()
                .getInfoByNamespace(callingUid, keyDescriptor.nspace);
            
            if (infos.isEmpty()) {
                Logger.e("Key not found");
                return SKIP;
            }
            
            KeyCache.KeyInfo info = null;
            for (KeyCache.KeyInfo i : infos) {
                if (i.response().metadata != null && 
                    i.response().metadata.key != null &&
                    keyDescriptor.alias.equals(i.response().metadata.key.alias) &&
                    algorithm.equals(i.keyPair().getPrivate().getAlgorithm())) {
                    info = i;
                    break;
                }
            }
            
            if (info == null) return SKIP;
            
            Logger.d("createOperation: " + info.chain().get(0));
            
            // Create operation
            KeyStoreOperationImpl op = new KeyStoreOperationImpl(
                info.keyPair().getPrivate(), "SHA256with" + algorithm);
            
            CreateOperationResponse response = new CreateOperationResponse();
            response.iOperation = op;
            
            Parcel reply = Parcel.obtain();
            reply.writeNoException();
            reply.writeTypedObject(response, 0);
            return new OverrideReply(0, reply);
            
        } catch (Exception e) {
            Logger.e("Create operation error", e);
            return SKIP;
        }
    }
    
    private Result handleImportWrappedKey(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMySecurityLevel securityLevel) {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            
            if (!Config.getInstance().isImportKeyEnabled(callingUid)) {
                Logger.d("importKey feature disabled for " + callingUid);
                return SKIP;
            }
            
            KeyDescriptor key = data.readTypedObject(KeyDescriptor.CREATOR);
            if (key == null) return SKIP;
            
            KeyDescriptor wrappingKey = data.readTypedObject(KeyDescriptor.CREATOR);
            if (wrappingKey == null) return SKIP;
            
            byte[] maskingKey = data.createByteArray();
            KeyParameter[] params = data.createTypedArray(KeyParameter.CREATOR);
            if (params == null) return SKIP;
            
            AuthenticatorSpec[] authenticators = data.createTypedArray(AuthenticatorSpec.CREATOR);
            if (authenticators == null) return SKIP;
            
            if (securityLevel != null) {
                KeyMetadata response = (KeyMetadata) securityLevel.importWrappedKey(
                    ctx, key, wrappingKey, maskingKey, params, authenticators);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                reply.writeTypedObject(response, 0);
                return new OverrideReply(0, reply);
            }
            
        } catch (Exception e) {
            Logger.e("Import wrapped key error", e);
        }
        
        return SKIP;
    }
    
    private Result handleDeleteKey(Parcel data, CallerInfo ctx,
            int callingUid, int callingPid, IOhMySecurityLevel securityLevel) {
        try {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            
            KeyDescriptor key = data.readTypedObject(KeyDescriptor.CREATOR);
            if (key == null) return SKIP;
            
            if (securityLevel != null) {
                securityLevel.deleteKey(key);
                
                Parcel reply = Parcel.obtain();
                reply.writeNoException();
                return new OverrideReply(0, reply);
            }
            
        } catch (Exception e) {
            Logger.e("Delete key error", e);
        }
        
        return SKIP;
    }
    
    private boolean hasSigningPurpose(int[] purposes) {
        for (int purpose : purposes) {
            if (purpose == 2 || purpose == 7) { // SIGN or ATTEST_KEY
                return true;
            }
        }
        return false;
    }
    
    private KeyEntryResponse buildResponse(List<Certificate> chain,
            KeyGenParameters params, KeyDescriptor descriptor) {
        
        KeyEntryResponse response = new KeyEntryResponse();
        KeyMetadata metadata = new KeyMetadata();
        metadata.keySecurityLevel = level;
        
        try {
            CertificateUtils.putCertificateChain(metadata, chain.toArray(new Certificate[0]));
        } catch (Exception e) {
            Logger.e("Failed to put certificate chain", e);
        }
        
        KeyDescriptor d = new KeyDescriptor();
        d.domain = descriptor.domain;
        d.nspace = descriptor.nspace;
        metadata.key = d;
        
        List<Authorization> authorizations = new ArrayList<>();
        
        // Add purposes
        for (int purpose : params.getPurposes()) {
            Authorization auth = new Authorization();
            auth.keyParameter = new KeyParameter();
            auth.keyParameter.tag = Tag.PURPOSE;
            auth.keyParameter.value = KeyParameterValue.keyPurpose(purpose);
            auth.securityLevel = level;
            authorizations.add(auth);
        }
        
        // Add digests
        for (int digest : params.getDigests()) {
            Authorization auth = new Authorization();
            auth.keyParameter = new KeyParameter();
            auth.keyParameter.tag = Tag.DIGEST;
            auth.keyParameter.value = KeyParameterValue.digest(digest);
            auth.securityLevel = level;
            authorizations.add(auth);
        }
        
        // Add algorithm
        Authorization algoAuth = new Authorization();
        algoAuth.keyParameter = new KeyParameter();
        algoAuth.keyParameter.tag = Tag.ALGORITHM;
        algoAuth.keyParameter.value = KeyParameterValue.algorithm(params.getAlgorithm());
        algoAuth.securityLevel = level;
        authorizations.add(algoAuth);
        
        // Add key size
        Authorization sizeAuth = new Authorization();
        sizeAuth.keyParameter = new KeyParameter();
        sizeAuth.keyParameter.tag = Tag.KEY_SIZE;
        sizeAuth.keyParameter.value = KeyParameterValue.integer(params.getKeySize());
        sizeAuth.securityLevel = level;
        authorizations.add(sizeAuth);
        
        // Add EC curve for EC keys
        if (params.getAlgorithm() == Algorithm.EC) {
            Authorization curveAuth = new Authorization();
            curveAuth.keyParameter = new KeyParameter();
            curveAuth.keyParameter.tag = Tag.EC_CURVE;
            curveAuth.keyParameter.value = KeyParameterValue.ecCurve(params.getEcCurve());
            curveAuth.securityLevel = level;
            authorizations.add(curveAuth);
        }
        
        // Add no auth required
        if (params.isNoAuthRequired()) {
            Authorization noAuthAuth = new Authorization();
            noAuthAuth.keyParameter = new KeyParameter();
            noAuthAuth.keyParameter.tag = Tag.NO_AUTH_REQUIRED;
            noAuthAuth.keyParameter.value = KeyParameterValue.boolValue(true);
            noAuthAuth.securityLevel = level;
            authorizations.add(noAuthAuth);
        }
        
        metadata.authorizations = authorizations.toArray(new Authorization[0]);
        response.metadata = metadata;
        response.iSecurityLevel = original;
        
        return response;
    }
    
    /**
     * Implementation of IKeystoreOperation for signing operations.
     */
    private static class KeyStoreOperationImpl extends android.system.keystore2.IKeystoreOperation.Stub {
        
        private final Signature signature;
        private boolean isAborted = false;
        
        public KeyStoreOperationImpl(PrivateKey privateKey, String algorithm) throws Exception {
            Logger.d("KeyStoreOperation using algorithm " + algorithm + 
                    ", privateKey=" + privateKey.getAlgorithm());
            signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
        }
        
        @Override
        public void updateAad(byte[] aadInput) {
            Logger.d("updateAad called, ignored");
        }
        
        @Override
        public byte[] update(byte[] input) throws android.os.RemoteException {
            if (isAborted) {
                throw new IllegalStateException("Operation aborted");
            }
            Logger.d("update called with " + input.length + " bytes");
            try {
                signature.update(input);
            } catch (Exception e) {
                throw new android.os.RemoteException(e.getMessage());
            }
            return null;
        }
        
        @Override
        public byte[] finish(byte[] input, byte[] existingSignature) 
                throws android.os.RemoteException {
            if (isAborted) {
                throw new IllegalStateException("Operation aborted");
            }
            Logger.d("finish called with " + (input != null ? input.length : 0) + " bytes");
            try {
                if (input != null) {
                    signature.update(input);
                }
                return signature.sign();
            } catch (Exception e) {
                throw new android.os.RemoteException(e.getMessage());
            }
        }
        
        @Override
        public void abort() {
            Logger.d("abort called");
            isAborted = true;
        }
    }
}
