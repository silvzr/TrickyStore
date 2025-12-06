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

package io.github.a13e300.tricky_store.binder;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import io.github.a13e300.tricky_store.Logger;
import top.qwq2333.ohmykeymint.CallerInfo;

/**
 * Base class for intercepting Binder transactions.
 * 
 * Provides infrastructure for hooking into the Binder IPC mechanism
 * to intercept and modify keystore transactions.
 */
public class BinderInterceptor extends Binder {
    
    /**
     * Result of an interception operation.
     */
    public sealed interface Result permits Skip, Continue, OverrideData, OverrideReply {}
    
    /**
     * Skip this transaction - let it proceed normally.
     */
    public record Skip() implements Result {}
    
    /**
     * Continue processing this transaction.
     */
    public record Continue() implements Result {}
    
    /**
     * Override the transaction data.
     */
    public record OverrideData(Parcel data) implements Result {}
    
    /**
     * Override the transaction reply.
     */
    public record OverrideReply(int code, Parcel reply) implements Result {
        public OverrideReply(Parcel reply) {
            this(0, reply);
        }
    }
    
    // Singleton instances for common results
    public static final Skip SKIP = new Skip();
    public static final Continue CONTINUE = new Continue();
    
    /**
     * Gets the binder backdoor from a target binder.
     */
    public static IBinder getBinderBackdoor(IBinder target) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!target.transact(0xdeadbeef, data, reply, 0)) {
                Logger.d("BinderInterceptor: remote returned false");
                return null;
            }
            Logger.d("BinderInterceptor: remote returned true");
            return reply.readStrongBinder();
        } catch (RemoteException e) {
            Logger.e("BinderInterceptor: failed to get backdoor", e);
            return null;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
    
    /**
     * Registers a binder interceptor with the backdoor.
     */
    public static void registerBinderInterceptor(IBinder backdoor, IBinder target, 
            BinderInterceptor interceptor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeStrongBinder(target);
            data.writeStrongBinder(interceptor);
            backdoor.transact(1, data, reply, 0);
        } catch (RemoteException e) {
            Logger.e("BinderInterceptor: failed to register", e);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
    
    /**
     * Called before a transaction is processed.
     * Override to intercept pre-transaction.
     */
    public Result onPreTransact(IBinder target, int code, int flags, 
            CallerInfo ctx, Parcel data) {
        return SKIP;
    }
    
    /**
     * Called after a transaction is processed.
     * Override to intercept post-transaction.
     */
    public Result onPostTransact(IBinder target, int code, int flags,
            CallerInfo ctx, Parcel data, Parcel reply, int resultCode) {
        return SKIP;
    }
    
    @Override
    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) 
            throws RemoteException {
        
        Result result;
        
        switch (code) {
            case 1 -> { // PRE_TRANSACT
                IBinder target = data.readStrongBinder();
                int theCode = data.readInt();
                int theFlags = data.readInt();
                int callingUid = data.readInt();
                int callingPid = data.readInt();
                long sz = data.readLong();
                
                Parcel theData = Parcel.obtain();
                try {
                    theData.appendFrom(data, data.dataPosition(), (int) sz);
                    theData.setDataPosition(0);
                    
                    CallerInfo ctx = new CallerInfo();
                    ctx.callingUid = callingUid;
                    ctx.callingPid = callingPid;
                    ctx.callingSid = "reserved";
                    
                    result = onPreTransact(target, theCode, theFlags, ctx, theData);
                } finally {
                    theData.recycle();
                }
            }
            
            case 2 -> { // POST_TRANSACT
                IBinder target = data.readStrongBinder();
                int theCode = data.readInt();
                int theFlags = data.readInt();
                int callingUid = data.readInt();
                int callingPid = data.readInt();
                int resultCode = data.readInt();
                
                Parcel theData = Parcel.obtain();
                Parcel theReply = Parcel.obtain();
                try {
                    int sz = (int) data.readLong();
                    theData.appendFrom(data, data.dataPosition(), sz);
                    theData.setDataPosition(0);
                    data.setDataPosition(data.dataPosition() + sz);
                    
                    int sz2 = (int) data.readLong();
                    if (sz2 != 0) {
                        theReply.appendFrom(data, data.dataPosition(), sz2);
                        theReply.setDataPosition(0);
                    }
                    
                    CallerInfo ctx = new CallerInfo();
                    ctx.callingUid = callingUid;
                    ctx.callingPid = callingPid;
                    ctx.callingSid = "reserved";
                    
                    result = onPostTransact(target, theCode, theFlags, ctx, theData,
                            sz2 == 0 ? null : theReply, resultCode);
                } finally {
                    theData.recycle();
                    theReply.recycle();
                }
            }
            
            default -> {
                return super.onTransact(code, data, reply, flags);
            }
        }
        
        // Write result to reply
        if (reply != null) {
            switch (result) {
                case Skip s -> reply.writeInt(1);
                case Continue c -> reply.writeInt(2);
                case OverrideReply or -> {
                    reply.writeInt(3);
                    reply.writeInt(or.code());
                    reply.writeLong(or.reply().dataSize());
                    reply.appendFrom(or.reply(), 0, or.reply().dataSize());
                    or.reply().recycle();
                }
                case OverrideData od -> {
                    reply.writeInt(4);
                    reply.writeLong(od.data().dataSize());
                    reply.appendFrom(od.data(), 0, od.data().dataSize());
                    od.data().recycle();
                }
            }
        }
        
        return true;
    }
}
