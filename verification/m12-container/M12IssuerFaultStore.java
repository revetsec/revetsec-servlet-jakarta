/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example;

import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthStoreCommitReceipt;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;

/** Private fixture-only faults after genuine committed authorization-code consumption. */
final class M12IssuerFaultStore implements OAuthAuthorizationServerStore {
    private final @NonNull OAuthAuthorizationServerStore delegate;
    private @NonNull String mode="none";
    private boolean refuseFinalRead;
    private int effects;
    private int finalReads;
    private @Nullable OAuthStoreKey consumedKey;
    private @Nullable String consumedVersion;
    M12IssuerFaultStore(@NonNull OAuthAuthorizationServerStore delegate){this.delegate=delegate;}
    synchronized void arm(@NonNull String value){
        if(!value.equals("confirmed") && !value.equals("unknown"))throw new IllegalArgumentException("Invalid fixture mode");
        this.mode=value;
    }
    synchronized int effects(){return this.effects;}
    synchronized int finalReads(){return this.finalReads;}
    synchronized boolean backingVersionChanged(){
        OAuthStoreKey key=this.consumedKey;String version=this.consumedVersion;
        if(key==null || version==null)return false;
        OAuthStoreReadResult read=this.delegate.read(key,Duration.ofSeconds(1));
        return read instanceof OAuthStoreReadResult.Available available && available.getEntry().isPresent()
                && version.equals(available.getEntry().orElseThrow().getVersion());
    }
    @Override public synchronized @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
        if(this.refuseFinalRead){
            this.refuseFinalRead=false;this.finalReads++;
            if(key.getKind()!=OAuthStoreKey.Kind.ISSUER_STATE)throw new IllegalStateException("Expected minimum issuer-root checkpoint");
            return OAuthStoreReadResult.Unavailable.get();
        }
        return this.delegate.read(key,budget);
    }
    @Override public synchronized @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){
        OAuthStoreCommitReceipt receipt=this.delegate.commit(transaction,budget);
        boolean code=false,access=false;
        for(var mutation:transaction.getMutations()){
            if(mutation.getKey().getKind()==OAuthStoreKey.Kind.CODE)code=true;
            if(mutation.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN)access=true;
        }
        if(receipt.getStatus()==OAuthStoreCommitStatus.COMMITTED && code && access && !this.mode.equals("none")){
            this.effects++;
            for(var mutation:transaction.getMutations())if(mutation.getKey().getKind()==OAuthStoreKey.Kind.CODE){
                this.consumedKey=mutation.getKey();this.consumedVersion=mutation.getEntry().orElseThrow().getVersion();
            }
            String selected=this.mode;this.mode="none";
            if(selected.equals("unknown"))return OAuthStoreCommitReceipt.unknownInstance();
            this.refuseFinalRead=true;
        }
        return receipt;
    }
}
