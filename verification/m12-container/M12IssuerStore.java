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

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.oauth.server.*;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * App-owned finite volatile store, without durability or restore protection. Construction only retains
 * limits. The first operation owns a UTC/elapsed projection independent of the engine worker clock.
 * Reads, barriers and failed writes never reclaim retained state; capacity safely refuses until an
 * explicit admitted application lifecycle handles it. This local clock is not a qualified witness.
 */
final class M12IssuerStore implements OAuthAuthorizationServerStore {
    private final @NonNull ReentrantLock lock=new ReentrantLock();
    private @NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> entries=new LinkedHashMap<>();
    private @NonNull Set<@NonNull String> activatedScopes=new HashSet<>();
    private final int capacity;
    private final long maximumBytes;
    private @Nullable SecureRandom random;
    private @Nullable StoreAdmission admission;
    private @Nullable String clockGeneration;
    private @Nullable Instant anchor;
    private long anchorNanos;
    private long lastNanos;
    private boolean continuityLost;
    M12IssuerStore(int capacity,long maximumBytes) {
        if(capacity<2 || capacity>4096 || maximumBytes<1024 || maximumBytes>16_777_216) throw unavailable();
        this.capacity=capacity;this.maximumBytes=maximumBytes;
    }
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {
        Objects.requireNonNull(key);long started=System.nanoTime();long nanos=budgetNanos(budget);
        if(!acquire(nanos))return OAuthStoreReadResult.Unavailable.get();
        try {
            if(expired(started,nanos) || missingRoot(key))return OAuthStoreReadResult.Unavailable.get();
            StoreTimeObservation observation=observe();
            if(expired(started,nanos))return OAuthStoreReadResult.Unavailable.get();
            return OAuthStoreReadResult.Available.fromObservation(key,this.entries.get(key),observation);
        } catch(RuntimeException failure){return OAuthStoreReadResult.Unavailable.get();}
        finally {this.lock.unlock();}
    }
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget) {
        Objects.requireNonNull(transaction);long started=System.nanoTime();long nanos=budgetNanos(budget);
        if(!acquire(nanos))return refuse(OAuthStoreCommitStatus.UNAVAILABLE);
        try {
            if(expired(started,nanos) || missingRoot(transaction.getConditions().get(0).getKey()))return refuse(OAuthStoreCommitStatus.UNAVAILABLE);
            StoreAdmission current=operationalAdmission();
            if(!sameAdmission(current,transaction.getExpectedAdmission()))return refuse(OAuthStoreCommitStatus.FENCED);
            for(OAuthStoreTransaction.Condition condition:transaction.getConditions()) {
                OAuthStoreEntry existing=this.entries.get(condition.getKey());
                if(!condition.getExpectedVersion().equals(existing==null?Optional.empty():Optional.of(existing.getVersion()))) return refuse(OAuthStoreCommitStatus.CONFLICT);
            }
            OAuthStoreCommitReceipt committed;
            if(transaction.getPurpose()==OAuthStoreTransaction.Purpose.FENCE_ONLY)committed=OAuthStoreCommitReceipt.fromFenceAdmission(current);
            else {
                StoreTemporalCondition condition=transaction.getTemporalCondition().orElseThrow();
                if(!Objects.equals(this.clockGeneration,condition.getClockGeneration()))return refuse(OAuthStoreCommitStatus.FENCED);
                StoreTimeObservation sampled=observe();
                if(!(sampled instanceof StoreTimeObservation.Healthy validated))return refuse(OAuthStoreCommitStatus.TIME_UNAVAILABLE);
                if(validated.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return refuse(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR);
                if(condition.getValidBeforeExclusive().isPresent() && !validated.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))return refuse(OAuthStoreCommitStatus.TIME_EXPIRED);
                committed=OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated,null));
            }
            if(transaction.getMutations().isEmpty())return expired(started,nanos)?refuse(OAuthStoreCommitStatus.UNAVAILABLE):committed;
            Map<OAuthStoreKey,OAuthStoreEntry> next=new LinkedHashMap<>(this.entries);
            Set<String> nextActivated=new HashSet<>(this.activatedScopes);
            for(OAuthStoreTransaction.Mutation mutation:transaction.getMutations()) {
                if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE) {
                    // Engine operations never delete permanent issuer or subject fences.
                    if(permanent(mutation.getKey()))return refuse(OAuthStoreCommitStatus.CONFLICT);
                    next.remove(mutation.getKey());
                } else {
                    next.put(mutation.getKey(),mutation.getEntry().orElseThrow());
                    if(mutation.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE)nextActivated.add(scope(mutation.getKey()));
                }
            }
            if(next.size()>this.capacity || charged(next)>this.maximumBytes)return refuse(OAuthStoreCommitStatus.CAPACITY);
            if(expired(started,nanos))return refuse(OAuthStoreCommitStatus.UNAVAILABLE);
            this.entries=next;this.activatedScopes=nextActivated;
            // Assignment is known; expiry after it cannot erase COMMITTED.
            return committed;
        } catch(RuntimeException failure){return refuse(OAuthStoreCommitStatus.UNAVAILABLE);}
        finally {this.lock.unlock();}
    }
    private @NonNull StoreAdmission operationalAdmission(){
        StoreAdmission current=this.admission;
        if(current==null){current=StoreAdmission.fromIdentifiers(identity(),identity());this.clockGeneration=identity();this.admission=current;}
        return current;
    }
    private @NonNull StoreTimeObservation observe(){
        StoreAdmission current=operationalAdmission();Instant established=this.anchor;
        if(established==null && !this.continuityLost){
            long before=System.nanoTime();Instant captured=Instant.now();long after=System.nanoTime();
            long bracket=after-before;
            if(bracket<0 || bracket>250_000_000L || !supported(captured))this.continuityLost=true;
            else {this.anchor=captured;this.anchorNanos=after;this.lastNanos=after;established=captured;}
        }
        if(established==null || this.continuityLost)return StoreTimeObservation.Unavailable.fromAdmission(current);
        long now=System.nanoTime();
        try {
            long elapsed=Math.subtractExact(now,this.anchorNanos);long since=Math.subtractExact(now,this.lastNanos);
            if(elapsed<0 || since<0)throw unavailable();this.lastNanos=now;
            Instant point=established.plusNanos(elapsed);
            if(!supported(point))throw unavailable();
            return StoreTimeObservation.Healthy.fromObservation(current,Objects.requireNonNull(this.clockGeneration),point,Duration.ofMillis(250));
        } catch(RuntimeException failure){this.continuityLost=true;return StoreTimeObservation.Unavailable.fromAdmission(current);}
    }
    private @NonNull String identity(){
        SecureRandom source=this.random;if(source==null){source=new SecureRandom();this.random=source;}
        byte[] bytes=new byte[32];source.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private boolean missingRoot(@NonNull OAuthStoreKey key){
        String ns=scope(key);boolean data=false;
        for(OAuthStoreKey present:this.entries.keySet())if(scope(present).equals(ns)){
            if(present.getKind()==OAuthStoreKey.Kind.ISSUER_STATE)return false;data=true;
        }
        return data || this.activatedScopes.contains(ns);
    }
    private boolean acquire(long nanos) {
        if(nanos<=0 || Thread.currentThread().isInterrupted())return false;
        try {return this.lock.tryLock(nanos,TimeUnit.NANOSECONDS);}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();return false;}
    }
    private static long budgetNanos(@NonNull Duration budget){Objects.requireNonNull(budget);return budget.isNegative() || budget.isZero()?0:budget.compareTo(Duration.ofSeconds(30))>=0?30_000_000_000L:budget.toNanos();}
    private static boolean expired(long started,long budget){long elapsed=System.nanoTime()-started;return Thread.currentThread().isInterrupted() || elapsed<0 || elapsed>=budget;}
    private static boolean supported(@NonNull Instant time){return time.getEpochSecond()>=0 && time.getEpochSecond()<=253402300799L;}
    private static boolean sameAdmission(@NonNull StoreAdmission expected,@NonNull StoreAdmission actual){return expected.getAuthorityId().equals(actual.getAuthorityId()) && expected.getRecoveryGeneration().equals(actual.getRecoveryGeneration());}
    private static @NonNull String scope(@NonNull OAuthStoreKey key){return key.getStorageKey().split(":")[3];}
    private static boolean permanent(@NonNull OAuthStoreKey key){return key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE || key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE;}
    private static long charged(@NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> map) {
        long used=0;for(OAuthStoreEntry entry:map.values())used+=entry.getKey().getStorageKey().length()+entry.getVersion().length()+entry.toSealedForm().length()+128L;
        return used;
    }
    private static @NonNull OAuthStoreCommitReceipt refuse(@NonNull OAuthStoreCommitStatus status){return OAuthStoreCommitReceipt.fromRefusal(status);}
    private static @NonNull IllegalStateException unavailable(){return new IllegalStateException("Local issuer store unavailable.");}
}
