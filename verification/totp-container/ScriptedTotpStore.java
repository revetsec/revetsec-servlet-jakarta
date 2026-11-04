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

import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreRecord;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreCommitReceipt;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeRules;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;

/**
 * Test-only independent authority plus atomic opaque TOTP store. The authority is
 * not a worker Clock, and no production store constructor receives this control.
 * All valid operational writes are genuine engine-generated transactions.
 */
@ThreadSafe
final class ScriptedTotpStore implements TotpStore {
	private final @NonNull String namespace;
	private @NonNull String epoch;
	private final @NonNull Map<@NonNull TotpStoreKey,@NonNull TotpStoreRecord> records = new HashMap<>();
	private final @NonNull Set<@NonNull String> epochHistory = new HashSet<>();
	private final int maximumEntries;
	private final long maximumBytes;
	private @NonNull StoreAdmission admission;
	private @NonNull String clockGeneration;
	private @NonNull Instant time;
	private boolean initialized;
	private @NonNull Instant lastPublished = Instant.EPOCH;
	private boolean healthy = true;
	private int clockSequence;

	ScriptedTotpStore(@NonNull String namespace,@NonNull String epoch,@NonNull Instant time) {
		this(namespace,epoch,time,65536,268435456L);
	}
	ScriptedTotpStore(@NonNull String namespace,@NonNull String epoch,@NonNull Instant time,
			int maximumEntries,long maximumBytes) {
		TotpStoreKey.forNamespace(namespace,epoch);
		if(maximumEntries<1 || maximumEntries>65536 || maximumBytes<1 || maximumBytes>268435456L)
			throw new IllegalArgumentException("Invalid test store capacity");
		this.namespace=namespace;this.epoch=epoch;this.time=time;
		this.maximumEntries=maximumEntries;this.maximumBytes=maximumBytes;
		this.epochHistory.add(epoch);
		this.admission=StoreAdmission.fromIdentifiers(identity("authority/"+namespace),identity("recovery/"+epoch));
		this.clockGeneration=identity("clock/"+namespace+"/0");
	}
	/** Explicit fixture inventory seed, not a normal store write or migration controller. */
	synchronized void seedClosedMigration(@NonNull List<@NonNull TotpStoreRecord> values) {
		if(this.initialized || !this.records.isEmpty())throw new IllegalStateException("Fixture seed must precede activation");
		Map<TotpStoreKey,TotpStoreRecord> candidate=new HashMap<>();
		for(TotpStoreRecord value:values) {
			if(!this.namespace.equals(value.getKey().getCredentialNamespace()) || !this.epoch.equals(value.getKey().getRecoveryEpoch())
					|| candidate.put(value.getKey(),value)!=null)throw new IllegalArgumentException("Invalid fixture inventory");
		}
		this.records.putAll(candidate);
		this.initialized=this.records.containsKey(TotpStoreKey.forNamespace(this.namespace,this.epoch));
	}
	synchronized @NonNull Instant authorityTime() {return this.time;}
	synchronized void advance(@NonNull Duration duration) {this.time=this.time.plus(duration);}
	synchronized void setTime(@NonNull Instant value) {this.time=value;}
	synchronized void setHealthy(boolean value) {this.healthy=value;}
	synchronized void rotateClockGeneration() {this.clockGeneration=identity("clock/"+this.namespace+'/'+(++this.clockSequence));}
	synchronized @NonNull StoreAdmission admission() {return this.admission;}
	synchronized @NonNull String clockGeneration() {return this.clockGeneration;}
	synchronized @NonNull TotpStoreCommitResult provisionRecoveryEpoch(@NonNull String next,@NonNull Duration budget) {
		TotpStoreKey.forNamespace(this.namespace,next);
		if(badBudget(budget))return TotpStoreCommitResult.UNAVAILABLE;
		if(this.epochHistory.contains(next) || this.epochHistory.size()>=65536)
			throw new IllegalArgumentException("Test recovery epoch cannot be reused");
		this.epochHistory.add(next);this.epoch=next;this.initialized=false;
		this.admission=StoreAdmission.fromIdentifiers(this.admission.getAuthorityId(),identity("recovery/"+next));
		return TotpStoreCommitResult.COMMITTED;
	}
	@Override public synchronized @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,
			@NonNull Duration budget) {
		if(badBudget(budget))return TotpStoreReadResult.Unavailable.get();
		if(keys.isEmpty() || keys.size()>16)throw new IllegalArgumentException("Test snapshot bound");
		for(TotpStoreKey key:keys)
			if(!this.namespace.equals(key.getCredentialNamespace()) || !this.epoch.equals(key.getRecoveryEpoch()))
				return TotpStoreReadResult.Fenced.get();
		Map<TotpStoreKey,TotpStoreEntry> entries=new HashMap<>();
		for(TotpStoreKey key:keys) {
			TotpStoreRecord record=this.records.get(key);
			entries.put(key,record==null?TotpStoreEntry.Absent.confirmed():TotpStoreEntry.Present.fromRecord(record));
		}
		StoreTimeObservation observation=timeAvailable()?observation():StoreTimeObservation.Unavailable.fromAdmission(this.admission);
		return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(keys,entries,observation));
	}
	@Override public synchronized @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,
			@NonNull Duration budget) {
		if(badBudget(budget))return refuse(TotpStoreCommitResult.UNAVAILABLE);
		StoreTemporalCondition condition=write.getTemporalCondition();
		if(!this.namespace.equals(write.getCredentialNamespace()) || !this.epoch.equals(write.getRecoveryEpoch())
				|| !StoreTimeRules.sameAdmission(this.admission,condition.getAdmission())
				|| !this.clockGeneration.equals(condition.getClockGeneration()))return refuse(TotpStoreCommitResult.FENCED);
		if(write.getPurpose()==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE && this.initialized)
			return refuse(TotpStoreCommitResult.FENCED);
		if(write.getPurpose()==TotpStoreWrite.Purpose.UPDATE && !this.initialized)return refuse(TotpStoreCommitResult.FENCED);
		for(Map.Entry<TotpStoreKey,TotpStoreEntry> expected:write.getSnapshot().getEntries().entrySet()) {
			TotpStoreRecord actual=this.records.get(expected.getKey());
			if(expected.getValue() instanceof TotpStoreEntry.Absent ? actual!=null
					:actual==null || !((TotpStoreEntry.Present)expected.getValue()).getRecord().getVersion().equals(actual.getVersion()))
				return refuse(TotpStoreCommitResult.CONFLICT);
		}
		if(!timeAvailable())return refuse(TotpStoreCommitResult.TIME_UNAVAILABLE);
		StoreTimeObservation.Healthy validated=observation();
		if(validated.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return refuse(TotpStoreCommitResult.TIME_BEFORE_FLOOR);
		if(condition.getValidBeforeExclusive().isPresent() && !validated.getObservedAt().isBefore(condition.getValidBeforeExclusive().get()))
			return refuse(TotpStoreCommitResult.TIME_EXPIRED);
		Map<TotpStoreKey,TotpStoreRecord> projected=new HashMap<>(this.records);
		for(TotpStoreWrite.Mutation mutation:write.getMutations())projected.put(mutation.getKey(),mutation.getRecord());
		long bytes=0;
		for(TotpStoreRecord record:projected.values())bytes+=record.getSealedBytes().length;
		if(projected.size()>this.maximumEntries || bytes>this.maximumBytes)return refuse(TotpStoreCommitResult.CAPACITY_REFUSED);
		this.records.clear();this.records.putAll(projected);
		if(write.getPurpose()==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE)this.initialized=true;
		return TotpStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated,null));
	}
	private boolean timeAvailable() {return this.healthy && !this.time.isBefore(this.lastPublished);}
	private StoreTimeObservation.@NonNull Healthy observation() {
		this.lastPublished=this.time;
		return StoreTimeObservation.Healthy.fromObservation(this.admission,this.clockGeneration,this.time,Duration.ZERO);
	}
	private static @NonNull TotpStoreCommitReceipt refuse(@NonNull TotpStoreCommitResult status) {
		return TotpStoreCommitReceipt.fromRefusal(status);
	}
	private static boolean badBudget(@NonNull Duration budget) {
		return budget.isNegative() || budget.isZero() || Thread.currentThread().isInterrupted();
	}
	private static @NonNull String identity(@NonNull String value) {
		try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
		catch(NoSuchAlgorithmException unavailable){throw new IllegalStateException("Required test digest unavailable",unavailable);}
	}
}
