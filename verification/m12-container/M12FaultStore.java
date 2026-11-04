/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package example;

import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;

/** Private transport fault controls around genuine engine-generated writes, never a proof factory. */
@ThreadSafe
final class M12FaultStore implements WebAuthnStore {
    private enum Fault { NONE, RECONCILIATION, UNKNOWN }
    private final @NonNull WebAuthnStore delegate;
    private final @NonNull AtomicReference<@NonNull Fault> armed = new AtomicReference<>(Fault.NONE);
    private final @NonNull AtomicBoolean failFinalRead = new AtomicBoolean();
    private final @NonNull AtomicInteger effects = new AtomicInteger();
    private final @NonNull AtomicInteger finalReads = new AtomicInteger();

    M12FaultStore(@NonNull WebAuthnStore delegate) { this.delegate = Objects.requireNonNull(delegate); }

    void arm(@NonNull String mode) {
        Fault selected = switch (mode) {
            case "reconciliation" -> Fault.RECONCILIATION;
            case "unknown" -> Fault.UNKNOWN;
            default -> throw new IllegalArgumentException("Invalid fixture fault");
        };
        if (this.failFinalRead.get() || !this.armed.compareAndSet(Fault.NONE, selected))
            throw new IllegalStateException("Fixture fault already armed");
    }

    int effects() { return this.effects.get(); }
    int finalReads() { return this.finalReads.get(); }

    @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
            @NonNull Duration budget) {
        if (this.failFinalRead.getAndSet(false)) {
            if (keys.size() != 1 || keys.iterator().next().getKind() != WebAuthnStoreKey.Kind.NAMESPACE_CLOCK)
                throw new AssertionError("Expected the minimum final root read");
            this.finalReads.incrementAndGet();
            return WebAuthnStoreReadResult.Unavailable.get();
        }
        return this.delegate.read(keys, budget);
    }

    @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,
            @NonNull Duration budget) {
        long started = System.nanoTime();
        WebAuthnStoreCommitReceipt receipt = this.delegate.compareAndCommit(write, budget);
        if (receipt.getStatus() != WebAuthnStoreCommitResult.COMMITTED || write.getMutations().isEmpty()) return receipt;
        Fault fault = Objects.requireNonNull(this.armed.getAndSet(Fault.NONE));
        if (fault == Fault.NONE) return receipt;
        // Inspect the private backing store directly, before injecting any response fault. This
        // verifies the committed ceremony bytes/version against the genuine proposed mutation.
        int consumed = 0;
        for (WebAuthnStoreWrite.Mutation mutation : write.getMutations()) {
            if (mutation.getKey().getKind() != WebAuthnStoreKey.Kind.CEREMONY) continue;
            if (mutation.getKind() != WebAuthnStoreWrite.Mutation.Kind.REPLACE)
                throw new AssertionError("Fault requires a genuine completion transition");
            long remaining = budget.toNanos() - (System.nanoTime() - started);
            if (remaining <= 0) throw new AssertionError("Fixture observation budget exhausted");
            WebAuthnStoreReadResult raw = this.delegate.read(Set.of(mutation.getKey()), Duration.ofNanos(remaining));
            if (!(raw instanceof WebAuthnStoreReadResult.Available available)
                    || !(available.getSnapshot().getEntry(mutation.getKey()) instanceof WebAuthnStoreEntry.Present actual)
                    || !(write.getSnapshot().getEntry(mutation.getKey()) instanceof WebAuthnStoreEntry.Present prior)
                    || Arrays.equals(actual.getVersion(), prior.getVersion())
                    || !Arrays.equals(actual.getSealedBytes(), mutation.getSealedBytes().orElseThrow()))
                throw new AssertionError("Committed ceremony state was not observed");
            consumed++;
        }
        if (consumed != 1) throw new AssertionError("Expected one committed ceremony consumption");
        this.effects.incrementAndGet();
        if (fault == Fault.RECONCILIATION) { this.failFinalRead.set(true); return receipt; }
        return WebAuthnStoreCommitReceipt.unknownInstance();
    }
}
