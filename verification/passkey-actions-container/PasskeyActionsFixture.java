/*
 * Copyright 2026 Revetware LLC.
 *
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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.json.*;
import com.revetsec.webauthn.*;
import com.revetsec.servlet.jakarta.ServletWebAuthn;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Public-core genuine WebAuthn/JCA inputs plus bounded local fault controls. Never deploy. */
@ThreadSafe
final class PasskeyActionsFixture {
    static final @NonNull String RP="login.example.com",ORIGIN="https://login.example.com",NAMESPACE="passkey-actions",OPERATOR="A".repeat(43);
    static final byte @NonNull [] ACCOUNT={4,5,6};
    final @NonNull AppClock clock=new AppClock();
    final @NonNull Gate gate=new Gate(this.clock);
    final @NonNull M12FaultStore store=new M12FaultStore(InMemoryWebAuthnStore.fromLimits(512,4_000_000L));
    final @NonNull PausingStore pausedStore=new PausingStore(this.store);
    final @NonNull WebAuthnRelyingParty rp;
    final @NonNull ServletPasskeyActionsRecipe application;
    final @NonNull Map<@NonNull String,@NonNull Authenticator> authenticators;
    final @NonNull AtomicReference<@NonNull String> writerMode=new AtomicReference<>("normal");
    final @NonNull AtomicBoolean writerObserved=new AtomicBoolean(),burnObservedWithoutClock=new AtomicBoolean(),interruptionObserved=new AtomicBoolean(),interruptNoGrant=new AtomicBoolean();
    final @NonNull AtomicInteger writerExceptions=new AtomicInteger(),writerAttempts=new AtomicInteger();
    final @NonNull AtomicReference<@Nullable Latch> writerLatch=new AtomicReference<>();
    PasskeyActionsFixture(){
        origin(WebAuthnRelyingParty.class,"CORE");origin(ServletWebAuthn.class,"ADAPTER");
        for(String absent:List.of("org.junit.jupiter.api.Test","org.jspecify.annotations.NonNull")){try{Class.forName(absent);throw new IllegalStateException("Runtime test/annotation dependency present");}catch(ClassNotFoundException expected){ }}
        this.authenticators=Map.of("one",new Authenticator(new byte[]{1,2,3},RP,ORIGIN,ACCOUNT),"two",new Authenticator(new byte[]{7,8,9},RP,ORIGIN,ACCOUNT));
        byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",Base64.getEncoder().encodeToString(bytes))).build();Arrays.fill(bytes,(byte)0);
        this.rp=WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Synthetic RP").allowedOrigins(Set.of(ORIGIN)).credentialNamespace(NAMESPACE).store(this.pausedStore).stateSealer(sealer).recoveryGate(this.gate).settings(WebAuthnSettings.builder().maximumResponseBodyBytes(65_536).build()).build();
        this.application=new ServletPasskeyActionsRecipe(ORIGIN,RP,OPERATOR,this.clock,ACCOUNT,NAMESPACE,this.rp,this.gate);
    }
    @NonNull JsonObject control(@NonNull String command){
        switch(command){
            case "deadline-wrap"->{long now=Long.MAX_VALUE-Duration.ofSeconds(90).toNanos();long session=now+Duration.ofMinutes(10).toNanos();return JsonObject.builder().put("duration",ServletPasskeyActionsRecipe.grantDeadline(session,now)-now).build();}case "state"->{}case "clock-expire-grant"->this.clock.offset.set(60);case "clock-expire-session"->this.clock.offset.set(600);case "clock-normal"->{this.clock.fail.set(false);this.clock.offset.set(0);}
            case "gate-deny"->this.gate.open.set(false);case "gate-allow"->this.gate.open.set(true);
            case "close-expire","close-clock-throw","close-interrupt","close-throw","close-stale","close-block","final-stale"->{if(!this.gate.mode.compareAndSet("normal",command))throw new IllegalStateException("Gate control already armed");}
            case "writer-throw","writer-runtime","writer-clock-throw","writer-block-throw"->{this.writerLatch.set(null);if(!this.writerMode.compareAndSet("normal",command))throw new IllegalStateException("Writer control already armed");}
            case "store-unknown"->this.store.arm("unknown");case "store-reconciliation"->this.store.arm("reconciliation");
            case "store-pause-completion"->this.pausedStore.pauseCompletion();case "store-block-reads"->this.pausedStore.blockReads();
            case "release"->{this.pausedStore.release();this.gate.release();Latch value=this.writerLatch.get();if(value!=null)value.release.countDown();}
            default->throw new IllegalArgumentException("Unknown fixture control");
        }
        return state();
    }
    @NonNull JsonObject state(){return JsonObject.builder().put("origin_verified",true).put("java_version",Objects.requireNonNull(System.getProperty("java.version"))).put("application",this.application.stateSnapshot()).put("raw",this.application.sessions.rawSnapshot()).put("store_effects",(long)this.store.effects()).put("store_final_reads",(long)this.store.finalReads()).put("writer_exceptions",this.writerExceptions.longValue()).put("writer_attempts",this.writerAttempts.longValue()).put("writer_observed",this.writerObserved.get()).put("burn_without_clock",this.burnObservedWithoutClock.get()).put("interruption_observed",this.interruptionObserved.get()).put("interrupt_no_grant",this.interruptNoGrant.get()).put("store_blocked",this.pausedStore.completionBlocked()).put("read_entered",(long)this.pausedStore.readEntered()).put("read_peak",(long)this.pausedStore.readPeak()).put("gate_blocked",this.gate.blocked()).put("writer_blocked",this.writerLatch.get()!=null&&Objects.requireNonNull(this.writerLatch.get()).entered.getCount()==0&&Objects.requireNonNull(this.writerLatch.get()).release.getCount()!=0).build();}
    @NonNull JsonObject mint(@NonNull String name,@NonNull String kind,@NonNull String challenge)throws Exception {
        Authenticator auth=Objects.requireNonNull(this.authenticators.get(name));if(!challenge.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("Fixture challenge shape");byte[] body=kind.equals("register")?auth.registration(challenge):kind.equals("assert")?auth.assertion(challenge):null;if(body==null)throw new IllegalArgumentException("Fixture kind");return JsonObject.builder().put("body",Base64.getEncoder().encodeToString(body)).put("credential_id",b64(auth.id)).build();
    }
    void observedWriterFailure(){this.writerExceptions.incrementAndGet();this.writerObserved.set(true);JsonObject raw=this.application.sessions.rawSnapshot();boolean empty=((JsonNumber)raw.getMembers().get("grants")).getValue().intValueExact()==0;this.burnObservedWithoutClock.set(empty);this.clock.fail.set(false);}
    void observedPostClose(){if(this.clock.fail.get()){JsonObject raw=this.application.sessions.rawSnapshot();this.burnObservedWithoutClock.set(((JsonNumber)raw.getMembers().get("grants")).getValue().intValueExact()==0);this.clock.fail.set(false);}if(this.gate.injectedInterrupt.getAndSet(false)){this.interruptionObserved.set(Thread.currentThread().isInterrupted());this.interruptNoGrant.set(((JsonNumber)this.application.sessions.rawSnapshot().getMembers().get("grants")).getValue().intValueExact()==0);Thread.interrupted();}}
    @NonNull JsonObject proofGuard(@NonNull String variant)throws Exception {
        if(!Set.of("valid","namespace","rp","account","purpose","ceremony","pending","foreign-owner").contains(variant))throw new IllegalArgumentException("Fixed proof fixture variant");
        String rpId=variant.equals("rp")?"other.example.com":RP,ns=variant.equals("namespace")?"other-namespace":NAMESPACE,purpose=variant.equals("purpose")?"other-purpose":"demo-sensitive-action";byte[] user=variant.equals("account")?new byte[]{8,8,8}:ACCOUNT;
        Authenticator auth=new Authenticator(new byte[]{11,12,13},rpId,"https://"+rpId,user);byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",Base64.getEncoder().encodeToString(bytes))).build();Arrays.fill(bytes,(byte)0);
        WebAuthnRelyingParty actual=WebAuthnRelyingParty.withRelyingPartyId(rpId).relyingPartyName("Actual foreign fixture").allowedOrigins(Set.of("https://"+rpId)).credentialNamespace(ns).store(InMemoryWebAuthnStore.fromLimits(64,1_000_000L)).stateSealer(sealer).recoveryGate(this.gate).build();
        var session=this.application.sessions.rotate(this.application.sessions.begin(),true);var binding=session.binding;
        WebAuthnRegistrationRequestResult start=actual.beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(user).userName("fixture").userDisplayName("Fixture").build(),binding);if(!(start instanceof WebAuthnRegistrationRequestResult.Prepared registration))throw new IllegalStateException("Genuine scope registration start");
        String challenge=((JsonString)registration.getRequest().getPublicKeyOptions().getMembers().get("challenge")).getValue();if(!(actual.completeRegistrationResult(registration.getRequest().getCeremonyId(),auth.registration(challenge),binding)instanceof WebAuthnRegistrationResult.Succeeded))throw new IllegalStateException("Genuine scope registration finish");
        WebAuthnAuthenticationRequestResult begun=actual.beginReauthenticationResult(user,purpose,binding);if(!(begun instanceof WebAuthnAuthenticationRequestResult.Prepared prepared))throw new IllegalStateException("Genuine scope request");String ceremony=prepared.getRequest().getCeremonyId();challenge=((JsonString)prepared.getRequest().getPublicKeyOptions().getMembers().get("challenge")).getValue();
        WebAuthnReauthenticationResult done=actual.completeReauthenticationResult(user,purpose,ceremony,auth.assertion(challenge),binding);if(!(done instanceof WebAuthnReauthenticationResult.Succeeded succeeded))throw new IllegalStateException("Genuine scope proof");
        if(!this.application.sessions.remember(session,ServletPasskeyActionsRecipe.Action.SENSITIVE,new byte[0],ceremony))throw new IllegalStateException("App pending preparation");var pending=this.application.sessions.pending(session,ServletPasskeyActionsRecipe.Action.SENSITIVE,ceremony).orElseThrow();
        if(variant.equals("ceremony")||variant.equals("pending")){this.application.sessions.remember(session,ServletPasskeyActionsRecipe.Action.SENSITIVE,new byte[0],"B".repeat(43));if(variant.equals("ceremony"))pending=this.application.sessions.pending(session,ServletPasskeyActionsRecipe.Action.SENSITIVE,"B".repeat(43)).orElseThrow();}
        var completed=this.application.sessions.complete(session,pending,succeeded.getReauthentication());boolean accepted=completed.isPresent(),foreignPreserved=false;if(variant.equals("foreign-owner")&&completed.isPresent()){new ServletPasskeyActionsRecipe.Sessions(this.clock,ACCOUNT,NAMESPACE,RP).burn(session,completed.orElseThrow());foreignPreserved=this.application.sessions.consume(session,ServletPasskeyActionsRecipe.Action.SENSITIVE,new byte[0]);}if(completed.isPresent())this.application.sessions.burn(session,completed.orElseThrow());return JsonObject.builder().put("accepted",accepted).put("genuine_core_proof",true).put("foreign_burn_preserved",foreignPreserved).put("variant",variant).build();
    }
    static @NonNull String b64(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static void origin(@NonNull Class<?> type,@NonNull String kind){try{Path expected=Path.of(Objects.requireNonNull(System.getenv("REVETSEC_PASSKEY_"+kind+"_JAR"))).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)));if(!actual.equals(expected)||!digest.equals(System.getenv("REVETSEC_PASSKEY_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact origin mismatch");}catch(Exception rejected){throw new IllegalStateException("Selected artifact origin mismatch");}}
    /** Delays only a genuine known commit after the backing monitor has been released. */
    static final class PausingStore implements WebAuthnStore {
        final @NonNull WebAuthnStore delegate;final @NonNull AtomicReference<@Nullable Latch> completion=new AtomicReference<>(),activeCompletion=new AtomicReference<>();final @NonNull AtomicReference<@Nullable ReadLatch> reads=new AtomicReference<>();
        PausingStore(@NonNull WebAuthnStore delegate){this.delegate=delegate;}
        void pauseCompletion(){this.activeCompletion.set(null);if(!this.completion.compareAndSet(null,new Latch()))throw new IllegalStateException("Completion already paused");}
        void blockReads(){if(!this.reads.compareAndSet(null,new ReadLatch()))throw new IllegalStateException("Reads already blocked");}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration remaining){long started=System.nanoTime();ReadLatch selected=this.reads.get();if(selected!=null)selected.waitHere();long left=remaining.toNanos()-(System.nanoTime()-started);return left<=0?WebAuthnStoreReadResult.Unavailable.get():this.delegate.read(keys,Duration.ofNanos(left));}
        @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration remaining){WebAuthnStoreCommitReceipt result=this.delegate.compareAndCommit(write,remaining);if(result.getStatus()==WebAuthnStoreCommitResult.COMMITTED&&write.getMutations().stream().anyMatch(m->m.getKey().getKind()==WebAuthnStoreKey.Kind.CEREMONY&&m.getKind()==WebAuthnStoreWrite.Mutation.Kind.REPLACE)){Latch selected=this.completion.getAndSet(null);if(selected!=null){this.activeCompletion.set(selected);selected.waitHere();}}return result;}
        boolean completionBlocked(){Latch selected=this.activeCompletion.get();return selected!=null&&selected.entered.getCount()==0&&selected.release.getCount()!=0;}
        int readEntered(){ReadLatch selected=this.reads.get();return selected==null?0:selected.entered.get();}int readPeak(){ReadLatch selected=this.reads.get();return selected==null?0:selected.peak.get();}
        void release(){Latch selected=this.activeCompletion.get();if(selected!=null)selected.release.countDown();ReadLatch blocked=this.reads.getAndSet(null);if(blocked!=null)blocked.release.countDown();}
    }
    static final class ReadLatch {
        final @NonNull CountDownLatch release=new CountDownLatch(1);final @NonNull AtomicInteger entered=new AtomicInteger(),active=new AtomicInteger(),peak=new AtomicInteger();
        void waitHere(){this.entered.incrementAndGet();int current=this.active.incrementAndGet();this.peak.accumulateAndGet(current,Math::max);try{if(!this.release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Bounded read latch expired");}catch(InterruptedException cancelled){Thread.currentThread().interrupt();throw new IllegalStateException("Read latch interrupted");}finally{this.active.decrementAndGet();}}
    }
    static final class AppClock extends Clock {
        final @NonNull AtomicLong offset=new AtomicLong();final @NonNull AtomicBoolean fail=new AtomicBoolean();
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException("UTC fixture only");return this;}
        @Override public @NonNull Instant instant(){if(this.fail.get())throw new IllegalStateException("Injected application clock outage");return Clock.systemUTC().instant().plusSeconds(this.offset.get());}
    }
    static final class Latch {final @NonNull CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);void waitHere(){this.entered.countDown();try{if(!this.release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Fixture latch timeout");}catch(InterruptedException cancelled){Thread.currentThread().interrupt();throw new IllegalStateException("Fixture interrupted");}}}
    static final class Gate implements WebAuthnRecoveryGate {
        final @NonNull ReentrantReadWriteLock lock=new ReentrantReadWriteLock(true);final @NonNull ThreadLocal<@NonNull Integer> depth=ThreadLocal.withInitial(()->0);final @NonNull AtomicBoolean open=new AtomicBoolean(true),injectedInterrupt=new AtomicBoolean();final @NonNull AtomicReference<@NonNull String> mode=new AtomicReference<>("normal");final @NonNull AtomicReference<@Nullable Latch> latch=new AtomicReference<>();final @NonNull AppClock clock;
        Gate(@NonNull AppClock clock){this.clock=clock;}
        @Override public @Nullable Permit acquire(@NonNull Duration remaining){if(remaining.isNegative()||remaining.isZero()||!this.open.get())return null;try{if(!this.lock.readLock().tryLock(remaining.toNanos(),TimeUnit.NANOSECONDS))return null;}catch(InterruptedException cancelled){Thread.currentThread().interrupt();return null;}this.depth.set(this.depth.get()+1);int nesting=this.depth.get();return new Permit(){private boolean closed;private int observations;@Override public @NonNull Boolean isCurrent(){String active=mode.get();if(nesting==1&&++this.observations==2&&active.equals("final-stale")&&mode.compareAndSet(active,"normal"))return false;return !this.closed&&open.get();}@Override public void close(){if(this.closed)throw new IllegalStateException("Permit closed twice");this.closed=true;try{if(nesting==1){String selected=mode.getAndSet("normal");switch(selected){case "close-expire"->clock.offset.set(60);case "close-clock-throw"->clock.fail.set(true);case "close-interrupt"->{injectedInterrupt.set(true);Thread.currentThread().interrupt();}case "close-throw"->throw new IllegalStateException("Injected gate close refusal");case "close-stale"->open.set(false);case "close-block"->{Latch paused=new Latch();latch.set(paused);paused.waitHere();}default->{}}}}finally{depth.set(depth.get()-1);lock.readLock().unlock();}}};}
        boolean blocked(){Latch value=this.latch.get();return value!=null&&value.entered.getCount()==0&&value.release.getCount()!=0;}
        void release(){Latch value=this.latch.get();if(value!=null)value.release.countDown();}
    }
    static final class Authenticator {
        final byte @NonNull [] id,handle;final @NonNull String rpId,origin;final @NonNull KeyPair pair;final @NonNull AtomicLong counter=new AtomicLong();
        Authenticator(byte @NonNull [] id,@NonNull String rpId,@NonNull String origin,byte @NonNull [] handle){this.id=id.clone();this.rpId=rpId;this.origin=origin;this.handle=handle.clone();try{this.pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture Ed25519 unavailable");}}
        byte @NonNull [] registration(@NonNull String challenge){byte[] auth=authData(true,0);String id=b64(this.id);return json("{\"id\":\""+id+"\",\"rawId\":\""+id+"\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""+b64(client("webauthn.create",challenge))+"\",\"authenticatorData\":\""+b64(auth)+"\",\"attestationObject\":\""+b64(attestation(auth))+"\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");}
        byte @NonNull [] assertion(@NonNull String challenge)throws GeneralSecurityException {byte[] auth=authData(false,this.counter.incrementAndGet()),client=client("webauthn.get",challenge);Signature signer=Signature.getInstance("Ed25519");signer.initSign(this.pair.getPrivate());signer.update(auth);signer.update(hash(client));String id=b64(this.id);return json("{\"id\":\""+id+"\",\"rawId\":\""+id+"\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""+b64(client)+"\",\"authenticatorData\":\""+b64(auth)+"\",\"signature\":\""+b64(signer.sign())+"\",\"userHandle\":\""+b64(this.handle)+"\"},\"clientExtensionResults\":{}}");}
        private byte @NonNull [] client(@NonNull String type,@NonNull String challenge){return json("{\"type\":\""+type+"\",\"challenge\":\""+challenge+"\",\"origin\":\""+this.origin+"\",\"crossOrigin\":false}");}
        private byte @NonNull [] authData(boolean registration,long counter){ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes(hash(this.rpId.getBytes(StandardCharsets.US_ASCII)));out.write(registration?0x45:0x05);out.write((int)(counter>>>24));out.write((int)(counter>>>16));out.write((int)(counter>>>8));out.write((int)counter);if(registration){out.writeBytes(new byte[16]);out.write(this.id.length>>>8);out.write(this.id.length);out.writeBytes(this.id);byte[] spki=this.pair.getPublic().getEncoded();out.write(0xa4);out.write(1);out.write(1);out.write(3);out.write(0x27);out.write(0x20);out.write(6);out.write(0x21);out.write(0x58);out.write(32);out.writeBytes(Arrays.copyOfRange(spki,spki.length-32,spki.length));}return out.toByteArray();}
        private static byte @NonNull [] attestation(byte @NonNull [] auth){ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(0xa3);text(out,"fmt");text(out,"none");text(out,"authData");bytes(out,auth);text(out,"attStmt");out.write(0xa0);return out.toByteArray();}
        private static void text(@NonNull ByteArrayOutputStream out,@NonNull String value){byte[] bytes=value.getBytes(StandardCharsets.US_ASCII);out.write(0x60|bytes.length);out.writeBytes(bytes);}
        private static void bytes(@NonNull ByteArrayOutputStream out,byte @NonNull [] bytes){if(bytes.length<24)out.write(0x40|bytes.length);else if(bytes.length<256){out.write(0x58);out.write(bytes.length);}else{out.write(0x59);out.write(bytes.length>>>8);out.write(bytes.length);}out.writeBytes(bytes);}
        private static byte @NonNull [] json(@NonNull String value){return value.getBytes(StandardCharsets.UTF_8);}
        private static byte @NonNull [] hash(byte @NonNull [] bytes){try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture hash unavailable");}}
        @Override public @NonNull String toString(){return "SyntheticAuthenticator{<redacted>}";}
    }
    @Override public @NonNull String toString(){return "PasskeyActionsFixture{<redacted>}";}
}
