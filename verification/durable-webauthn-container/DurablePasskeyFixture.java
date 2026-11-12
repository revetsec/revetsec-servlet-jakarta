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

import com.revetsec.*;
import com.revetsec.json.*;
import com.revetsec.webauthn.*;
import com.revetsec.servlet.jakarta.ServletWebAuthn;
import example.pending.PostgresqlWebAuthnStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.lang.reflect.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Synthetic keys, scripted time and legal JDBC commit faults around the unchanged application. */
@ThreadSafe
public final class DurablePasskeyFixture {
    static final @NonNull String RP="login.example.com",ORIGIN="https://login.example.com",NAMESPACE="servlet_webauthn",OPERATOR="A".repeat(43);
    static final byte @NonNull [] ACCOUNT={4,5,6};
    static final @NonNull Instant START=Instant.parse("2026-11-05T12:00:00Z");
    final @NonNull ServletPasskeyActionsRecipe application;
    final @NonNull WebAuthnRelyingParty rp;
    final @NonNull Map<@NonNull String,@NonNull Authenticator> authenticators;
    private final @NonNull AtomicBoolean authorityAvailable=new AtomicBoolean(true),gateOpen=new AtomicBoolean(true);
    private final @NonNull AtomicReference<@NonNull String> fault=new AtomicReference<>("normal");
    private final @NonNull AtomicInteger observations=new AtomicInteger(),connections=new AtomicInteger(),commits=new AtomicInteger(),appliedCommits=new AtomicInteger(),unknownFaults=new AtomicInteger(),knownFaults=new AtomicInteger(),openRefusals=new AtomicInteger();
    private final @NonNull AtomicReference<@Nullable Pause> paused=new AtomicReference<>();
    DurablePasskeyFixture()throws Exception {
        origin(WebAuthnRelyingParty.class,"CORE");origin(ServletWebAuthn.class,"ADAPTER");origin(PostgresqlWebAuthnStore.class,"STORE");origin(com.pyranid.Database.class,"PYRANID");origin(org.postgresql.Driver.class,"DRIVER");
        for(String absent:List.of("org.junit.jupiter.api.Test","org.jspecify.annotations.NonNull","org.checkerframework.checker.nullness.qual.Nullable")){try{Class.forName(absent);throw new IllegalStateException("Runtime test/annotation dependency present");}catch(ClassNotFoundException expected){ }}
        Path directory=Path.of(required("REVETSEC_DURABLE_SECRETS"));KeyFactory factory=KeyFactory.getInstance("Ed25519");Map<String,Authenticator> selected=new LinkedHashMap<>();
        int index=0;for(String name:List.of("one","two")){KeyPair pair=new KeyPair(factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(directory.resolve(name+"-public.der")))),factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve(name+"-private.der")))));selected.put(name,new Authenticator(index++==0?new byte[]{1,2,3}:new byte[]{7,8,9},pair,directory.resolve(name+"-counter.txt")));}this.authenticators=Map.copyOf(selected);
        String secret=Files.readString(directory.resolve("sealer.txt"),StandardCharsets.US_ASCII);Clock worker=Clock.fixed(Instant.ofEpochSecond(Long.parseLong(required("REVETSEC_TEST_WA_WORKER_NOW"))),ZoneOffset.UTC);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",secret)).clock(worker).build();
        WebAuthnRecoveryGate gate=new RecoveryGate(directory.resolve("marker.txt"),directory.resolve("gate.lock"));
        WebAuthnRelyingParty.Builder configured=WebAuthnFixtureWorker.configure(WebAuthnRelyingParty.withRelyingPartyId(RP)).relyingPartyName("Synthetic durable RP").allowedOrigins(Set.of(ORIGIN)).settings(WebAuthnSettings.builder().maximumResponseBodyBytes(65_536).build());
        this.rp=ServletDurableBackendRecipe.withWebAuthnStore(configured,NAMESPACE,identity("webauthn-physical/"+NAMESPACE),this::connection,4096,this::observe,sealer,gate).build();
        this.application=new ServletPasskeyActionsRecipe(ORIGIN,RP,OPERATOR,worker,ACCOUNT,NAMESPACE,this.rp,gate);
    }
    private @NonNull StoreTimeObservation observe(@NonNull String physical,@NonNull Duration remaining){if(!physical.equals(identity("webauthn-physical/"+NAMESPACE))||remaining.isNegative()||remaining.isZero()||Thread.currentThread().isInterrupted())throw new IllegalStateException("Scripted authority unavailable");this.observations.incrementAndGet();StoreAdmission admitted=StoreAdmission.fromIdentifiers(identity("webauthn-authority/"+NAMESPACE),identity("webauthn-recovery/"+NAMESPACE));return this.authorityAvailable.get()?StoreTimeObservation.Healthy.fromObservation(admitted,identity("webauthn-clock/"+NAMESPACE),Instant.ofEpochSecond(Long.parseLong(required("REVETSEC_TEST_WA_AUTHORITY_NOW"))),Duration.ZERO):StoreTimeObservation.Unavailable.fromAdmission(admitted);}
    private @NonNull Connection connection(@NonNull Duration remaining)throws SQLException {
        if(remaining.isNegative()||remaining.isZero()||Thread.currentThread().isInterrupted())throw new SQLException("Original connection budget exhausted");if(this.fault.get().equals("open-unavailable")){this.openRefusals.incrementAndGet();throw new SQLException("Injected sustained connection refusal");}
        int seconds=Math.max(1,(int)Math.min(3,(remaining.toMillis()+999)/1000));Properties properties=new Properties();properties.setProperty("user",required("REVETSEC_DURABLE_DB_USER"));properties.setProperty("password",required("REVETSEC_DURABLE_DB_PASSWORD"));properties.setProperty("connectTimeout",Integer.toString(seconds));properties.setProperty("socketTimeout",Integer.toString(seconds));properties.setProperty("gssEncMode","disable");Connection actual=DriverManager.getConnection(required("REVETSEC_DURABLE_DB_URL"),properties);this.connections.incrementAndGet();AtomicBoolean wrote=new AtomicBoolean();
        return(Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            if(method.getName().equals("commit")&&wrote.get()){
                this.commits.incrementAndGet();String selected=this.fault.getAndSet("normal");if(selected.equals("unknown-before")){this.unknownFaults.incrementAndGet();throw new SQLException("Injected uncertainty before actual commit");}actual.commit();this.appliedCommits.incrementAndGet();if(selected.equals("unknown-after")){this.unknownFaults.incrementAndGet();throw new SQLException("Injected lost acknowledgement after actual commit");}if(selected.equals("known-after")){this.knownFaults.incrementAndGet();this.authorityAvailable.set(false);}if(selected.equals("pause-after")){Pause pause=new Pause();this.paused.set(pause);pause.await();}return null;
            }
            try{Object value=method.invoke(actual,args);if(method.getName().equals("prepareStatement")&&args!=null&&args[0]instanceof String sql&&value instanceof PreparedStatement statement){boolean mutation=sql.stripLeading().matches("(?is)^(INSERT|UPDATE|DELETE).*");return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{try{Object result=m.invoke(statement,a);if(mutation&&Set.of("execute","executeUpdate","executeLargeUpdate","executeBatch","executeLargeBatch").contains(m.getName()))wrote.set(true);return result;}catch(InvocationTargetException failure){throw failure.getCause();}});}return value;}catch(InvocationTargetException failure){throw failure.getCause();}
        });
    }
    @NonNull JsonObject control(@NonNull String command){switch(command){case"state"->{}case"authority-unavailable"->this.authorityAvailable.set(false);case"authority-healthy"->this.authorityAvailable.set(true);case"gate-deny"->this.gateOpen.set(false);case"gate-allow"->this.gateOpen.set(true);case"release"->{Pause pause=this.paused.get();if(pause!=null)pause.release.countDown();}case"unknown-before","unknown-after","known-after","open-unavailable","pause-after"->{if(!this.fault.compareAndSet("normal",command))throw new IllegalStateException("Fault already armed");}case"connections-healthy"->{String current=this.fault.get();if(!current.equals("open-unavailable")||!this.fault.compareAndSet(current,"normal"))throw new IllegalStateException("No connection outage");}default->throw new IllegalArgumentException("Fixed fixture command");}return state();}
    @NonNull JsonObject state(){Pause pause=this.paused.get();return JsonObject.builder().put("origins_verified",true).put("java_version",Objects.requireNonNull(System.getProperty("java.version"))).put("application",this.application.stateSnapshot()).put("connections",this.connections.longValue()).put("authority_observations",this.observations.longValue()).put("commit_attempts",this.commits.longValue()).put("actual_applied_commits",this.appliedCommits.longValue()).put("unknown_faults",this.unknownFaults.longValue()).put("known_faults",this.knownFaults.longValue()).put("open_refusals",this.openRefusals.longValue()).put("commit_paused",pause!=null&&pause.entered.getCount()==0&&pause.release.getCount()!=0).build();}
    @NonNull JsonObject mint(@NonNull String name,@NonNull String kind,@NonNull String challenge)throws GeneralSecurityException {if(!challenge.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("Fixed challenge");Authenticator auth=Objects.requireNonNull(this.authenticators.get(name));byte[] body=kind.equals("register")?auth.registration(challenge):kind.equals("assert")?auth.assertion(challenge):null;if(body==null)throw new IllegalArgumentException("Fixed kind");return JsonObject.builder().put("body",Base64.getEncoder().encodeToString(body)).put("credential_id",b64(auth.id)).build();}
    static @NonNull String b64(byte @NonNull [] value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value);}
    static @NonNull String identity(@NonNull String value){try{return b64(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(GeneralSecurityException failure){throw new IllegalStateException("Required digest unavailable");}}
    static @NonNull String required(@NonNull String name){return Objects.requireNonNull(System.getenv(name));}
    private static void origin(@NonNull Class<?> type,@NonNull String kind)throws Exception{Path selected=Path.of(required("REVETSEC_DURABLE_"+kind+"_JAR")).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();if(!selected.equals(actual)||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(required("REVETSEC_DURABLE_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact origin mismatch");}
    static final class Pause {final @NonNull CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);void await(){this.entered.countDown();try{if(!this.release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Bounded actual-commit pause expired");}catch(InterruptedException cancelled){Thread.currentThread().interrupt();throw new IllegalStateException("Fixture cancelled");}}}
    /** One-host external file barrier, separate from PostgreSQL shared-clock admission; no fleet claim. */
    final class RecoveryGate implements WebAuthnRecoveryGate {
        final @NonNull Path marker,lock;final @NonNull String expectedEpoch=required("REVETSEC_DURABLE_EXPECTED_EPOCH"),expectedDigest=required("REVETSEC_DURABLE_SEALER_DIGEST");final @NonNull ThreadLocal<@Nullable Active> active=new ThreadLocal<>();
        RecoveryGate(@NonNull Path marker,@NonNull Path lock){this.marker=marker;this.lock=lock;}
        @Override public @Nullable Permit acquire(@NonNull Duration remaining){if(remaining.isZero()||remaining.isNegative()||Thread.currentThread().isInterrupted())return null;Active existing=this.active.get();if(existing!=null){if(!existing.isCurrent())return null;existing.depth++;return existing;}long deadline=System.nanoTime()+remaining.toNanos();FileChannel channel=null;FileLock held=null;try{channel=FileChannel.open(this.lock,StandardOpenOption.READ,StandardOpenOption.WRITE);held=channel.tryLock(0,Long.MAX_VALUE,true);if(held==null||!current(deadline))return null;Active admitted=new Active(channel,held,deadline);this.active.set(admitted);channel=null;held=null;return admitted;}catch(IOException|RuntimeException failure){return null;}finally{if(held!=null)try{held.release();}catch(IOException ignored){}if(channel!=null)try{channel.close();}catch(IOException ignored){}}}
        boolean current(long deadline){if(!gateOpen.get()||Thread.currentThread().isInterrupted()||System.nanoTime()-deadline>=0)return false;try{if(Files.size(this.marker)>200||!Files.readString(this.marker,StandardCharsets.US_ASCII).equals(this.expectedEpoch+"\n"+this.expectedDigest+"\n"))return false;try(Connection connection=connection(Duration.ofNanos(deadline-System.nanoTime()));PreparedStatement statement=connection.prepareStatement("SELECT epoch,sealer_digest FROM webauthn_recovery_epoch WHERE namespace=?")){statement.setString(1,NAMESPACE);statement.setQueryTimeout(1);try(ResultSet rows=statement.executeQuery()){return rows.next()&&this.expectedEpoch.equals(rows.getString(1))&&this.expectedDigest.equals(rows.getString(2))&&System.nanoTime()-deadline<0;}}}catch(IOException|SQLException|RuntimeException unavailable){return false;}}
        final class Active implements Permit {final @NonNull FileChannel channel;final @NonNull FileLock held;final long deadline;int depth=1;boolean closed;Active(@NonNull FileChannel channel,@NonNull FileLock held,long deadline){this.channel=channel;this.held=held;this.deadline=deadline;}@Override public @NonNull Boolean isCurrent(){return !this.closed&&this.held.isValid()&&current(this.deadline);}@Override public void close(){if(this.closed)return;if(--this.depth>0)return;this.closed=true;active.remove();try{this.held.release();}catch(IOException failure){throw new IllegalStateException("Fixture barrier release refused");}finally{try{this.channel.close();}catch(IOException failure){throw new IllegalStateException("Fixture barrier close refused");}}}}
    }
    public static void main(@NonNull String @NonNull [] args)throws Exception{if(args.length!=2||!args[0].equals("keygen"))throw new IllegalArgumentException("Owned fixture key preparation only");Path directory=Path.of(args[1]);KeyPairGenerator generator=KeyPairGenerator.getInstance("Ed25519");for(String name:List.of("one","two")){KeyPair pair=generator.generateKeyPair();Files.write(directory.resolve(name+"-private.der"),pair.getPrivate().getEncoded());Files.write(directory.resolve(name+"-public.der"),pair.getPublic().getEncoded());}byte[] secret=new byte[32];new SecureRandom().nextBytes(secret);Files.writeString(directory.resolve("sealer.txt"),Base64.getEncoder().encodeToString(secret),StandardCharsets.US_ASCII);Arrays.fill(secret,(byte)0);Files.write(directory.resolve("gate.lock"),new byte[0]);}
    static final class Authenticator {
        final byte @NonNull [] id,handle;final @NonNull String rpId,origin;final @NonNull KeyPair pair;final @NonNull Path counterPath;final @NonNull AtomicLong counter=new AtomicLong();
        Authenticator(byte @NonNull [] id,@NonNull KeyPair pair,@NonNull Path counterPath)throws IOException{this.counterPath=counterPath;if(Files.exists(counterPath))this.counter.set(Long.parseLong(Files.readString(counterPath,StandardCharsets.US_ASCII)));this.id=id.clone();this.rpId=RP;this.origin=ORIGIN;this.handle=ACCOUNT.clone();this.pair=pair;}

        byte @NonNull [] registration(@NonNull String challenge){byte[] auth=authData(true,0);String id=b64(this.id);return json("{\"id\":\""+id+"\",\"rawId\":\""+id+"\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""+b64(client("webauthn.create",challenge))+"\",\"authenticatorData\":\""+b64(auth)+"\",\"attestationObject\":\""+b64(attestation(auth))+"\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");}
        byte @NonNull [] assertion(@NonNull String challenge)throws GeneralSecurityException {byte[] auth=authData(false,nextCounter()),client=client("webauthn.get",challenge);Signature signer=Signature.getInstance("Ed25519");signer.initSign(this.pair.getPrivate());signer.update(auth);signer.update(hash(client));String id=b64(this.id);return json("{\"id\":\""+id+"\",\"rawId\":\""+id+"\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""+b64(client)+"\",\"authenticatorData\":\""+b64(auth)+"\",\"signature\":\""+b64(signer.sign())+"\",\"userHandle\":\""+b64(this.handle)+"\"},\"clientExtensionResults\":{}}");}
        private synchronized long nextCounter(){long value=this.counter.incrementAndGet();try{Files.writeString(this.counterPath,Long.toString(value),StandardCharsets.US_ASCII);}catch(IOException failure){throw new IllegalStateException("Synthetic authenticator counter persistence refused");}return value;}
        private byte @NonNull [] client(@NonNull String type,@NonNull String challenge){return json("{\"type\":\""+type+"\",\"challenge\":\""+challenge+"\",\"origin\":\""+this.origin+"\",\"crossOrigin\":false}");}
        private byte @NonNull [] authData(boolean registration,long counter){ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes(hash(this.rpId.getBytes(StandardCharsets.US_ASCII)));out.write(registration?0x45:0x05);out.write((int)(counter>>>24));out.write((int)(counter>>>16));out.write((int)(counter>>>8));out.write((int)counter);if(registration){out.writeBytes(new byte[16]);out.write(this.id.length>>>8);out.write(this.id.length);out.writeBytes(this.id);byte[] spki=this.pair.getPublic().getEncoded();out.write(0xa4);out.write(1);out.write(1);out.write(3);out.write(0x27);out.write(0x20);out.write(6);out.write(0x21);out.write(0x58);out.write(32);out.writeBytes(Arrays.copyOfRange(spki,spki.length-32,spki.length));}return out.toByteArray();}
        private static byte @NonNull [] attestation(byte @NonNull [] auth){ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(0xa3);text(out,"fmt");text(out,"none");text(out,"authData");bytes(out,auth);text(out,"attStmt");out.write(0xa0);return out.toByteArray();}
        private static void text(@NonNull ByteArrayOutputStream out,@NonNull String value){byte[] bytes=value.getBytes(StandardCharsets.US_ASCII);out.write(0x60|bytes.length);out.writeBytes(bytes);}
        private static void bytes(@NonNull ByteArrayOutputStream out,byte @NonNull [] bytes){if(bytes.length<24)out.write(0x40|bytes.length);else if(bytes.length<256){out.write(0x58);out.write(bytes.length);}else{out.write(0x59);out.write(bytes.length>>>8);out.write(bytes.length);}out.writeBytes(bytes);}
        private static byte @NonNull [] json(@NonNull String value){return value.getBytes(StandardCharsets.UTF_8);}
        private static byte @NonNull [] hash(byte @NonNull [] bytes){try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture hash unavailable");}}
        @Override public @NonNull String toString(){return "SyntheticAuthenticator{<redacted>}";}
    }
    @Override public @NonNull String toString(){return "DurablePasskeyFixture{<redacted>}";}
}
