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

import com.revetsec.json.*;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.password.*;
import com.revetsec.scim.ScimServiceProvider;
import com.revetsec.servlet.jakarta.ServletScim;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import example.ServletScimDirectoryRecipe.Stage;
import example.ServletScimDirectoryRecipe.Principal;
import example.ServletScimDirectoryRecipe.Identity;
import example.ServletScimDirectoryRecipe.Role;

/** Owned synthetic JWT/JWKS, current principal, KDF and transaction observations. Never deploy. */
@ThreadSafe
final class ScimDirectoryFixture implements AutoCloseable {
    private static final @NonNull String ISSUER="https://issuer.example",CLIENT="scim-client";
    private static final @NonNull KeyPair KEY=key(),OTHER=key();
    private final @NonNull MutableClock clock=new MutableClock();
    private final @NonNull AtomicLong nanos=new AtomicLong(),sequence=new AtomicLong();
    private final @NonNull AtomicInteger keys=new AtomicInteger(),policies=new AtomicInteger(),kdf=new AtomicInteger(),admissions=new AtomicInteger();
    private final @NonNull AtomicBoolean admitted=new AtomicBoolean(true),credentialAllowed=new AtomicBoolean(true),injectedInterrupt=new AtomicBoolean();
    private final @NonNull AtomicReference<char @Nullable []> borrowed=new AtomicReference<>();
    private final @NonNull AtomicReference<@Nullable Effect> effect=new AtomicReference<>();
    private final @NonNull AtomicReference<@Nullable Block> block=new AtomicReference<>();
    private final @NonNull Map<@NonNull String,@NonNull Principal> principals=new ConcurrentHashMap<>();
    private final @NonNull ExecutorService workers=Executors.newFixedThreadPool(4);
    private final @NonNull HttpServer server;
    private final ServletScimDirectoryRecipe.@NonNull Directory directory;
    private final @NonNull ServletScimDirectoryRecipe recipe;
    private final @NonNull PasswordHasher hasher;
    private volatile int keyStatus=200;
    ScimDirectoryFixture()throws IOException{
        verifyOrigin(ScimServiceProvider.class,"CORE");verifyOrigin(ServletScim.class,"ADAPTER");
        this.server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);this.server.setExecutor(this.workers);
        this.server.createContext("/jwks",exchange->{this.keys.incrementAndGet();RSAPublicKey publicKey=(RSAPublicKey)KEY.getPublic();String payload=JsonObject.builder().put("keys",JsonArray.fromElements(List.of(JsonObject.builder().put("kty","RSA").put("kid","fixture").put("alg","RS256").put("use","sig").put("n",unsigned(publicKey.getModulus())).put("e",unsigned(publicKey.getPublicExponent())).build()))).build().toJson();
            byte[] bytes=(this.keyStatus==200?payload:"{}").getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json");exchange.getResponseHeaders().set("Cache-Control","max-age=60");exchange.getResponseHeaders().set("Date",DateTimeFormatter.RFC_1123_DATE_TIME.format(this.clock.instant().atZone(ZoneOffset.UTC)));exchange.sendResponseHeaders(this.keyStatus,bytes.length);try(var output=exchange.getResponseBody()){output.write(bytes);}});this.server.start();
        for(String name:List.of("adminA","limitedA","readerA","selfA","adminB","readerB")){Role role=name.startsWith("reader")?Role.READER:name.startsWith("self")?Role.SELF:Role.PROVISIONER;this.principals.put(name,new Principal(name,name.endsWith("B")?"beta":"alpha",role,role==Role.SELF?"u1":null,1,name.startsWith("admin")));}
        Map<Identity,Principal> records=new LinkedHashMap<>();this.principals.forEach((name,value)->records.put(identity(name),value));this.directory=new ServletScimDirectoryRecipe.Directory(Set.of("alpha","beta"),records);
        URI keys=URI.create("http://127.0.0.1:"+this.server.getAddress().getPort()+"/jwks");RemoteJwksSource source=RemoteJwksSource.withUri(keys).allowInsecureLoopback(true).clock(this.clock).maximumKeys(4).maximumResponseBytes(16_384).maximumStaleness(Duration.ZERO).requestTimeout(Duration.ofSeconds(1)).build();
        AccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(ISSUER).jwksSource(source).expectedAudiences(Set.of("https://app.example/scim-api")).allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).requiredClaims(Set.of("tenant","scope")).clockSkew(Duration.ZERO).maximumTokenLength(8192).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).clock(this.clock).build();
        this.hasher=PasswordHasher.withArgon2id(Argon2idParameters.fromCosts(19_456,2,1)).workGate(PasswordWorkGate.fromInMemoryLimits(2,38_912)).build();
        var config=new ServletScimDirectoryRecipe.Configuration(URI.create("https://app.example"),ISSUER,URI.create("https://app.example/scim-api"),URI.create(ISSUER+"/jwks"),Set.of("alpha","beta"));
        int responseLimit=Integer.parseInt(System.getenv().getOrDefault("REVETSEC_SCIM_RESPONSE_LIMIT","65536"));if(responseLimit!=2048&&responseLimit!=65536)throw new IllegalArgumentException("Fixed fixture response limit");
        this.recipe=new ServletScimDirectoryRecipe(config,validator,this.directory,this.hasher,(principal,password,remaining)->{this.policies.incrementAndGet();this.borrowed.set(password);return this.credentialAllowed.get()&&password.length>0;},(peer,remaining)->{this.admissions.incrementAndGet();return this.admitted.get();},this.clock,()->System.nanoTime()+this.nanos.get(),this::probe,responseLimit);
    }
    @NonNull ServletScimDirectoryRecipe recipe(){return this.recipe;}
    boolean takeInjectedInterrupt(){return this.injectedInterrupt.getAndSet(false);}
    long writes(){return ((JsonNumber)this.directory.snapshotCounts().getMembers().get("writes")).getValue().longValueExact();}
    @NonNull String token(@NonNull String actor,@NonNull String mode)throws GeneralSecurityException{
        Principal principal=this.principals.get(actor);if(principal==null)throw new IllegalArgumentException("Unknown fixture actor");Instant now=this.clock.instant();
        Map<String,JsonValue> claims=new LinkedHashMap<>(JsonObject.builder().put("iss",mode.equals("wrong-issuer")?"https://wrong.invalid":ISSUER).put("aud",mode.equals("wrong-audience")?"https://wrong.invalid/api":"https://app.example/scim-api").put("sub",mode.equals("unmapped")?"not-mapped":actor).put("client_id",CLIENT).put("iat",(mode.equals("future")?now.plusSeconds(1):now).getEpochSecond()).put("exp",(mode.equals("expired")?now:now.plusSeconds(300)).getEpochSecond()).put("jti","fixture-"+this.sequence.incrementAndGet()).put("tenant",mode.equals("wrong-tenant")?(principal.tenant().equals("alpha")?"beta":"alpha"):principal.tenant()).put("scope",mode.equals("no-scope")?"other":mode.equals("read-only")?"scim:read":"scim:read scim:write").build().getMembers());
        if(mode.equals("missing-client"))claims.remove("client_id");if(mode.equals("missing-tenant"))claims.remove("tenant");if(mode.equals("role-claim-admin"))claims.put("role",JsonString.fromValue("PROVISIONER"));
        String header=JsonObject.builder().put("alg","RS256").put("kid","fixture").put("typ",mode.equals("wrong-type")?"JWT":"at+jwt").build().toJson();String unsigned=b64(header)+'.'+b64(JsonObject.fromMembers(claims).toJson());Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign((mode.equals("wrong-key")?OTHER:KEY).getPrivate());signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));return unsigned+'.'+Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }
    @NonNull JsonObject control(@NonNull String command){
        if(command.startsWith("block/")){String[] parts=command.split("/",-1);if(parts.length!=2&&parts.length!=3)throw new IllegalArgumentException("Fixture block");if(this.block.get()!=null)throw new IllegalArgumentException("Block already selected");this.block.set(new Block(stage(parts[1]),parts.length==3?Integer.parseInt(parts[2]):8));}
        else if(command.startsWith("effect/")){String[] parts=command.split("/",-1);if(parts.length!=3)throw new IllegalArgumentException("Fixture effect");this.effect.set(new Effect(stage(parts[1]),parts[2]));}
        else switch(command){
            case "state"->{}case "release"->{Block selected=this.block.getAndSet(null);if(selected!=null)selected.release.countDown();}
            case "admission-deny"->this.admitted.set(false);case "admission-allow"->this.admitted.set(true);case "credential-deny"->this.credentialAllowed.set(false);case "credential-allow"->this.credentialAllowed.set(true);
            case "unknown-next"->this.directory.failNext(true);case "unavailable-next"->this.directory.failNext(false);
            case "policy-reader"->replace("adminA",Role.READER,"alpha",null,false);case "policy-no-credential"->replace("adminA",Role.PROVISIONER,"alpha",null,false);case "policy-beta"->replace("adminA",Role.PROVISIONER,"beta",null,true);
            case "reset-policy"->{for(String actor:new ArrayList<>(this.principals.keySet())){Role role=actor.startsWith("reader")?Role.READER:actor.startsWith("self")?Role.SELF:Role.PROVISIONER;replace(actor,role,actor.endsWith("B")?"beta":"alpha",role==Role.SELF?"u1":null,actor.startsWith("admin"));}}
            case "keys-outage"->{this.clock.advance(61);this.keyStatus=503;}case "advance-expiry"->this.clock.advance(301);case "clear-late"->this.nanos.set(0);
            default->throw new IllegalArgumentException("Unknown fixture command");
        }
        Block selected=this.block.get();char[] password=this.borrowed.get();boolean cleared=true;if(password!=null)for(char value:password)if(value!=0)cleared=false;
        return JsonObject.builder().put("origin_verified",true).put("directory",this.directory.snapshotCounts()).put("key_requests",this.keys.longValue()).put("credential_policy_calls",this.policies.longValue()).put("kdf_stages",this.kdf.longValue()).put("admissions",this.admissions.longValue()).put("borrowed_password_cleared",cleared).put("blocked_entered",selected==null?0L:selected.entered.longValue()).put("block_peak",selected==null?0L:selected.peak.longValue()).build();
    }
    boolean passwordMatches(@NonNull String tenant,@NonNull String id,char @NonNull [] password){try{String stored=this.directory.credential(tenant,id);return stored!=null&&this.hasher.verifyResult(password,stored) instanceof PasswordVerificationResult.Matched;}finally{Arrays.fill(password,'\0');}}
    private void probe(@NonNull Stage stage,@NonNull Duration remaining)throws Exception{
        if(stage==Stage.BEFORE_KDF)this.kdf.incrementAndGet();Block selected=this.block.get();if(selected!=null&&selected.stage==stage){int entered=selected.claimed.getAndIncrement();if(entered<selected.limit){selected.entered.incrementAndGet();selected.peak.accumulateAndGet(entered+1,Math::max);try{if(!selected.release.await(4,TimeUnit.SECONDS))throw new IllegalStateException("Fixture block timed out");}finally{selected.entered.decrementAndGet();}}}
        Effect effect=this.effect.get();if(effect==null||effect.stage()!=stage||!this.effect.compareAndSet(effect,null))return;
        switch(effect.mode()){
            case "expire"->this.clock.advance(300);case "rollback"->this.clock.value.set(this.clock.instant().minusSeconds(1));case "late"->this.nanos.addAndGet(Duration.ofSeconds(9).toNanos());
            case "interrupt"->{this.injectedInterrupt.set(true);Thread.currentThread().interrupt();}case "checked-interrupt"->{this.injectedInterrupt.set(true);throw new InterruptedException("TEST-ONLY interrupted callback");}
            case "checked-io"->{this.injectedInterrupt.set(true);throw new java.io.InterruptedIOException("TEST-ONLY interrupted callback");}case "timeout"->throw new java.net.SocketTimeoutException("TEST-ONLY timeout");
            case "reader"->replace("adminA",Role.READER,"alpha",null,false);case "no-credential"->replace("adminA",Role.PROVISIONER,"alpha",null,false);case "tenant-beta"->replace("adminA",Role.PROVISIONER,"beta",null,true);
            default->throw new IllegalArgumentException("Unknown fixture effect");
        }
    }
    private void replace(@NonNull String actor,@NonNull Role role,@NonNull String tenant,@Nullable String owner,boolean credentials){Principal previous=this.principals.get(actor);Principal replacement=new Principal(actor,tenant,role,owner,previous.generation()+1,credentials);this.directory.replacePrincipal(identity(actor),replacement);this.principals.put(actor,replacement);}
    private static @NonNull Identity identity(@NonNull String actor){return new Identity(ISSUER,actor,CLIENT);}
    private static @NonNull Stage stage(@NonNull String value){return Stage.valueOf(value.replace('-','_').toUpperCase(Locale.ROOT));}
    private record Effect(@NonNull Stage stage,@NonNull String mode){ }
    private static final class Block{final @NonNull Stage stage;final int limit;final @NonNull CountDownLatch release=new CountDownLatch(1);final @NonNull AtomicInteger claimed=new AtomicInteger(),entered=new AtomicInteger(),peak=new AtomicInteger();Block(@NonNull Stage stage,int limit){if(limit<1||limit>8)throw new IllegalArgumentException("Bounded fixture block");this.stage=stage;this.limit=limit;}}
    private static final class MutableClock extends Clock{final @NonNull AtomicReference<@NonNull Instant> value=new AtomicReference<>(Instant.parse("2026-11-05T12:00:00Z"));void advance(long seconds){this.value.updateAndGet(now->now.plusSeconds(seconds));}@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException("Fixture UTC only");return this;}@Override public @NonNull Instant instant(){return this.value.get();}}
    private static @NonNull String b64(@NonNull String value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));}
    private static @NonNull String unsigned(java.math.@NonNull BigInteger value){byte[] bytes=value.toByteArray();return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes[0]==0?Arrays.copyOfRange(bytes,1,bytes.length):bytes);}
    private static @NonNull KeyPair key(){try{KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);return generator.generateKeyPair();}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture crypto unavailable");}}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind){try{Path expected=Path.of(Objects.requireNonNull(System.getenv("REVETSEC_SCIM_"+kind+"_JAR"))).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)));if(!expected.equals(actual)||!hash.equals(System.getenv("REVETSEC_SCIM_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact mismatch");}catch(Exception mismatch){throw new IllegalStateException("Selected artifact mismatch");}}
    @Override public void close(){Block selected=this.block.getAndSet(null);if(selected!=null)selected.release.countDown();this.server.stop(0);this.workers.shutdownNow();try{if(!this.workers.awaitTermination(3,TimeUnit.SECONDS))throw new IllegalStateException("Fixture workers retained");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}
}
