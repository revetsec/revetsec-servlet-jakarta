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

import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.RemoteJwksSource;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.InMemoryPendingAuthorizationStore;
import com.revetsec.oauth.IssuerParameterPolicy;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Test-only OP, keys, account backend and latches. No real OP account or browser/TLS proof. */
@ThreadSafe
public final class OidcProviderFixture implements AutoCloseable {
    private static final @NonNull KeyPair KEY=key("TEST-ONLY-oidc-op"),OTHER=key("TEST-ONLY-oidc-attacker");
    private static final @NonNull Instant INITIAL=Instant.parse("2026-11-05T12:00:00Z");
    private final @NonNull MutableClock clock=new MutableClock();
    private final @NonNull AtomicLong nanoOffset=new AtomicLong();
    private final @NonNull SecureRandom random=new SecureRandom();
    private final @NonNull ExecutorService executor=Executors.newFixedThreadPool(4);
    private final @NonNull HttpServer server;
    private final @NonNull Map<@NonNull String,@NonNull Code> codes=new LinkedHashMap<>();
    private long codeBytes;
    private final @NonNull AtomicInteger tokenPosts=new AtomicInteger(),pkceVerified=new AtomicInteger(),tokenRefusals=new AtomicInteger(),
            keyRequests=new AtomicInteger(),lookups=new AtomicInteger(),authorizations=new AtomicInteger(),saves=new AtomicInteger(),consumes=new AtomicInteger();
    private final @NonNull AtomicBoolean enabled=new AtomicBoolean(true),admission=new AtomicBoolean(true),injectedInterrupt=new AtomicBoolean(),interruptObserved=new AtomicBoolean(),interruptLeftSet=new AtomicBoolean(),interruptPublicationSafe=new AtomicBoolean();
    private final @NonNull AtomicReference<@NonNull String> saveMode=new AtomicReference<>("normal"),consumeMode=new AtomicReference<>("normal");
    private final @NonNull AtomicReference<@NonNull String> nextMode=new AtomicReference<>("valid"),lookupMode=new AtomicReference<>("normal");
    private final @NonNull AtomicReference<@Nullable Block> block=new AtomicReference<>();
    private volatile int keyStatus=200;
    private final @NonNull ServletOidcRpRecipe recipe;
    private final @NonNull String issuer;

    public OidcProviderFixture() throws IOException {
        verifyOrigin(OidcClient.class,"CORE");verifyOrigin(com.revetsec.servlet.jakarta.ServletOAuth.class,"ADAPTER");
        this.server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);this.server.setExecutor(this.executor);
        this.issuer="http://127.0.0.1:"+this.server.getAddress().getPort();
        this.server.createContext("/authorize",this::authorize);this.server.createContext("/token",this::token);this.server.createContext("/jwks",this::keys);this.server.start();
        var config=new ServletOidcRpRecipe.Configuration(URI.create("https://app.example"),URI.create("https://app.example/oidc/callback"),this.issuer,"oidc-rp");
        var metadata=OidcProviderMetadata.withIssuer(this.issuer).authorizationEndpoint(uri("/authorize")).tokenEndpoint(uri("/token"))
                .jwksUri(uri("/jwks")).codeChallengeMethodsSupported(Set.of("S256")).build();
        OidcClient client=OidcClient.withProviderMetadata(metadata).clientId("oidc-rp").redirectUri(config.callback())
                .clientAuthentication(ClientAuthentication.noneInstance()).scopes(Set.of("openid")).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256))
                .issuerParameterPolicy(IssuerParameterPolicy.REQUIRED).requirePkceAdvertised(true).clockSkew(Duration.ZERO)
                .pendingAuthorizationLifetime(Duration.ofMinutes(5)).maximumIdTokenAge(Duration.ofMinutes(5)).requestTimeout(Duration.ofSeconds(1))
                .totalDeadline(Duration.ofSeconds(3)).allowInsecureLoopback(true).clock(this.clock)
                .jwksSource(RemoteJwksSource.withUri(uri("/jwks")).allowInsecureLoopback(true).clock(this.clock).requestTimeout(Duration.ofSeconds(1))
                        .maximumStaleness(Duration.ZERO).maximumKeys(8).maximumResponseBytes(65_536).build()).build();
        PendingAuthorizationStore backing=InMemoryPendingAuthorizationStore.builder().clock(this.clock).maximumLiveEntries(128)
                .maximumChargedBytes(524_288L).maximumOpaqueRecordBytes(4096).build();
        PendingAuthorizationStore pending=new PendingAuthorizationStore(){
            @Override public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding,@NonNull String state,@NonNull String opaque,@NonNull Instant expires,@NonNull Duration remaining){String mode=saveMode.getAndSet("normal");if(mode.equals("unavailable"))return PendingAuthorizationSaveResult.UNAVAILABLE;PendingAuthorizationSaveResult result=backing.save(binding,state,opaque,expires,remaining);if(result==PendingAuthorizationSaveResult.SAVED)saves.incrementAndGet();return result==PendingAuthorizationSaveResult.SAVED&&mode.equals("unknown")?PendingAuthorizationSaveResult.INDETERMINATE:result;}
            @Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding,@NonNull String state,@NonNull Duration remaining){Optional<String> result=backing.consume(binding,state,remaining);if(result.isPresent())consumes.incrementAndGet();if(consumeMode.getAndSet("normal").equals("unknown"))throw new IllegalStateException("Fixture removal acknowledgement lost");return result;}
        };
        var accounts=new ServletOidcRpRecipe.Accounts(){
            @Override public @NonNull Optional<ServletOidcRpRecipe.@NonNull Account> findAndAuthorizeLogin(@NonNull String provider,@NonNull String subject,@NonNull Duration remaining){
                lookups.incrementAndGet();pause("account");
                switch(lookupMode.getAndSet("normal")){case "late"->nanoOffset.addAndGet(Duration.ofSeconds(6).toNanos());case "interrupt"->{injectedInterrupt.set(true);Thread.currentThread().interrupt();}case "expire"->clock.advance(301);default->{}}
                return enabled.get()&&provider.equals(issuer)&&subject.equals("fixture-sub")?Optional.of(new ServletOidcRpRecipe.Account("alice","tenant")):Optional.empty();
            }
            @Override public boolean authorize(ServletOidcRpRecipe.@NonNull Account account,@NonNull String tenant,@NonNull String id,@NonNull Duration remaining){authorizations.incrementAndGet();pause("authorize");return enabled.get()&&account.tenant().equals(tenant)&&account.id().equals(id);}
        };
        this.recipe=new ServletOidcRpRecipe(config,client,pending,accounts,(peer,remaining)->this.admission.get(),this.clock,
                ()->System.nanoTime()+this.nanoOffset.get());
    }
    public @NonNull ServletOidcRpRecipe recipe(){return this.recipe;}
    boolean takeInjectedInterrupt(){return this.injectedInterrupt.getAndSet(false);}
    void recordCancellation(boolean leftSet,boolean safe){this.interruptLeftSet.set(leftSet);this.interruptPublicationSafe.set(safe);this.interruptObserved.set(true);}
    public @NonNull JsonObject control(@NonNull String command){
        if(command.startsWith("next/")){String mode=command.substring(5);if(!Set.of("valid","wrong-nonce","missing-nonce","wrong-issuer","wrong-audience","wrong-access-hash","wrong-code-hash","expired","signature","unmapped","old-auth-time","future-auth-time","missing-auth-time","endpoint-unavailable").contains(mode))throw new IllegalArgumentException("Unknown mutation");this.nextMode.set(mode);}
        else switch(command){
            case "state"->{}
            case "deny"->this.enabled.set(false);
            case "allow"->this.enabled.set(true);
            case "admission-deny"->this.admission.set(false);
            case "admission-allow"->this.admission.set(true);
            case "advance-keys"->this.clock.advance(61);
            case "advance-pending"->this.clock.advance(301);
            case "advance-session"->this.clock.advance(1801);
            case "rollback"->this.clock.value.set(INITIAL);
            case "recover-clock"->this.clock.recover();
            case "outage"->{this.clock.advance(61);this.keyStatus=503;}
            case "pending-save-unavailable"->this.saveMode.set("unavailable");
            case "pending-save-unknown"->this.saveMode.set("unknown");
            case "pending-consume-unknown"->this.consumeMode.set("unknown");
            case "lookup-late"->this.lookupMode.set("late");
            case "lookup-interrupt"->this.lookupMode.set("interrupt");
            case "lookup-expire"->this.lookupMode.set("expire");
            case "block-token"->this.block.set(new Block("token"));
            case "block-keys"->this.block.set(new Block("keys"));
            case "block-account"->this.block.set(new Block("account"));
            case "block-authorize"->this.block.set(new Block("authorize"));
            case "release"->{Block value=this.block.getAndSet(null);if(value!=null)value.release.countDown();}
            default->throw new IllegalArgumentException("Unknown control");
        }
        Block paused=this.block.get();
        return JsonObject.builder().put("origin_verified",true).put("injected_interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptLeftSet.get()).put("handler_cancel_no_publication",this.interruptPublicationSafe.get()).put("issuer",this.issuer).put("token_posts",this.tokenPosts.longValue())
                .put("pkce_verified",this.pkceVerified.longValue()).put("token_refusals",this.tokenRefusals.longValue())
                .put("key_requests",this.keyRequests.longValue()).put("lookups",this.lookups.longValue()).put("authorizations",this.authorizations.longValue())
                .put("pending_saved",this.saves.longValue()).put("pending_consumed",this.consumes.longValue())
                .put("host",this.recipe.stateSnapshot())
                .put("blocked",paused!=null&&paused.entered.getCount()==0).put("blocked_count",paused==null?0L:paused.active.longValue()).build();
    }
    private void authorize(@NonNull HttpExchange exchange)throws IOException{
        try{
            Map<String,String> parameters=form(exchange.getRequestURI().getRawQuery());
            String nonce=required(parameters,"nonce"),state=required(parameters,"state"),challenge=required(parameters,"code_challenge"),mode=parameters.getOrDefault("response_mode","query");
            if(!exchange.getRequestMethod().equals("GET")||!required(parameters,"client_id").equals("oidc-rp")||!required(parameters,"response_type").equals("code")
                    ||!required(parameters,"redirect_uri").equals("https://app.example/oidc/callback")||!required(parameters,"code_challenge_method").equals("S256")
                    ||!List.of("query","form_post").contains(mode)||!nonce.matches("[A-Za-z0-9_-]{43}")||!state.matches("[A-Za-z0-9_-]{43}")||!challenge.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("Invalid authorization");
            String code=token();
            synchronized(this.codes){
                int inspected=0;List<Map.Entry<String,Code>> keep=new java.util.ArrayList<>();
                for(var it=this.codes.entrySet().iterator();it.hasNext()&&inspected++<16;){var entry=it.next();it.remove();if(entry.getValue().created.plusSeconds(300).isAfter(this.clock.instant()))keep.add(entry);else this.codeBytes-=entry.getValue().charge();}
                for(var entry:keep)this.codes.put(entry.getKey(),entry.getValue());
                Code value=new Code(state,nonce,challenge,this.nextMode.getAndSet("valid"),this.clock.instant());
                if(this.codes.size()>=256||value.charge()>65_536-this.codeBytes)throw new IllegalArgumentException("Fixture capacity");
                this.codes.put(code,value);this.codeBytes+=value.charge();
            }
            String fields="code="+enc(code)+"&state="+enc(state)+"&iss="+enc(this.issuer);
            if(mode.equals("query")){
                exchange.getResponseHeaders().set("Location","https://app.example/oidc/callback?"+fields);reply(exchange,302,"text/plain","");
            }else{
                String html="<!doctype html><form method=\"post\" action=\"https://app.example/oidc/callback\"><input name=\"code\" value=\""+code+"\"><input name=\"state\" value=\""+state+"\"><input name=\"iss\" value=\""+this.issuer+"\"></form>";
                reply(exchange,200,"text/html; charset=UTF-8",html);
            }
        }catch(IllegalArgumentException rejected){reply(exchange,400,"application/json","{\"error\":\"invalid_request\"}");}
    }
    private void token(@NonNull HttpExchange exchange)throws IOException{
        this.tokenPosts.incrementAndGet();pause("token");
        try{
            byte[] raw=exchange.getRequestBody().readNBytes(4097);if(raw.length>4096)throw new IllegalArgumentException("Oversize");
            Map<String,String> parameters=form(new String(raw,StandardCharsets.US_ASCII));String code=required(parameters,"code"),verifier=required(parameters,"code_verifier");Code selected;
            synchronized(this.codes){
                selected=this.codes.get(code);
                if(!exchange.getRequestMethod().equals("POST")||selected==null||!selected.created.plusSeconds(300).isAfter(this.clock.instant())
                        ||!required(parameters,"grant_type").equals("authorization_code")||!required(parameters,"client_id").equals("oidc-rp")
                        ||!required(parameters,"redirect_uri").equals("https://app.example/oidc/callback")||!verifier.matches("[A-Za-z0-9_-]{43}")||!selected.challenge.equals(hash(verifier)))throw new IllegalArgumentException("Invalid grant");
                this.codes.remove(code);this.codeBytes-=selected.charge();this.pkceVerified.incrementAndGet();
            }
            if(selected.mode.equals("endpoint-unavailable")){reply(exchange,503,"application/json","{\"error\":\"server_error\"}");return;}
            Instant now=this.clock.instant();String access="TEST-ONLY-access-"+code;
            Map<String,JsonValue> claims=new LinkedHashMap<>(JsonObject.builder().put("iss",this.issuer).put("aud","oidc-rp").put("sub","fixture-sub")
                    .put("iat",now.getEpochSecond()).put("exp",now.plusSeconds(120).getEpochSecond()).put("auth_time",now.getEpochSecond())
                    .put("nonce",selected.nonce).put("at_hash",halfHash(access)).put("c_hash",halfHash(code)).build().getMembers());
            KeyPair signer=KEY;
            switch(selected.mode){
                case "wrong-nonce"->claims.put("nonce",JsonString.fromValue("another-flow"));
                case "missing-nonce"->claims.remove("nonce");
                case "wrong-issuer"->claims.put("iss",JsonString.fromValue("https://attacker.invalid"));
                case "wrong-audience"->claims.put("aud",JsonString.fromValue("attacker-client"));
                case "wrong-access-hash"->claims.put("at_hash",JsonString.fromValue("wrong"));
                case "wrong-code-hash"->claims.put("c_hash",JsonString.fromValue("wrong"));
                case "expired"->claims.put("exp",com.revetsec.json.JsonNumber.fromValue(now.getEpochSecond()));
                case "signature"->signer=OTHER;
                case "unmapped"->claims.put("sub",JsonString.fromValue("unmapped-sub"));
                case "old-auth-time"->claims.put("auth_time",com.revetsec.json.JsonNumber.fromValue(now.minusSeconds(301).getEpochSecond()));
                case "future-auth-time"->claims.put("auth_time",com.revetsec.json.JsonNumber.fromValue(now.plusSeconds(1).getEpochSecond()));
                case "missing-auth-time"->claims.remove("auth_time");
                default->{}
            }
            String jwt=sign(signer,JsonObject.fromMembers(claims).toJson());
            reply(exchange,200,"application/json",JsonObject.builder().put("token_type","Bearer").put("access_token",access).put("expires_in",120L).put("scope","openid").put("id_token",jwt).build().toJson());
        }catch(IllegalArgumentException rejected){this.tokenRefusals.incrementAndGet();reply(exchange,400,"application/json","{\"error\":\"invalid_grant\"}");}
    }
    private void keys(@NonNull HttpExchange exchange)throws IOException{
        this.keyRequests.incrementAndGet();pause("keys");RSAPublicKey key=(RSAPublicKey)KEY.getPublic();
        exchange.getResponseHeaders().set("Cache-Control","max-age=60");exchange.getResponseHeaders().set("Date",DateTimeFormatter.RFC_1123_DATE_TIME.format(this.clock.instant().atZone(ZoneOffset.UTC)));
        reply(exchange,this.keyStatus,"application/json","{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"op\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\""+unsigned(key.getModulus())+"\",\"e\":\""+unsigned(key.getPublicExponent())+"\"}]}");
    }
    private void pause(@NonNull String stage){Block selected=this.block.get();if(selected!=null&&selected.stage.equals(stage)){selected.entered.countDown();selected.active.incrementAndGet();try{if(!selected.release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Fixture wait timed out");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Fixture interrupted");}finally{selected.active.decrementAndGet();}}}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind)throws IOException{
        try{
            Path expected=Path.of(System.getenv("REVETSEC_OIDC_"+kind+"_JAR")).toRealPath();Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
            if(!actual.equals(expected)||Files.size(actual)>16_777_216||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(System.getenv("REVETSEC_OIDC_"+kind+"_SHA256")))throw new IOException("Selected origin mismatch");
        }catch(java.net.URISyntaxException|GeneralSecurityException|RuntimeException unavailable){throw new IOException("Selected origin unavailable");}
    }
    private @NonNull URI uri(@NonNull String path){return URI.create(this.issuer+path);}
    private @NonNull String token(){byte[] bytes=new byte[32];this.random.nextBytes(bytes);return b64(bytes);}
    private static @NonNull String required(@NonNull Map<@NonNull String,@NonNull String> form,@NonNull String key){String value=form.get(key);if(value==null||value.isEmpty())throw new IllegalArgumentException("Missing fixture field");return value;}
    private static @NonNull Map<@NonNull String,@NonNull String> form(@Nullable String encoded){
        if(encoded==null||encoded.length()>8192)throw new IllegalArgumentException("Invalid fixture form");Map<String,String> values=new LinkedHashMap<>();String[] parts=encoded.split("&",-1);if(parts.length>24)throw new IllegalArgumentException("Too many fields");
        for(String part:parts){int at=part.indexOf('=');if(at<1)throw new IllegalArgumentException("Invalid field");String name=URLDecoder.decode(part.substring(0,at),StandardCharsets.UTF_8),value=URLDecoder.decode(part.substring(at+1),StandardCharsets.UTF_8);if(values.putIfAbsent(name,value)!=null)throw new IllegalArgumentException("Duplicate field");}return values;
    }
    private static @NonNull String enc(@NonNull String value){return URLEncoder.encode(value,StandardCharsets.UTF_8);}
    private static @NonNull String b64(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static byte @NonNull [] sha(@NonNull String value){try{return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture hash unavailable");}}
    private static @NonNull String hash(@NonNull String value){return b64(sha(value));}
    private static @NonNull String halfHash(@NonNull String value){return b64(Arrays.copyOf(sha(value),16));}
    private static @NonNull String unsigned(java.math.@NonNull BigInteger value){byte[] bytes=value.toByteArray();return b64(bytes.length>1&&bytes[0]==0?Arrays.copyOfRange(bytes,1,bytes.length):bytes);}
    private static @NonNull KeyPair key(@NonNull String label){try{SecureRandom random=SecureRandom.getInstance("SHA1PRNG");random.setSeed(label.getBytes(StandardCharsets.US_ASCII));KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048,random);return generator.generateKeyPair();}catch(GeneralSecurityException unavailable){throw new ExceptionInInitializerError(unavailable);}}
    private static @NonNull String sign(@NonNull KeyPair key,@NonNull String payload){try{String input=b64("{\"alg\":\"RS256\",\"kid\":\"op\"}".getBytes(StandardCharsets.US_ASCII))+'.'+b64(payload.getBytes(StandardCharsets.UTF_8));Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key.getPrivate());signature.update(input.getBytes(StandardCharsets.US_ASCII));return input+'.'+b64(signature.sign());}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture signing unavailable");}}
    private static void reply(@NonNull HttpExchange exchange,int status,@NonNull String media,@NonNull String body)throws IOException{byte[] bytes=body.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type",media);exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.sendResponseHeaders(status,bytes.length);try(var output=exchange.getResponseBody()){output.write(bytes);}exchange.close();}
    @Override public void close(){Block paused=this.block.getAndSet(null);if(paused!=null)paused.release.countDown();this.server.stop(0);this.executor.shutdownNow();}
    private static final class Block{final @NonNull String stage;final @NonNull AtomicInteger active=new AtomicInteger();final @NonNull CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);Block(@NonNull String stage){this.stage=stage;}}
    private record Code(@NonNull String state,@NonNull String nonce,@NonNull String challenge,@NonNull String mode,@NonNull Instant created){long charge(){return 172L+this.mode.length();}}
    private static final class MutableClock extends Clock{
        final @NonNull AtomicReference<@NonNull Instant> value=new AtomicReference<>(INITIAL),maximum=new AtomicReference<>(INITIAL);
        void advance(long seconds){Instant next=this.value.updateAndGet(value->value.plusSeconds(seconds));this.maximum.accumulateAndGet(next,(old,current)->old.isAfter(current)?old:current);}
        void recover(){Instant next=this.maximum.get().plusSeconds(1);this.maximum.set(next);this.value.set(next);}
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
        @Override public @NonNull Instant instant(){return this.value.get();}
    }
}
