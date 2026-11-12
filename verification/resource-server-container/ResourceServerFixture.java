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
import com.revetsec.jose.Jwks;
import com.revetsec.jose.JwksParseResult;
import com.revetsec.jose.RemoteJwksSource;
import com.revetsec.jose.StaticJwksSource;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.oauth.AccessToken;
import com.revetsec.oauth.AccessTokenValidationResult;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.ClientCredentialsTokenSource;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.TokenIntrospectionClient;
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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Synthetic AS/introspection/key/backend services for S2. No real service account or customer database. */
@ThreadSafe
public final class ResourceServerFixture implements AutoCloseable{
    private static final @NonNull URI ORIGIN=URI.create("https://api.example"),AUDIENCE=URI.create("https://api.example/accounts"),BACKEND_AUDIENCE=URI.create("https://backend.example/accounts");
    private static final @NonNull String INTRO_ID="resource-reader",INTRO_SECRET="TEST-ONLY-introspection +:/&",CC_ID="backend-service",CC_SECRET="TEST-ONLY-acquisition +:/&";
    private static final @NonNull KeyPair KEY=key("TEST-ONLY-resource-key"),OTHER=key("TEST-ONLY-resource-attacker");
    private final @NonNull MutableClock clock=new MutableClock();
    private final @NonNull AtomicLong offset=new AtomicLong(),generation=new AtomicLong(1);
    private final @NonNull SecureRandom random=new SecureRandom();
    private final @NonNull ExecutorService serverExecutor=Executors.newFixedThreadPool(8),clientExecutor=Executors.newFixedThreadPool(4);
    private final @NonNull HttpServer server;
    private final @NonNull String issuer;
    private final @NonNull HttpClient http;
    private final @NonNull Map<@NonNull String,@NonNull JsonObject> opaque=new LinkedHashMap<>();
    private final @NonNull Set<@NonNull String> revokedOpaque=ConcurrentHashMap.newKeySet(),revokedBackend=ConcurrentHashMap.newKeySet();
    private final @NonNull Map<@NonNull String,@NonNull String> rows=Map.of("tenant/alice","protected-alice-v1","other/bob","protected-bob-v1");
    private final @NonNull AtomicInteger keyCalls=new AtomicInteger(),introspectionCalls=new AtomicInteger(),acquisitionCalls=new AtomicInteger(),backendCalls=new AtomicInteger(),backendAuthorized=new AtomicInteger(),lookups=new AtomicInteger(),policyCalls=new AtomicInteger(),dataReads=new AtomicInteger(),basicChecks=new AtomicInteger();
    private final @NonNull AtomicBoolean enabled=new AtomicBoolean(true),readAllowed=new AtomicBoolean(true),proxyAllowed=new AtomicBoolean(true),admitted=new AtomicBoolean(true),rejectBackendNext=new AtomicBoolean(),injectedInterrupt=new AtomicBoolean(),interruptObserved=new AtomicBoolean(),interruptLeftSet=new AtomicBoolean(),interruptWithheld=new AtomicBoolean();
    private final @NonNull AtomicReference<@NonNull String> action=new AtomicReference<>("normal");
    private final @NonNull AtomicReference<@Nullable Block> block=new AtomicReference<>();
    private volatile int introspectionStatus=200,acquisitionStatus=200,keyStatus=200;
    private final @NonNull ServletResourceServerRecipe jwt,opaqueRecipe;
    private final @NonNull JwtAccessTokenValidator backendValidator;

    public ResourceServerFixture()throws IOException{
        verifyOrigin(OAuthClient.class,"CORE");verifyOrigin(com.revetsec.servlet.jakarta.ServletBearer.class,"ADAPTER");
        this.server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);this.server.setExecutor(this.serverExecutor);this.issuer="http://127.0.0.1:"+this.server.getAddress().getPort();
        this.server.createContext("/jwks",this::keys);this.server.createContext("/introspect",this::introspect);this.server.createContext("/token",this::acquire);this.server.createContext("/backend/",this::backend);this.server.start();
        this.http=HttpClient.newBuilder().executor(this.clientExecutor).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(1)).build();
        var metadata=AuthorizationServerMetadata.withIssuer(this.issuer).authorizationEndpoint(uri("/authorize")).tokenEndpoint(uri("/token")).introspectionEndpoint(uri("/introspect"))
                .tokenEndpointAuthMethodsSupported(Set.of("client_secret_basic")).introspectionEndpointAuthMethodsSupported(Set.of("client_secret_basic")).build();
        var introClient=OAuthClient.withAuthorizationServerMetadata(metadata).clientId(INTRO_ID).clientAuthentication(ClientAuthentication.fromClientSecretBasic(INTRO_SECRET))
                .clock(this.clock).allowInsecureLoopback(true).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).build();
        var introspection=TokenIntrospectionClient.withOAuthClient(introClient).introspectionEndpoint(uri("/introspect")).expectedAudiences(Set.of(AUDIENCE.toString()))
                .requiredClaims(Set.of("exp","sub","client_id","tenant","scope")).maximumTokenLength(8192).clockSkew(Duration.ZERO).build();
        var keySource=RemoteJwksSource.withUri(uri("/jwks")).allowInsecureLoopback(true).clock(this.clock).requestTimeout(Duration.ofSeconds(1)).maximumStaleness(Duration.ZERO).maximumKeys(8).maximumResponseBytes(65_536).build();
        var jwtValidator=JwtAccessTokenValidator.withIssuer(this.issuer).jwksSource(keySource).expectedAudiences(Set.of(AUDIENCE.toString())).allowedAlgorithms(Set.of(JwsAlgorithm.RS256))
                .requiredClaims(Set.of("tenant","scope")).maximumTokenLength(8192).clockSkew(Duration.ZERO).clock(this.clock).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).build();
        var ccClient=OAuthClient.withAuthorizationServerMetadata(metadata).clientId(CC_ID).clientAuthentication(ClientAuthentication.fromClientSecretBasic(CC_SECRET))
                .clock(this.clock).allowInsecureLoopback(true).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).build();
        ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(ccClient).scopes(Set.of("backend:read")).resources(List.of(BACKEND_AUDIENCE)).build();
        this.backendValidator=JwtAccessTokenValidator.withIssuer(this.issuer).jwksSource(StaticJwksSource.fromJwks(((JwksParseResult.Succeeded)Jwks.fromJsonResult(jwks())).getJwks()))
                .expectedAudiences(Set.of(BACKEND_AUDIENCE.toString())).allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).requiredClaims(Set.of("tenant","scope"))
                .clockSkew(Duration.ZERO).clock(this.clock).maximumTokenLength(8192).build();
        var accounts=new ServletResourceServerRecipe.Accounts(){
            @Override public @NonNull Optional<ServletResourceServerRecipe.@NonNull Account> lookup(@NonNull String provider,@NonNull String subject,@NonNull String client,@NonNull Duration remaining){
                lookups.incrementAndGet();pause("account");act();
                if(!enabled.get()||!provider.equals(issuer)||!client.equals("caller-client"))return Optional.empty();
                if(subject.equals("alice-sub"))return Optional.of(new ServletResourceServerRecipe.Account("alice","tenant",generation.get()));
                if(subject.equals("bob-sub"))return Optional.of(new ServletResourceServerRecipe.Account("bob","other",generation.get()));return Optional.empty();
            }
            @Override public boolean authorize(ServletResourceServerRecipe.@NonNull Account account,@NonNull String provider,@NonNull String subject,@NonNull String client,ServletResourceServerRecipe.@NonNull Operation operation,@NonNull Duration remaining){policyCalls.incrementAndGet();pause("policy");return enabled.get()&&(operation==ServletResourceServerRecipe.Operation.READ?readAllowed.get():proxyAllowed.get())&&account.generation()==generation.get()&&provider.equals(issuer)&&client.equals("caller-client")&&((subject.equals("alice-sub")&&account.id().equals("alice")&&account.tenant().equals("tenant"))||(subject.equals("bob-sub")&&account.id().equals("bob")&&account.tenant().equals("other")));}
        };
        ServletResourceServerRecipe.Resources resources=(tenant,accountId,remaining)->{this.dataReads.incrementAndGet();pause("data");act();return this.rows.get(tenant+'/'+accountId);};
        ServletResourceServerRecipe.Backend backend=(account,credential,remaining)->{
            HttpRequest request=HttpRequest.newBuilder(uri("/backend/"+account.tenant()+'/'+account.id())).timeout(remaining.compareTo(Duration.ofSeconds(1))<0?remaining:Duration.ofSeconds(1))
                    .header("Authorization",credential.getAuthorizationHeaderValue()).GET().build();
            HttpResponse<byte[]> response=this.http.send(request,HttpResponse.BodyHandlers.ofByteArray());
            if(response.body().length>4096)return new ServletResourceServerRecipe.BackendResponse(503,null);
            if(response.statusCode()!=200)return new ServletResourceServerRecipe.BackendResponse(response.statusCode()==401?401:response.statusCode()==403?403:503,null);
            if(!response.headers().firstValue("Content-Type").orElse("").startsWith("text/plain"))return new ServletResourceServerRecipe.BackendResponse(503,null);
            return new ServletResourceServerRecipe.BackendResponse(200,new String(response.body(),StandardCharsets.UTF_8));
        };
        var jwtConfig=new ServletResourceServerRecipe.Configuration(ORIGIN,"/jwt",this.issuer,AUDIENCE,BACKEND_AUDIENCE,INTRO_ID,CC_ID);
        var opaqueConfig=new ServletResourceServerRecipe.Configuration(ORIGIN,"/opaque",this.issuer,AUDIENCE,BACKEND_AUDIENCE,INTRO_ID,CC_ID);
        this.jwt=new ServletResourceServerRecipe(jwtConfig,jwtValidator,source,accounts,resources,backend,(peer,remaining)->this.admitted.get(),this.clock,()->System.nanoTime()+this.offset.get());
        this.opaqueRecipe=new ServletResourceServerRecipe(opaqueConfig,introspection,source,accounts,resources,backend,(peer,remaining)->this.admitted.get(),this.clock,()->System.nanoTime()+this.offset.get());
    }
    public @NonNull ServletResourceServerRecipe recipe(@NonNull String mount){if(mount.equals("/jwt"))return this.jwt;if(mount.equals("/opaque"))return this.opaqueRecipe;throw new IllegalArgumentException("Unknown fixed profile");}
    public @NonNull JsonObject mint(@NonNull String profile,@NonNull String mutation){
        Map<String,JsonValue> claims=claims("caller-client","alice-sub",AUDIENCE.toString(),"accounts:read accounts:proxy","tenant");String type="at+jwt";KeyPair signer=KEY;
        switch(mutation){
            case "valid"->{}
            case "bob"->{claims.put("sub",JsonString.fromValue("bob-sub"));claims.put("tenant",JsonString.fromValue("other"));}
            case "wrong-issuer"->claims.put("iss",JsonString.fromValue("https://attacker.invalid"));
            case "wrong-audience"->claims.put("aud",JsonString.fromValue("https://attacker.invalid"));
            case "multi-audience"->claims.put("aud",JsonArray.fromElements(List.of(JsonString.fromValue(AUDIENCE.toString()),JsonString.fromValue("https://other.invalid"))));
            case "expired"->claims.put("exp",JsonNumber.fromValue(this.clock.instant().getEpochSecond()));
            case "edge-expiry"->claims.put("exp",JsonNumber.fromValue(this.clock.instant().plusSeconds(1).getEpochSecond()));
            case "future-issued"->claims.put("iat",JsonNumber.fromValue(this.clock.instant().plusSeconds(1).getEpochSecond()));
            case "wrong-scope"->claims.put("scope",JsonString.fromValue("unrelated"));
            case "read-only"->claims.put("scope",JsonString.fromValue("accounts:read"));
            case "missing-tenant"->claims.remove("tenant");
            case "nonstring-tenant"->claims.put("tenant",JsonNumber.fromValue(1L));
            case "wrong-tenant"->claims.put("tenant",JsonString.fromValue("other"));
            case "unmapped"->claims.put("sub",JsonString.fromValue("unmapped-sub"));
            case "wrong-client"->claims.put("client_id",JsonString.fromValue("unmapped-client"));
            case "signature"->signer=OTHER;
            case "identity-type"->{type="JWT";claims.put("nonce",JsonString.fromValue("identity-nonce"));}
            case "omit-issuer"->claims.remove("iss");
            default->throw new IllegalArgumentException("Unknown fixture mutation");
        }
        String compact;
        if(profile.equals("jwt"))compact=sign(signer,JsonObject.fromMembers(claims).toJson(),type);
        else if(profile.equals("opaque")){
            compact=token();synchronized(this.opaque){if(this.opaque.size()>=256)throw new IllegalArgumentException("Fixture token capacity");this.opaque.put(compact,JsonObject.fromMembers(claims));}
        }else throw new IllegalArgumentException("Unknown profile");
        return JsonObject.builder().put("token",compact).build();
    }
    public @NonNull JsonObject control(@NonNull String command,@Nullable String token){
        switch(command){
            case "state"->{}
            case "deny"->this.enabled.set(false);
            case "allow"->this.enabled.set(true);
            case "deny-read"->this.readAllowed.set(false);
            case "allow-read"->this.readAllowed.set(true);
            case "deny-proxy"->this.proxyAllowed.set(false);
            case "allow-proxy"->this.proxyAllowed.set(true);
            case "admission-deny"->this.admitted.set(false);
            case "admission-allow"->this.admitted.set(true);
            case "generation"->this.generation.incrementAndGet();
            case "revoke-opaque"->{if(token==null||!token.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("Invalid fixture token");this.revokedOpaque.add(hash(token));}
            case "reject-backend"->this.rejectBackendNext.set(true);
            case "advance-one"->this.clock.advance(1);
            case "advance-expiry"->this.clock.advance(121);
            case "lookup-late"->this.action.set("late");
            case "lookup-interrupt"->this.action.set("interrupt");
            case "lookup-expire"->this.action.set("expire");
            case "block-account"->this.block.set(new Block("account"));
            case "block-policy"->this.block.set(new Block("policy"));
            case "block-data"->this.block.set(new Block("data"));
            case "block-backend"->this.block.set(new Block("backend"));
            case "block-introspection"->this.block.set(new Block("introspection"));
            case "block-acquisition"->this.block.set(new Block("acquisition"));
            case "block-keys"->this.block.set(new Block("keys"));
            case "release"->{Block value=this.block.getAndSet(null);if(value!=null)value.release.countDown();}
            case "introspection-unauthorized"->this.introspectionStatus=401;
            case "acquisition-unavailable"->{this.clock.advance(121);this.acquisitionStatus=503;}
            case "keys-unavailable"->{this.clock.advance(61);this.keyStatus=503;}
            default->throw new IllegalArgumentException("Unknown control");
        }
        Block paused=this.block.get();
        return JsonObject.builder().put("origin_verified",true).put("issuer",this.issuer).put("key_calls",this.keyCalls.longValue()).put("introspection_calls",this.introspectionCalls.longValue())
                .put("acquisition_calls",this.acquisitionCalls.longValue()).put("backend_calls",this.backendCalls.longValue()).put("backend_authorized",this.backendAuthorized.longValue())
                .put("lookups",this.lookups.longValue()).put("policy_calls",this.policyCalls.longValue()).put("data_reads",this.dataReads.longValue()).put("basic_checks",this.basicChecks.longValue())
                .put("generation",this.generation.get()).put("blocked_count",paused==null?0L:paused.active.longValue())
                .put("injected_interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptLeftSet.get()).put("handler_cancel_no_protected_output",this.interruptWithheld.get()).build();
    }
    boolean takeInjectedInterrupt(){return this.injectedInterrupt.getAndSet(false);}
    void recordInterrupt(boolean leftSet,boolean withheld){this.interruptLeftSet.set(leftSet);this.interruptWithheld.set(withheld);this.interruptObserved.set(true);}
    private void act(){switch(this.action.getAndSet("normal")){case "late"->this.offset.addAndGet(Duration.ofSeconds(6).toNanos());case "expire"->this.clock.advance(121);case "interrupt"->{this.injectedInterrupt.set(true);Thread.currentThread().interrupt();}default->{}}}
    private void keys(@NonNull HttpExchange exchange)throws IOException{this.keyCalls.incrementAndGet();pause("keys");exchange.getResponseHeaders().set("Date",DateTimeFormatter.RFC_1123_DATE_TIME.format(this.clock.instant().atZone(ZoneOffset.UTC)));reply(exchange,this.keyStatus,"application/json",jwks());}
    private void introspect(@NonNull HttpExchange exchange)throws IOException{
        this.introspectionCalls.incrementAndGet();pause("introspection");
        if(!basic(exchange,INTRO_ID,INTRO_SECRET)){reply(exchange,401,"application/json","{\"error\":\"invalid_client\"}");return;}
        if(this.introspectionStatus!=200){reply(exchange,this.introspectionStatus,"application/json","{\"error\":\"invalid_client\"}");return;}
        try{
            Map<String,String> fields=form(exchange);if(!exchange.getRequestMethod().equals("POST")||!fields.keySet().equals(Set.of("token","token_type_hint"))||!"access_token".equals(fields.get("token_type_hint")))throw new IllegalArgumentException("Invalid introspection");
            String compact=required(fields,"token");JsonObject stored;synchronized(this.opaque){stored=this.opaque.get(compact);}
            if(stored==null||this.revokedOpaque.contains(hash(compact))){reply(exchange,200,"application/json","{\"active\":false}");return;}
            Map<String,JsonValue> claims=new LinkedHashMap<>(stored.getMembers());claims.put("active",com.revetsec.json.JsonBoolean.trueInstance());reply(exchange,200,"application/json",JsonObject.fromMembers(claims).toJson());
        }catch(IllegalArgumentException rejected){reply(exchange,400,"application/json","{\"error\":\"invalid_request\"}");}
    }
    private void acquire(@NonNull HttpExchange exchange)throws IOException{
        this.acquisitionCalls.incrementAndGet();pause("acquisition");
        if(!basic(exchange,CC_ID,CC_SECRET)){reply(exchange,401,"application/json","{\"error\":\"invalid_client\"}");return;}
        if(this.acquisitionStatus!=200){reply(exchange,this.acquisitionStatus,"application/json","{\"error\":\"server_error\"}");return;}
        try{
            Map<String,String> fields=form(exchange);if(!exchange.getRequestMethod().equals("POST")||!fields.keySet().equals(Set.of("grant_type","scope","resource"))||!required(fields,"grant_type").equals("client_credentials")||!required(fields,"scope").equals("backend:read")||!required(fields,"resource").equals(BACKEND_AUDIENCE.toString()))throw new IllegalArgumentException("Fixed acquisition policy required");
            String compact=sign(KEY,JsonObject.fromMembers(claims(CC_ID,CC_ID,BACKEND_AUDIENCE.toString(),"backend:read","tenant")).toJson(),"at+jwt");
            reply(exchange,200,"application/json",JsonObject.builder().put("access_token",compact).put("token_type","Bearer").put("expires_in",120L).put("scope","backend:read").build().toJson());
        }catch(IllegalArgumentException rejected){reply(exchange,400,"application/json","{\"error\":\"invalid_request\"}");}
    }
    private void backend(@NonNull HttpExchange exchange)throws IOException{
        this.backendCalls.incrementAndGet();
        BearerTokenResult parsed=BearerToken.fromAuthorizationHeaderValuesResult(exchange.getRequestHeaders().getOrDefault("Authorization",List.of()));
        if(!(parsed instanceof BearerTokenResult.Present present)){reply(exchange,401,"text/plain","");return;}
        AccessTokenValidationResult checked=this.backendValidator.validateResult(present.getToken());
        if(!(checked instanceof AccessTokenValidationResult.Succeeded success)||!success.getAccessToken().getClientId().orElse("").equals(CC_ID)||!success.getAccessToken().getSubject().orElse("").equals(CC_ID)||!success.getAccessToken().getScopes().contains("backend:read")){reply(exchange,401,"text/plain","");return;}
        String fingerprint=hash(exchange.getRequestHeaders().getFirst("Authorization"));
        if(this.rejectBackendNext.getAndSet(false))this.revokedBackend.add(fingerprint);
        if(this.revokedBackend.contains(fingerprint)){reply(exchange,401,"text/plain","");return;}
        String path=exchange.getRequestURI().getRawPath();if(!exchange.getRequestMethod().equals("GET")||exchange.getRequestURI().getRawQuery()!=null||!path.matches("/backend/[A-Za-z0-9_-]{1,64}/[A-Za-z0-9_-]{1,64}")){reply(exchange,403,"text/plain","");return;}
        String value=this.rows.get(path.substring("/backend/".length()));if(value==null){reply(exchange,403,"text/plain","");return;}
        this.backendAuthorized.incrementAndGet();pause("backend");act();reply(exchange,200,"text/plain; charset=UTF-8",value);
    }
    private boolean basic(@NonNull HttpExchange exchange,@NonNull String id,@NonNull String secret){List<String> values=exchange.getRequestHeaders().getOrDefault("Authorization",List.of());String expected="Basic "+Base64.getEncoder().encodeToString((URLEncoder.encode(id,StandardCharsets.UTF_8)+':'+URLEncoder.encode(secret,StandardCharsets.UTF_8)).getBytes(StandardCharsets.US_ASCII));boolean valid=values.size()==1&&MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),values.get(0).getBytes(StandardCharsets.US_ASCII));if(valid)this.basicChecks.incrementAndGet();return valid;}
    private @NonNull Map<@NonNull String,@NonNull JsonValue> claims(@NonNull String client,@NonNull String subject,@NonNull String audience,@NonNull String scope,@NonNull String tenant){Instant now=this.clock.instant();return new LinkedHashMap<>(JsonObject.builder().put("iss",this.issuer).put("aud",audience).put("sub",subject).put("client_id",client).put("jti",token()).put("iat",now.getEpochSecond()).put("exp",now.plusSeconds(120).getEpochSecond()).put("scope",scope).put("tenant",tenant).build().getMembers());}
    private static @NonNull Map<@NonNull String,@NonNull String> form(@NonNull HttpExchange exchange)throws IOException{byte[] bytes=exchange.getRequestBody().readNBytes(16_385);if(bytes.length>16_384)throw new IllegalArgumentException("Fixture form overflow");String text=new String(bytes,StandardCharsets.US_ASCII);String[] pieces=text.split("&",-1);if(pieces.length>8)throw new IllegalArgumentException("Fixture form fields");Map<String,String> fields=new LinkedHashMap<>();for(String piece:pieces){int at=piece.indexOf('=');if(at<1)throw new IllegalArgumentException("Invalid field");String name=URLDecoder.decode(piece.substring(0,at),StandardCharsets.UTF_8),value=URLDecoder.decode(piece.substring(at+1),StandardCharsets.UTF_8);if(fields.putIfAbsent(name,value)!=null)throw new IllegalArgumentException("Duplicate field");}return fields;}
    private static @NonNull String required(@NonNull Map<@NonNull String,@NonNull String> values,@NonNull String name){String value=values.get(name);if(value==null||value.isEmpty())throw new IllegalArgumentException("Missing fixture field");return value;}
    private void pause(@NonNull String stage){Block paused=this.block.get();if(paused!=null&&paused.stage.equals(stage)){paused.active.incrementAndGet();try{if(!paused.release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Bounded fixture wait");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Fixture interrupted");}finally{paused.active.decrementAndGet();}}}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind)throws IOException{try{Path expected=Path.of(System.getenv("REVETSEC_RESOURCE_"+kind+"_JAR")).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();if(!actual.equals(expected)||Files.size(actual)>16_777_216||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(System.getenv("REVETSEC_RESOURCE_"+kind+"_SHA256")))throw new IOException("Selected artifact origin mismatch");}catch(java.net.URISyntaxException|GeneralSecurityException|RuntimeException failure){throw new IOException("Selected artifact origin unavailable");}}
    private @NonNull URI uri(@NonNull String path){return URI.create(this.issuer+path);}
    private @NonNull String token(){byte[] bytes=new byte[32];this.random.nextBytes(bytes);return b64(bytes);}
    private static @NonNull String hash(@NonNull String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture hash unavailable");}}
    private static @NonNull String jwks(){RSAPublicKey key=(RSAPublicKey)KEY.getPublic();return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"resource\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\""+unsigned(key.getModulus())+"\",\"e\":\""+unsigned(key.getPublicExponent())+"\"}]}";}
    private static @NonNull String b64(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static @NonNull String unsigned(java.math.@NonNull BigInteger value){byte[] bytes=value.toByteArray();return b64(bytes.length>1&&bytes[0]==0?Arrays.copyOfRange(bytes,1,bytes.length):bytes);}
    private static @NonNull KeyPair key(@NonNull String label){try{SecureRandom random=SecureRandom.getInstance("SHA1PRNG");random.setSeed(label.getBytes(StandardCharsets.US_ASCII));KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048,random);return generator.generateKeyPair();}catch(GeneralSecurityException unavailable){throw new ExceptionInInitializerError(unavailable);}}
    private static @NonNull String sign(@NonNull KeyPair key,@NonNull String payload,@NonNull String type){try{String input=b64(JsonObject.builder().put("alg","RS256").put("kid","resource").put("typ",type).build().toJson().getBytes(StandardCharsets.UTF_8))+'.'+b64(payload.getBytes(StandardCharsets.UTF_8));Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key.getPrivate());signature.update(input.getBytes(StandardCharsets.US_ASCII));return input+'.'+b64(signature.sign());}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture signing unavailable");}}
    private static void reply(@NonNull HttpExchange exchange,int status,@NonNull String media,@NonNull String body)throws IOException{byte[] bytes=body.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type",media);exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.sendResponseHeaders(status,bytes.length);try(var output=exchange.getResponseBody()){output.write(bytes);}exchange.close();}
    @Override public void close(){Block paused=this.block.getAndSet(null);if(paused!=null)paused.release.countDown();this.server.stop(0);this.serverExecutor.shutdownNow();this.clientExecutor.shutdownNow();}
    private static final class Block{final @NonNull String stage;final @NonNull AtomicInteger active=new AtomicInteger();final @NonNull CountDownLatch release=new CountDownLatch(1);Block(@NonNull String stage){this.stage=stage;}}
    private static final class MutableClock extends Clock{final @NonNull AtomicReference<@NonNull Instant> value=new AtomicReference<>(Instant.parse("2026-11-05T12:00:00Z"));void advance(long seconds){this.value.updateAndGet(value->value.plusSeconds(seconds));}@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}@Override public @NonNull Instant instant(){return this.value.get();}}
}
