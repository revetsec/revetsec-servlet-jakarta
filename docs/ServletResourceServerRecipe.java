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
import com.revetsec.oauth.AccessToken;
import com.revetsec.oauth.AccessTokenAcquisitionResult;
import com.revetsec.oauth.AccessTokenValidationResult;
import com.revetsec.oauth.AccessTokenValidator;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.BearerChallenge;
import com.revetsec.oauth.BearerError;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.ClientCredentialsTokenSource;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.TokenIntrospectionClient;
import com.revetsec.oauth.VerifiedAccessToken;
import com.revetsec.servlet.jakarta.ServletBearer;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

/**
 * S2 application host for one trusted startup validation profile and a read-only service-token fetch.
 * No credential is returned or used as a session/authorization decision; only the core acquisition source caches its own service token.
 * The unpublished recipe adds no core/adapter API and implements no downstream mutations.
 */
@ThreadSafe
@SuppressWarnings("serial")
public final class ServletResourceServerRecipe extends HttpServlet{
    private static final long serialVersionUID=1L;
    public record Configuration(@NonNull URI origin,@NonNull String servletPath,@NonNull String issuer,
            @NonNull URI audience,@NonNull URI backendAudience,@NonNull String introspectionClientId,@NonNull String acquisitionClientId){
        public Configuration{
            Objects.requireNonNull(origin);Objects.requireNonNull(servletPath);Objects.requireNonNull(issuer);Objects.requireNonNull(audience);Objects.requireNonNull(backendAudience);
            checked(introspectionClientId);checked(acquisitionClientId);
            if(!https(origin)||!origin.getRawPath().isEmpty()||!servletPath.matches("/[a-z][a-z0-9-]{0,31}")||!https(audience)||!https(backendAudience))throw new IllegalArgumentException("Fixed trusted resource configuration required");
            URI provider=URI.create(issuer);if(!provider.isAbsolute()||provider.getHost()==null||provider.getRawUserInfo()!=null||provider.getRawQuery()!=null||provider.getRawFragment()!=null)throw new IllegalArgumentException("Exact issuer required");
        }
        @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
    }
    public record Account(@NonNull String id,@NonNull String tenant,long generation){
        public Account{if(!id.matches("[A-Za-z0-9_-]{1,64}")||!tenant.matches("[A-Za-z0-9_-]{1,64}")||generation<1)throw new IllegalArgumentException("Bounded current account required");}
        @Override public @NonNull String toString(){return "Account{<redacted>}";}
    }
    public enum Operation{READ,PROXY_READ}
    /** Both operations re-read current issuer/subject/account generation and tenant/object policy. */
    public interface Accounts{
        @NonNull Optional<@NonNull Account> lookup(@NonNull String issuer,@NonNull String subject,@NonNull String clientId,@NonNull Duration remaining)throws Exception;
        boolean authorize(@NonNull Account account,@NonNull String issuer,@NonNull String subject,@NonNull String clientId,@NonNull Operation operation,@NonNull Duration remaining)throws Exception;
    }
    @FunctionalInterface public interface Resources{@NonNull String read(@NonNull String tenant,@NonNull String accountId,@NonNull Duration remaining)throws Exception;}
    /** Only a fixed-target, bounded, read-only GET. No caller-selected URL, redirects, retry or mutation. */
    @FunctionalInterface public interface Backend{@NonNull BackendResponse read(@NonNull Account account,@NonNull AccessToken credential,@NonNull Duration remaining)throws Exception;}
    public record BackendResponse(int status,@Nullable String value){
        public BackendResponse{if(!Set.of(200,401,403,503).contains(status)||(status==200)!=(value!=null))throw new IllegalArgumentException("Bounded backend outcome required");if(value!=null)payload(value);}
        @Override public @NonNull String toString(){return "BackendResponse{status="+status+", value=<redacted>}";}
    }
    @FunctionalInterface public interface Admission{boolean allow(@NonNull String trustedPeer,@NonNull Duration remaining)throws Exception;}
    private final @NonNull Configuration config;
    private final @NonNull AccessTokenValidator validator;
    private final @NonNull ClientCredentialsTokenSource acquisition;
    private final @NonNull Accounts accounts;
    private final @NonNull Resources resources;
    private final @NonNull Backend backend;
    private final @NonNull Admission admission;
    private final @NonNull Clock clock;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull Semaphore work=new Semaphore(8);

    /** Trusted startup JWT profile; there is no JWT-to-introspection fallback. */
    public static @NonNull ServletResourceServerRecipe createJwt(@NonNull Configuration config,@NonNull AuthorizationServerMetadata metadata,
            @NonNull URI jwksUri,@NonNull String acquisitionSecret,@NonNull Accounts accounts,@NonNull Resources resources,@NonNull Backend backend,@NonNull Admission admission){
        startup(config,metadata);Clock clock=Clock.systemUTC();
        var keys=RemoteJwksSource.withUri(jwksUri).clock(clock).requestTimeout(Duration.ofSeconds(1)).maximumKeys(8).maximumResponseBytes(65_536).maximumStaleness(Duration.ZERO).build();
        var validator=JwtAccessTokenValidator.withIssuer(config.issuer()).jwksSource(keys).expectedAudiences(Set.of(config.audience().toString()))
                .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).requiredClaims(Set.of("tenant","scope"))
                .maximumTokenLength(8192).clockSkew(Duration.ZERO).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).clock(clock).build();
        return new ServletResourceServerRecipe(config,validator,source(config,metadata,acquisitionSecret,clock),accounts,resources,backend,admission,clock,System::nanoTime);
    }
    /** Trusted startup opaque-introspection profile with fixed confidential client-secret Basic authentication. */
    public static @NonNull ServletResourceServerRecipe createIntrospection(@NonNull Configuration config,@NonNull AuthorizationServerMetadata metadata,
            @NonNull String introspectionSecret,@NonNull String acquisitionSecret,@NonNull Accounts accounts,@NonNull Resources resources,@NonNull Backend backend,@NonNull Admission admission){
        startup(config,metadata);Clock clock=Clock.systemUTC();
        OAuthClient client=OAuthClient.withAuthorizationServerMetadata(metadata).clientId(config.introspectionClientId())
                .clientAuthentication(ClientAuthentication.fromClientSecretBasic(introspectionSecret)).clock(clock)
                .requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).build();
        var validator=TokenIntrospectionClient.withOAuthClient(client).introspectionEndpoint(metadata.getIntrospectionEndpoint().orElseThrow())
                .expectedAudiences(Set.of(config.audience().toString())).requiredClaims(Set.of("exp","sub","client_id","tenant","scope"))
                .maximumTokenLength(8192).clockSkew(Duration.ZERO).build();
        return new ServletResourceServerRecipe(config,validator,source(config,metadata,acquisitionSecret,clock),accounts,resources,backend,admission,clock,System::nanoTime);
    }
    private static void startup(@NonNull Configuration config,@NonNull AuthorizationServerMetadata metadata){if(!"https".equals(URI.create(config.issuer()).getScheme())||!metadata.getIssuer().equals(config.issuer()))throw new IllegalArgumentException("Exact HTTPS issuer required");}
    private static @NonNull ClientCredentialsTokenSource source(@NonNull Configuration config,@NonNull AuthorizationServerMetadata metadata,@NonNull String secret,@NonNull Clock clock){
        OAuthClient client=OAuthClient.withAuthorizationServerMetadata(metadata).clientId(config.acquisitionClientId()).clientAuthentication(ClientAuthentication.fromClientSecretBasic(secret))
                .clock(clock).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).build();
        return ClientCredentialsTokenSource.withClient(client).scopes(Set.of("backend:read")).resources(List.of(config.backendAudience())).build();
    }
    ServletResourceServerRecipe(@NonNull Configuration config,@NonNull AccessTokenValidator validator,@NonNull ClientCredentialsTokenSource acquisition,
            @NonNull Accounts accounts,@NonNull Resources resources,@NonNull Backend backend,@NonNull Admission admission,@NonNull Clock clock,@NonNull LongSupplier nanoTime){
        this.config=Objects.requireNonNull(config);this.validator=Objects.requireNonNull(validator);this.acquisition=Objects.requireNonNull(acquisition);this.accounts=Objects.requireNonNull(accounts);
        this.resources=Objects.requireNonNull(resources);this.backend=Objects.requireNonNull(backend);this.admission=Objects.requireNonNull(admission);this.clock=Objects.requireNonNull(clock);this.nanoTime=Objects.requireNonNull(nanoTime);
    }
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        Budget budget=new Budget(this.nanoTime);
        try{
            budget.check();String path=request.getPathInfo();
            if(path==null||!request.getServletPath().equals(this.config.servletPath())||!request.getRequestURI().equals(request.getContextPath()+this.config.servletPath()+path)
                    ||!request.isSecure()||!request.getScheme().equals("https")||request.getQueryString()!=null)throw new Denied(400,null,null);
            Map<String,List<String>> headers=headers(request);
            if(!one(headers,"host").equalsIgnoreCase(this.config.origin().getRawAuthority())||headers.containsKey("cookie"))throw new Denied(400,null,null);
            List<String> origins=headers.getOrDefault("origin",List.of());if(!origins.isEmpty()&&!origins.equals(List.of(this.config.origin().toString())))throw new Denied(403,null,null);
            String[] segments=path.split("/",-1);if(segments.length!=4&&segments.length!=5||!segments[1].equals("accounts")||!segments[2].matches("[A-Za-z0-9_-]{1,64}")||!segments[3].matches("[A-Za-z0-9_-]{1,64}"))throw new Denied(404,null,null);
            Operation operation;
            if(segments.length==4){
                if(!request.getMethod().equals("GET"))throw new Denied(405,null,null);
                if(request.getContentLengthLong()>0||headers.containsKey("transfer-encoding"))throw new Denied(400,null,null);operation=Operation.READ;
            }else{
                if(!segments[4].equals("proxy-read"))throw new Denied(404,null,null);
                if(!request.getMethod().equals("POST"))throw new Denied(405,null,null);
                if(!one(headers,"content-type").equalsIgnoreCase("application/x-www-form-urlencoded"))throw new Denied(415,null,null);
                if(request.getContentLengthLong()>128)throw new Denied(413,null,null);byte[] body=request.getInputStream().readNBytes(129);
                if(body.length>128)throw new Denied(413,null,null);if(!java.security.MessageDigest.isEqual(body,"read=1".getBytes(StandardCharsets.US_ASCII)))throw new Denied(400,null,null);operation=Operation.PROXY_READ;
            }
            BearerTokenResult parsed=ServletBearer.bearerTokenResultFor(request);
            String scope=operation==Operation.READ?"accounts:read":"accounts:proxy";
            if(parsed instanceof BearerTokenResult.Absent)throw new Denied(401,null,scope);
            if(!(parsed instanceof BearerTokenResult.Present present))throw new Denied(400,BearerError.INVALID_REQUEST,scope);
            if(!this.work.tryAcquire())throw new Denied(503,null,null);
            try{
                if(!this.admission.allow(request.getRemoteAddr(),budget.remaining()))throw new Denied(429,null,null);budget.beforeCore();
                AccessTokenValidationResult checked=this.validator.validateResult(present.getToken());budget.check();
                if(checked instanceof AccessTokenValidationResult.Rejected rejection)throw new Denied(rejection.getBearerError()==BearerError.INVALID_REQUEST?400:401,rejection.getBearerError(),scope);
                if(!(checked instanceof AccessTokenValidationResult.Succeeded success))throw new Denied(503,null,null);
                VerifiedAccessToken proof=success.getAccessToken();
                if(!proof.getIssuer().equals(this.config.issuer())||!proof.getAudiences().equals(List.of(this.config.audience().toString()))
                        ||proof.getExpiresAt().isEmpty()||!this.clock.instant().isBefore(proof.getExpiresAt().orElseThrow()))throw new Denied(401,BearerError.INVALID_TOKEN,scope);
                String subject=proof.getSubject().orElse(""),clientId=proof.getClientId().orElse("");
                if(!identity(subject)||!identity(clientId)||!(proof.getClaims().getMembers().get("tenant") instanceof JsonString claim)||!claim.getValue().matches("[A-Za-z0-9_-]{1,64}"))throw new Denied(401,BearerError.INVALID_TOKEN,scope);
                if(!proof.getScopes().contains(scope))throw new Denied(403,BearerError.INSUFFICIENT_SCOPE,scope);
                Optional<Account> found=this.accounts.lookup(proof.getIssuer(),subject,clientId,budget.remaining());budget.check();fresh(proof,scope);
                if(found.isEmpty())throw new Denied(403,null,null);Account account=found.orElseThrow();
                if(!account.tenant().equals(claim.getValue())||!account.tenant().equals(segments[2])||!account.id().equals(segments[3]))throw new Denied(403,null,null);
                if(!this.accounts.authorize(account,proof.getIssuer(),subject,clientId,operation,budget.remaining()))throw new Denied(403,null,null);budget.check();fresh(proof,scope);
                String value;
                if(operation==Operation.READ)value=this.resources.read(segments[2],segments[3],budget.remaining());
                else{
                    budget.beforeCore();AccessTokenAcquisitionResult acquired=this.acquisition.getAccessTokenResult();budget.check();fresh(proof,scope);
                    if(!(acquired instanceof AccessTokenAcquisitionResult.Succeeded supplied))throw new Denied(503,null,null);
                    AccessToken token=supplied.getAccessToken();
                    if(!token.isBearer()||token.getValue().length()>8192||token.getExpiresAt().isEmpty()||!this.clock.instant().isBefore(token.getExpiresAt().orElseThrow()))throw new Denied(503,null,null);
                    token.getAuthorizationHeaderValue();
                    if(!this.accounts.authorize(account,proof.getIssuer(),subject,clientId,operation,budget.remaining()))throw new Denied(403,null,null);budget.check();fresh(proof,scope);
                    BackendResponse reply=this.backend.read(account,token,budget.remaining());
                    if(reply.status()==401){this.acquisition.invalidate(token);throw new Denied(503,null,null);}
                    budget.check();fresh(proof,scope);
                    if(reply.status()!=200)throw new Denied(503,null,null);value=Objects.requireNonNull(reply.value());
                    if(!this.clock.instant().isBefore(token.getExpiresAt().orElseThrow()))throw new Denied(503,null,null);
                }
                payload(value);budget.check();fresh(proof,scope);
                if(!this.accounts.authorize(account,proof.getIssuer(),subject,clientId,operation,budget.remaining()))throw new Denied(403,null,null);budget.check();fresh(proof,scope);
                send(response,request,200,JsonObject.builder().put("tenant",account.tenant()).put("account",account.id()).put("value",value).build(),null);return;
            }finally{this.work.release();}
        }catch(Denied denial){
            String challenge=null;if(denial.scope!=null){var builder=BearerChallenge.builder().realm("accounts").scopes(List.of(denial.scope));if(denial.error!=null)builder.error(denial.error);challenge=builder.build().getHeaderValue();}
            send(response,request,denial.status,JsonObject.builder().put("error",denial.status>=500?"Temporarily unavailable":"Request denied").build(),challenge);
        }catch(Exception unavailable){send(response,request,503,JsonObject.builder().put("error","Temporarily unavailable").build(),null);}
    }
    private void fresh(@NonNull VerifiedAccessToken proof,@NonNull String scope){if(!this.clock.instant().isBefore(proof.getExpiresAt().orElseThrow()))throw new Denied(401,BearerError.INVALID_TOKEN,scope);}
    private static final class Budget{
        final @NonNull LongSupplier time;final long end;
        Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(6).toNanos();}
        void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Denied(503,null,null);}
        void beforeCore(){check();if(this.end-this.time.getAsLong()<Duration.ofSeconds(3).toNanos())throw new Denied(503,null,null);}
        @NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}
    }
    private static final class Denied extends RuntimeException{private static final long serialVersionUID=1L;final int status;final @Nullable BearerError error;final @Nullable String scope;Denied(int status,@Nullable BearerError error,@Nullable String scope){super("Request denied");this.status=status;this.error=error;this.scope=scope;}}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){
        Enumeration<String> names=request.getHeaderNames();if(names==null)throw new Denied(400,null,null);Map<String,List<String>> result=new LinkedHashMap<>();int count=0,occurrences=0;long bytes=0;
        while(names.hasMoreElements()){if(++count>32)throw new Denied(400,null,null);String name=names.nextElement();if(name==null||!name.matches("[A-Za-z0-9-]{1,64}"))throw new Denied(400,null,null);Enumeration<String> values=request.getHeaders(name);if(values==null)throw new Denied(400,null,null);List<String> copy=new ArrayList<>();
            while(values.hasMoreElements()){if(++occurrences>32)throw new Denied(400,null,null);String value=values.nextElement();if(value==null||value.length()>8192||!ascii(value))throw new Denied(400,null,null);bytes+=name.length()+value.length();if(bytes>16_384)throw new Denied(400,null,null);copy.add(value);}
            if(copy.isEmpty()||result.putIfAbsent(name.toLowerCase(java.util.Locale.ROOT),List.copyOf(copy))!=null)throw new Denied(400,null,null);
        }return Map.copyOf(result);
    }
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){List<String> values=headers.getOrDefault(name,List.of());if(values.size()!=1)throw new Denied(400,null,null);return values.get(0);}
    private static boolean https(@NonNull URI uri){return uri.isAbsolute()&&"https".equals(uri.getScheme())&&uri.getHost()!=null&&uri.getRawUserInfo()==null&&uri.getRawQuery()==null&&uri.getRawFragment()==null&&uri.getPort()!=0&&uri.getPort()<=65535;}
    private static boolean ascii(@NonNull String value){return value.chars().allMatch(c->c>=0x20&&c<=0x7e);}
    private static boolean identity(@NonNull String value){return !value.isEmpty()&&value.length()<=255&&value.chars().allMatch(c->c>=0x21&&c<=0x7e);}
    private static void checked(@NonNull String value){if(!identity(value))throw new IllegalArgumentException("Bounded client ID required");}
    private static void payload(@NonNull String value){if(value.length()>1024||!ascii(value))throw new IllegalArgumentException("Bounded protected payload required");}
    private static void send(@NonNull HttpServletResponse response,@NonNull HttpServletRequest request,int status,@NonNull JsonObject body,@Nullable String challenge)throws IOException{
        response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setHeader("Pragma","no-cache");response.setHeader("Referrer-Policy","no-referrer");response.setHeader("X-Content-Type-Options","nosniff");response.setContentType("application/json; charset=UTF-8");if(challenge!=null)response.setHeader("WWW-Authenticate",challenge);
        byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);if(!request.getMethod().equals("HEAD"))response.getOutputStream().write(bytes);
    }
    @Override public @NonNull String toString(){return "ServletResourceServerRecipe{profile/services=<redacted>}";}
}
