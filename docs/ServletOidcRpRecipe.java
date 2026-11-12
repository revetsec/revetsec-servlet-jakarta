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

import com.revetsec.BrowserBinding;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.RemoteJwksSource;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.InMemoryPendingAuthorizationStore;
import com.revetsec.oauth.IssuerParameterPolicy;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oidc.OidcAuthentication;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.oidc.OidcAuthenticationResult;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.servlet.jakarta.ServletOAuth;
import com.revetsec.servlet.jakarta.ServletOAuthCallbackResult;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

/**
 * Complete single-process S1 application host. Register an injected instance at a fixed {@code /oidc/*}
 * mapping. Current account, admission and deployment/recovery policy remain application responsibilities.
 * This unpublished cookbook adds no core or Servlet adapter API and performs no RP-Initiated Logout.
 */
@ThreadSafe
@SuppressWarnings("serial")
public final class ServletOidcRpRecipe extends HttpServlet {
    private static final long serialVersionUID = 1L;
    public static final @NonNull String SESSION_COOKIE="__Host-oidc-session",PENDING_COOKIE="__Host-oidc-pending";
    private static final long SESSION_NANOS=Duration.ofMinutes(30).toNanos(),PENDING_NANOS=Duration.ofMinutes(5).toNanos();
    private static final int MAXIMUM_ENTRIES=128;
    private static final long MAXIMUM_BYTES=65_536;
    public record Configuration(@NonNull URI origin,@NonNull URI callback,@NonNull String issuer,@NonNull String clientId){
        public Configuration{
            Objects.requireNonNull(origin);Objects.requireNonNull(callback);Objects.requireNonNull(issuer);Objects.requireNonNull(clientId);
            if(!"https".equals(origin.getScheme())||origin.getHost()==null||origin.getRawUserInfo()!=null||origin.getRawQuery()!=null||origin.getRawFragment()!=null
                    ||!origin.getRawPath().isEmpty()||origin.getPort()==0||origin.getPort()>65535
                    ||!callback.equals(origin.resolve("/oidc/callback"))||clientId.isEmpty()||clientId.length()>255||!ascii(clientId))
                throw new IllegalArgumentException("Fixed trusted RP configuration required");
            URI provider=URI.create(issuer);
            if(!provider.isAbsolute()||provider.getHost()==null||provider.getRawUserInfo()!=null||provider.getRawQuery()!=null||provider.getRawFragment()!=null)
                throw new IllegalArgumentException("Exact provider issuer required");
        }
        @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
    }
    public record Account(@NonNull String id,@NonNull String tenant){
        public Account{if(!id.matches("[A-Za-z0-9_-]{1,64}")||!tenant.matches("[A-Za-z0-9_-]{1,64}"))throw new IllegalArgumentException("Bounded local IDs required");}
        @Override public @NonNull String toString(){return "Account{<redacted>}";}
    }
    /** Read-only current issuer/sub login lookup and current policy on every protected request. */
    public interface Accounts{
        @NonNull Optional<@NonNull Account> findAndAuthorizeLogin(@NonNull String issuer,@NonNull String subject,@NonNull Duration remaining)throws Exception;
        boolean authorize(@NonNull Account account,@NonNull String tenant,@NonNull String id,@NonNull Duration remaining)throws Exception;
    }
    @FunctionalInterface public interface Admission{boolean allow(@NonNull String trustedPeer,@NonNull Duration remaining)throws Exception;}
    private final @NonNull Configuration config;
    private final @NonNull OidcClient client;
    private final @NonNull PendingAuthorizationStore pending;
    private final @NonNull Accounts accounts;
    private final @NonNull Admission admission;
    private final @NonNull Clock clock;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull SecureRandom random=new SecureRandom();
    private final @NonNull Semaphore work=new Semaphore(8);
    private final @NonNull Map<@NonNull String,@NonNull Session> sessions=new LinkedHashMap<>();
    private final @NonNull Map<@NonNull String,@NonNull Attempt> attempts=new LinkedHashMap<>();
    private long bytes;

    /** Fixed narrow production policy; metadata/authentication are trusted startup inputs, never request values. */
    public static @NonNull ServletOidcRpRecipe create(@NonNull Configuration config,@NonNull OidcProviderMetadata metadata,
            @NonNull ClientAuthentication authentication,@NonNull Accounts accounts,@NonNull Admission admission){
        if(!"https".equals(URI.create(config.issuer()).getScheme())||!metadata.getIssuer().equals(config.issuer()))throw new IllegalArgumentException("Exact configured issuer required");
        Clock clock=Clock.systemUTC();
        OidcClient client=OidcClient.withProviderMetadata(metadata).clientId(config.clientId()).redirectUri(config.callback())
                .clientAuthentication(authentication).scopes(Set.of("openid")).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256))
                .issuerParameterPolicy(IssuerParameterPolicy.REQUIRED).requirePkceAdvertised(true).clockSkew(Duration.ZERO)
                .pendingAuthorizationLifetime(Duration.ofMinutes(5)).maximumIdTokenAge(Duration.ofMinutes(5))
                .requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).clock(clock)
                .jwksSource(RemoteJwksSource.withUri(metadata.getJwksUri()).clock(clock).requestTimeout(Duration.ofSeconds(1))
                        .maximumResponseBytes(65_536).maximumKeys(8).maximumStaleness(Duration.ZERO).build()).build();
        PendingAuthorizationStore pending=InMemoryPendingAuthorizationStore.builder().clock(clock)
                .maximumLiveEntries(128).maximumChargedBytes(524_288L).maximumOpaqueRecordBytes(4096).build();
        return new ServletOidcRpRecipe(config,client,pending,accounts,admission,clock,System::nanoTime);
    }
    ServletOidcRpRecipe(@NonNull Configuration config,@NonNull OidcClient client,@NonNull PendingAuthorizationStore pending,
            @NonNull Accounts accounts,@NonNull Admission admission,@NonNull Clock clock,@NonNull LongSupplier nanoTime){
        this.config=Objects.requireNonNull(config);this.client=Objects.requireNonNull(client);this.pending=Objects.requireNonNull(pending);
        this.accounts=Objects.requireNonNull(accounts);this.admission=Objects.requireNonNull(admission);this.clock=Objects.requireNonNull(clock);this.nanoTime=Objects.requireNonNull(nanoTime);
    }
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        Budget budget=new Budget(this.nanoTime);boolean callback="/callback".equals(request.getPathInfo());boolean clear=false;
        try{
            budget.check();
            if(callback&&!request.getMethod().equals("GET")&&!request.getMethod().equals("POST")){send(response,request,405,json("error","Request denied"),List.of(),null);return;}
            String path=request.getPathInfo();
            if(path==null||!request.getRequestURI().equals(request.getContextPath()+request.getServletPath()+path)
                    ||!request.isSecure()||!request.getScheme().equals("https"))throw new Denied(400);
            Map<String,List<String>> headers=headers(request);
            if(!one(headers,"host").equalsIgnoreCase(this.config.origin().getRawAuthority()))throw new Denied(400);
            if(request.getMethod().equals("GET")&&(request.getContentLengthLong()>0||headers.containsKey("transfer-encoding")))throw new Denied(400);
            if(callback){
                if(request.getContentLengthLong()>32_768)throw new Denied(413);
                ServletOAuthCallbackResult parsed=ServletOAuth.authorizationResponseResultFor(request);
                if(!(parsed instanceof ServletOAuthCallbackResult.Succeeded read))throw new Denied(parsed instanceof ServletOAuthCallbackResult.TooLarge?413:400);
                List<String> origin=headers.getOrDefault("origin",List.of());
                URI issuer=URI.create(this.config.issuer());String providerOrigin=issuer.getScheme()+"://"+issuer.getRawAuthority();
                if(!origin.isEmpty()&&!origin.equals(List.of(providerOrigin)))throw new Denied(403);
                String cookie=cookie(headers,PENDING_COOKIE);
                if(cookie==null||!cookie.matches("[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}"))throw new Denied(401);
                Session old=session(headers,true);String id=cookie.substring(0,43),binding=cookie.substring(44);
                if(!this.work.tryAcquire())throw new Denied(503);
                Attempt selected=null;
                try{
                    BrowserBinding trustedBinding;
                    synchronized(this.sessions){
                        Attempt value=this.attempts.get(id);
                        if(value!=null&&!value.claimed&&!value.live(this.clock.instant(),this.nanoTime.getAsLong())){discard(value);value=null;}
                        if(value==null||value.claimed||!value.ready||value.old!=old||!same(value.binding.toSecretString(),binding)
                                ||!value.live(this.clock.instant(),this.nanoTime.getAsLong())||!current(old))throw new Denied(401);
                        value.claimed=true;selected=value;trustedBinding=value.binding;clear=true;
                    }
                    budget.beforeCore();
                    OidcAuthenticationResult result=this.client.completeAuthenticationResult(read.getResponse(),
                            PendingAuthorizationSource.fromStore(this.pending,trustedBinding),this.config.callback());
                    budget.check();
                    if(!(result instanceof OidcAuthenticationResult.Succeeded success))throw new Denied(result instanceof OidcAuthenticationResult.Failed?503:400);
                    synchronized(this.sessions){if(this.attempts.get(id)!=selected||!current(old))throw new Denied(401);}
                    OidcAuthentication authentication=success.getAuthentication();
                    String subject=authentication.getSubject();if(subject.isEmpty()||subject.length()>255||!ascii(subject))throw new Denied(400);
                    Optional<Account> found=this.accounts.findAndAuthorizeLogin(authentication.getIssuer(),subject,budget.remaining());budget.check();
                    if(found.isEmpty())throw new Denied(403);
                    Account account=found.orElseThrow();Session replacement=new Session(token(),token(),account,this.clock.instant(),this.nanoTime.getAsLong()+SESSION_NANOS);
                    synchronized(this.sessions){
                        Instant now=this.clock.instant();
                        if(this.attempts.get(id)!=selected||!selected.live(now,this.nanoTime.getAsLong())||!current(old)
                                ||now.isBefore(authentication.getIdToken().getClaims().getIssuedAt().orElseThrow())
                                ||!now.isBefore(authentication.getIdToken().getClaims().getExpiresAt().orElseThrow())
                                ||now.isBefore(authentication.getAuthenticationTime().orElseThrow())
                                ||now.isAfter(authentication.getAuthenticationTime().orElseThrow().plusSeconds(300)))throw new Denied(401);
                        long released=selected.charge+old.charge();
                        if(replacement.charge()>MAXIMUM_BYTES-(this.bytes-released)||this.sessions.containsKey(replacement.id))throw new Denied(503);
                        budget.check();discard(selected);this.sessions.remove(old.id);this.bytes-=old.charge();
                        this.sessions.put(replacement.id,replacement);this.bytes+=replacement.charge();
                    }
                    budget.check();send(response,request,303,JsonObject.builder().put("authenticated",true).build(),
                            List.of(sessionCookie(replacement),pendingCookie("",0)),this.config.origin().resolve("/oidc/session"));return;
                }finally{
                    synchronized(this.sessions){if(selected!=null)discard(selected);}this.work.release();
                }
            }
            if(request.getQueryString()!=null)throw new Denied(400);
            if(path.equals("/session")&&request.getMethod().equals("GET")){
                if(request.getContentLengthLong()>0)throw new Denied(400);
                Session selected=session(headers,false);
                send(response,request,200,selected==null?JsonObject.builder().put("authenticated",false).build():
                        JsonObject.builder().put("authenticated",selected.account!=null).put("csrf",selected.csrf).build(),List.of(),null);return;
            }
            if(path.startsWith("/account/")){
                if(!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new Denied(405);
                String[] parts=path.split("/",-1);if(parts.length!=4)throw new Denied(404);
                Session selected=session(headers,true);Account account=selected.account;
                if(account==null||!account.tenant().equals(parts[2])||!account.id().equals(parts[3]))throw new Denied(403);
                if(!this.work.tryAcquire())throw new Denied(503);
                try{
                    if(!this.accounts.authorize(account,parts[2],parts[3],budget.remaining()))throw new Denied(403);budget.check();
                    synchronized(this.sessions){if(!current(selected))throw new Denied(401);}
                    send(response,request,200,json("access","permitted"),List.of(),null);return;
                }finally{this.work.release();}
            }
            if(!request.getMethod().equals("POST"))throw new Denied(405);
            if(!headers.getOrDefault("origin",List.of()).equals(List.of(this.config.origin().toString())))throw new Denied(403);
            String type=one(headers,"content-type");
            if(!type.equalsIgnoreCase("application/x-www-form-urlencoded"))throw new Denied(415);
            if(request.getContentLengthLong()>128)throw new Denied(413);
            byte[] body=request.getInputStream().readNBytes(129);if(body.length>128)throw new Denied(413);
            if(path.equals("/session")){
                if(!MessageDigest.isEqual(body,"begin=1".getBytes(StandardCharsets.US_ASCII)))throw new Denied(400);
                if(!this.admission.allow(request.getRemoteAddr(),budget.remaining()))throw new Denied(429);budget.check();
                Session selected=session(headers,false);
                synchronized(this.sessions){
                    cleanup();
                    if(selected==null){
                        selected=new Session(token(),token(),null,this.clock.instant(),this.nanoTime.getAsLong()+SESSION_NANOS);
                        if(this.sessions.size()>=MAXIMUM_ENTRIES||selected.charge()>MAXIMUM_BYTES-this.bytes||this.sessions.containsKey(selected.id))throw new Denied(503);
                        budget.check();this.sessions.put(selected.id,selected);this.bytes+=selected.charge();
                    }else if(!current(selected))throw new Denied(401);
                }
                send(response,request,200,JsonObject.builder().put("authenticated",selected.account!=null).put("csrf",selected.csrf).build(),List.of(sessionCookie(selected)),null);return;
            }
            Session selected=session(headers,true);
            if(!MessageDigest.isEqual(body,("csrf="+selected.csrf).getBytes(StandardCharsets.US_ASCII)))throw new Denied(403);
            if(path.equals("/logout")){
                synchronized(this.sessions){
                    if(!current(selected))throw new Denied(401);
                    this.sessions.remove(selected.id);this.bytes-=selected.charge();
                    if(selected.pendingId!=null){Attempt attempt=this.attempts.get(selected.pendingId);if(attempt!=null&&!attempt.claimed)discard(attempt);}
                }
                send(response,request,200,JsonObject.builder().put("authenticated",false).build(),List.of(sessionCookie("",0,false),pendingCookie("",0)),null);return;
            }
            AuthorizationRequestOptions.ResponseMode mode;
            if(path.equals("/login/query"))mode=AuthorizationRequestOptions.ResponseMode.QUERY;
            else if(path.equals("/login/form-post"))mode=AuthorizationRequestOptions.ResponseMode.FORM_POST;
            else throw new Denied(404);
            if(!this.admission.allow(request.getRemoteAddr(),budget.remaining()))throw new Denied(429);budget.check();
            if(!this.work.tryAcquire())throw new Denied(503);
            Attempt attempt=null;
            try{
                synchronized(this.sessions){
                    cleanup();if(!current(selected)||selected.account!=null||selected.pendingId!=null)throw new Denied(409);
                    Attempt prepared=new Attempt(token(),BrowserBinding.fresh(),selected,this.clock.instant(),this.nanoTime.getAsLong()+PENDING_NANOS);
                    if(this.attempts.size()>=MAXIMUM_ENTRIES||prepared.charge+43>MAXIMUM_BYTES-this.bytes||this.attempts.containsKey(prepared.id))throw new Denied(503);
                    budget.check();selected.pendingId=prepared.id;this.bytes+=43;this.attempts.put(prepared.id,prepared);this.bytes+=prepared.charge;attempt=prepared;
                }
                budget.beforeCore();
                AuthorizationRedirect redirect=this.client.beginAuthentication(OidcAuthenticationOptions.builder().responseMode(mode).maxAge(Duration.ofMinutes(5)).prompt("login").build());
                if(redirect.getPendingAuthorization().saveToResult(this.pending,attempt.binding,budget.remaining())!=PendingAuthorizationSaveResult.SAVED)throw new Denied(503);
                synchronized(this.sessions){if(this.attempts.get(attempt.id)!=attempt||!current(selected)||!attempt.live(this.clock.instant(),this.nanoTime.getAsLong()))throw new Denied(401);budget.check();attempt.ready=true;}
                response.addHeader("Set-Cookie",pendingCookie(attempt.id+'.'+attempt.binding.toSecretString(),300));
                ServletOAuth.writeRedirect(response,redirect.getAuthorizationUri());return;
            }finally{
                synchronized(this.sessions){if(attempt!=null&&!attempt.ready)discard(attempt);}this.work.release();
            }
        }catch(Denied denial){send(response,request,denial.status,json("error","Request denied"),clear?List.of(pendingCookie("",0)):List.of(),null);}
        catch(Exception unavailable){send(response,request,503,json("error","Temporarily unavailable"),clear?List.of(pendingCookie("",0)):List.of(),null);}
    }
    private @Nullable Session session(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,boolean required){
        if(!headers.getOrDefault("authorization",List.of()).isEmpty())throw new Denied(400);
        String id=cookie(headers,SESSION_COOKIE);if(id==null){if(required)throw new Denied(401);return null;}
        if(!id.matches("[A-Za-z0-9_-]{43}"))throw new Denied(401);
        synchronized(this.sessions){Session value=this.sessions.get(id);if(value==null||!current(value)){if(required)throw new Denied(401);return null;}return value;}
    }
    private boolean current(@NonNull Session session){
        if(this.sessions.get(session.id)!=session)return false;
        if(session.live(this.clock.instant(),this.nanoTime.getAsLong()))return true;
        this.sessions.remove(session.id);this.bytes-=session.charge();
        if(session.pendingId!=null){Attempt attempt=this.attempts.get(session.pendingId);if(attempt!=null&&!attempt.claimed)discard(attempt);}
        return false;
    }
    private void discard(@NonNull Attempt attempt){
        if(this.attempts.remove(attempt.id,attempt)){
            this.bytes-=attempt.charge;
            if(attempt.id.equals(attempt.old.pendingId)){
                if(this.sessions.get(attempt.old.id)==attempt.old)this.bytes-=43;
                attempt.old.pendingId=null;
            }
        }
    }
    private void cleanup(){
        Instant now=this.clock.instant();long elapsed=this.nanoTime.getAsLong();int count=0;List<Attempt> retained=new ArrayList<>();
        for(Iterator<Attempt> it=this.attempts.values().iterator();it.hasNext()&&count++<16;){Attempt value=it.next();it.remove();if(value.claimed||value.live(now,elapsed))retained.add(value);else{this.bytes-=value.charge;if(value.id.equals(value.old.pendingId)){if(this.sessions.get(value.old.id)==value.old)this.bytes-=43;value.old.pendingId=null;}}}
        for(Attempt value:retained)this.attempts.put(value.id,value);
        count=0;List<Session> keep=new ArrayList<>();
        for(Iterator<Session> it=this.sessions.values().iterator();it.hasNext()&&count++<16;){Session value=it.next();it.remove();if(value.live(now,elapsed))keep.add(value);else this.bytes-=value.charge();}
        for(Session value:keep)this.sessions.put(value.id,value);
    }
    private static final class Session{
        final @NonNull String id,csrf;final @Nullable Account account;final @NonNull Instant created;final long expires;@Nullable String pendingId;
        Session(@NonNull String id,@NonNull String csrf,@Nullable Account account,@NonNull Instant created,long expires){this.id=id;this.csrf=csrf;this.account=account;this.created=created;this.expires=expires;}
        long charge(){return 86+(this.pendingId==null?0:43)+(this.account==null?0:this.account.id().length()+this.account.tenant().length());}
        boolean live(@NonNull Instant now,long elapsed){return !now.isBefore(this.created)&&now.isBefore(this.created.plusSeconds(1800))&&this.expires-elapsed>0;}
    }
    private static final class Attempt{
        final @NonNull String id;final @NonNull BrowserBinding binding;final @NonNull Session old;final @NonNull Instant created;final long expires,charge;boolean ready,claimed;
        Attempt(@NonNull String id,@NonNull BrowserBinding binding,@NonNull Session old,@NonNull Instant created,long expires){this.id=id;this.binding=binding;this.old=old;this.created=created;this.expires=expires;this.charge=86+old.charge()+43;}
        boolean live(@NonNull Instant now,long elapsed){return !now.isBefore(this.created)&&now.isBefore(this.created.plusSeconds(300))&&this.expires-elapsed>0;}
    }
    private static final class Budget{
        final @NonNull LongSupplier time;final long end;
        Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(6).toNanos();}
        void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Denied(503);}
        void beforeCore(){check();if(this.end-this.time.getAsLong()<Duration.ofSeconds(3).toNanos())throw new Denied(503);}
        @NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}
    }
    private static final class Denied extends RuntimeException{private static final long serialVersionUID=1L;final int status;Denied(int status){super("Request denied");this.status=status;}}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){
        Enumeration<String> names=request.getHeaderNames();if(names==null)throw new Denied(400);Map<String,List<String>> result=new LinkedHashMap<>();int count=0,occurrences=0;long bytes=0;
        while(names.hasMoreElements()){
            if(++count>32)throw new Denied(400);String name=names.nextElement();if(name==null||!name.matches("[A-Za-z0-9-]{1,64}"))throw new Denied(400);
            Enumeration<String> values=request.getHeaders(name);if(values==null)throw new Denied(400);List<String> copy=new ArrayList<>();
            while(values.hasMoreElements()){if(++occurrences>32)throw new Denied(400);String value=values.nextElement();if(value==null||value.length()>4096||!ascii(value))throw new Denied(400);bytes+=name.length()+value.length();if(bytes>8192)throw new Denied(400);copy.add(value);}
            if(copy.isEmpty()||result.putIfAbsent(name.toLowerCase(java.util.Locale.ROOT),List.copyOf(copy))!=null)throw new Denied(400);
        }return Map.copyOf(result);
    }
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> values,@NonNull String name){List<String> found=values.getOrDefault(name,List.of());if(found.size()!=1)throw new Denied(400);return found.get(0);}
    private static @Nullable String cookie(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){
        String found=null;for(String line:headers.getOrDefault("cookie",List.of()))for(String raw:line.split(";",-1)){String pair=raw.stripLeading();int split=pair.indexOf('=');if(split<1)throw new Denied(400);if(pair.substring(0,split).equals(name)){String value=pair.substring(split+1);if(found!=null||value.length()>256||!value.matches("[A-Za-z0-9_.-]*"))throw new Denied(400);found=value;}}
        return found;
    }
    private static boolean ascii(@NonNull String value){return value.chars().allMatch(c->c>=0x20&&c<=0x7e);}
    private static boolean same(@NonNull String expected,@NonNull String actual){return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII));}
    private @NonNull String token(){byte[] bytes=new byte[32];this.random.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static @NonNull String pendingCookie(@NonNull String value,int age){return PENDING_COOKIE+'='+value+"; Path=/; Secure; HttpOnly; SameSite=None; Max-Age="+age;}
    private static @NonNull String sessionCookie(@NonNull Session session){return sessionCookie(session.id,1800,session.account==null);}
    private static @NonNull String sessionCookie(@NonNull String value,int age,boolean anonymous){return SESSION_COOKIE+'='+value+"; Path=/; Secure; HttpOnly; SameSite="+(anonymous?"None":"Lax")+"; Max-Age="+age;}
    private static @NonNull JsonObject json(@NonNull String name,@NonNull String value){return JsonObject.builder().put(name,value).build();}
    private static void send(@NonNull HttpServletResponse response,@NonNull HttpServletRequest request,int status,@NonNull JsonObject body,@NonNull List<@NonNull String> cookies,@Nullable URI location)throws IOException{
        response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setHeader("Pragma","no-cache");response.setHeader("Referrer-Policy","no-referrer");response.setHeader("X-Content-Type-Options","nosniff");response.setContentType("application/json; charset=UTF-8");
        for(String cookie:cookies)response.addHeader("Set-Cookie",cookie);if(location!=null)response.setHeader("Location",location.toASCIIString());
        byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);if(!request.getMethod().equals("HEAD"))response.getOutputStream().write(bytes);
    }
    @NonNull Set<@NonNull String> sessionIds(){synchronized(this.sessions){return Set.copyOf(this.sessions.keySet());}}
    @NonNull JsonObject stateSnapshot(){synchronized(this.sessions){return JsonObject.builder()
            .put("sessions",(long)this.sessions.size()).put("attempts",(long)this.attempts.size()).put("state_bytes",this.bytes)
            .put("authenticated_sessions",this.sessions.values().stream().filter(value->value.account!=null).count())
            .put("pending_sessions",this.sessions.values().stream().filter(value->value.pendingId!=null).count()).build();}}
    @Override public @NonNull String toString(){return "ServletOidcRpRecipe{configuration/state=<redacted>}";}
}
