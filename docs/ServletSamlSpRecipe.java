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
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.json.JsonObject;
import com.revetsec.saml.*;
import com.revetsec.servlet.jakarta.ServletSaml;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

/** Complete bounded single-process S3 host, registered at the fixed {@code /saml/*} mapping. */
@ThreadSafe
@SuppressWarnings("serial")
public final class ServletSamlSpRecipe extends HttpServlet {
    private static final long serialVersionUID=1L;
    public static final @NonNull String SESSION_COOKIE="__Host-saml-session",PENDING_COOKIE="__Host-saml-pending",LOGOUT_COOKIE="__Host-saml-logout";
    private static final int MAXIMUM_SESSIONS=128,MAXIMUM_ATTEMPTS=128,PER_CONNECTION_PENDING=32;
    private static final long MAXIMUM_BYTES=262_144,SESSION_NANOS=Duration.ofMinutes(30).toNanos(),PENDING_NANOS=Duration.ofMinutes(5).toNanos();
    private static final @NonNull String AUTH_CONTEXT="recipe.saml.login.v1",LOGOUT_CONTEXT="recipe.saml.logout.v1";
    /** Trusted startup connection; request data cannot supply endpoints, keys or connection IDs. */
    public record Connection(@NonNull String id,@NonNull String entity,@NonNull URI redirectSso,@NonNull URI postSso,
            @NonNull URI redirectSlo,@NonNull URI postSlo,@NonNull List<@NonNull PublicKey> signingKeys){
        public Connection{
            if(!id.matches("[A-Za-z0-9_-]{1,64}")||entity.length()>256||entity.isEmpty()||!ascii(entity))throw new IllegalArgumentException("Bounded trusted connection required");
            for(URI uri:List.of(redirectSso,postSso,redirectSlo,postSlo))endpoint(uri);
            signingKeys=List.copyOf(signingKeys);if(signingKeys.isEmpty()||signingKeys.size()>4||signingKeys.stream().anyMatch(key->!(key instanceof java.security.interfaces.RSAPublicKey rsa)||rsa.getModulus().bitLength()<2048||rsa.getModulus().bitLength()>8192))throw new IllegalArgumentException("Fixed signing keys required");
        }
        @Override public @NonNull String toString(){return "Connection{<redacted>}";}
        @NonNull SamlIdentityProvider identityProvider(){return SamlIdentityProvider.withEntityId(this.entity).connectionId(this.id)
                .redirectSingleSignOnService(this.redirectSso).postSingleSignOnService(this.postSso)
                .redirectSingleLogoutService(this.redirectSlo).postSingleLogoutService(this.postSlo)
                .redirectSingleLogoutResponseService(this.redirectSlo).postSingleLogoutResponseService(this.postSlo)
                .signingKeys(this.signingKeys).wantAuthnRequestsSigned(true).requireSignedAssertions(true)
                .allowUnsolicitedResponses(false).allowAesCbcEncryption(false).build();}
    }
    public record Configuration(@NonNull URI origin,@NonNull String entity,@NonNull List<@NonNull Connection> connections){
        public Configuration{
            endpoint(origin);if(!origin.getRawPath().isEmpty()||entity.isEmpty()||entity.length()>256||!ascii(entity))throw new IllegalArgumentException("Fixed SP origin/entity required");
            connections=List.copyOf(connections);if(connections.isEmpty()||connections.size()>8||connections.stream().map(Connection::id).distinct().count()!=connections.size())throw new IllegalArgumentException("Distinct trusted connections required");
        }
        @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
    }
    public record Account(@NonNull String id,@NonNull String tenant,long generation){
        public Account{if(!id.matches("[A-Za-z0-9_-]{1,64}")||!tenant.matches("[A-Za-z0-9_-]{1,64}")||generation<0)throw new IllegalArgumentException("Bounded current local account required");}
        @Override public @NonNull String toString(){return "Account{<redacted>}";}
    }
    public interface Accounts{
        /** Stable key is personal data. Include connection and entity; never substitute email/display name. */
        @NonNull Optional<@NonNull Account> findAndAuthorizeLogin(@NonNull String connection,@NonNull String entity,@NonNull String stableKey,@NonNull Duration remaining)throws Exception;
        boolean authorize(@NonNull Account account,@NonNull String tenant,@NonNull String owner,@NonNull Duration remaining)throws Exception;
    }
    @FunctionalInterface public interface Admission{boolean allow(@NonNull String trustedPeer,@NonNull Duration remaining)throws Exception;}
    private final @NonNull Configuration config;
    private final @NonNull Map<@NonNull String,@NonNull Connection> connections;
    private final @NonNull Map<@NonNull String,@NonNull SamlIdentityProvider> idps;
    private final @NonNull SamlServiceProvider sp;
    private final @NonNull Map<@NonNull String,@NonNull SamlServiceProvider> logoutReceivers;
    private final @NonNull StateSealer sealer;
    private final @NonNull PendingSamlAuthenticationStore pending;
    private final @NonNull Accounts accounts;
    private final @NonNull Admission admission;
    private final @NonNull Clock clock;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull SecureRandom random=new SecureRandom();
    private final @NonNull Semaphore work=new Semaphore(8);
    private final @NonNull Map<@NonNull String,@NonNull Session> sessions=new LinkedHashMap<>();
    private final @NonNull Map<@NonNull String,@NonNull Attempt> attempts=new LinkedHashMap<>();
    private long bytes;

    /** Fixed reservations prevent a noisy configured IdP from borrowing another IdP's replay capacity. */
    public static @NonNull ServletSamlSpRecipe create(@NonNull Configuration config,@NonNull PrivateKey signingKey,
            @NonNull List<@NonNull SamlCredential> decryptionKeys,@NonNull SealingKey sealingKey,@NonNull Accounts accounts,@NonNull Admission admission){
        if(!(signingKey instanceof java.security.interfaces.RSAPrivateKey rsa)||rsa.getModulus().bitLength()<2048||rsa.getModulus().bitLength()>8192||decryptionKeys.size()>2)throw new IllegalArgumentException("Bounded RSA credentials required");
        Clock clock=Clock.systemUTC();Map<String,Integer> quotas=new LinkedHashMap<>();for(Connection value:config.connections())quotas.put(value.id(),128);
        SamlReplayCache replay=InMemorySamlReplayCache.fromConnectionLimits(clock,quotas);
        SamlServiceProvider sp=provider(config,signingKey,decryptionKeys,replay,clock,"/saml/logout-return/");
        Map<String,SamlServiceProvider> receivers=new LinkedHashMap<>();
        for(Connection connection:config.connections())receivers.put(connection.id(),provider(config,signingKey,decryptionKeys,replay,clock,"/saml/idp-logout/"+connection.id()+'/'));
        return new ServletSamlSpRecipe(config,sp,receivers,StateSealer.withActiveKey(sealingKey).clock(clock).maximumSealedLength(8192).build(),
                InMemoryPendingSamlAuthenticationStore.fromLimit(clock,256),accounts,admission,clock,System::nanoTime);
    }
    static @NonNull SamlServiceProvider provider(@NonNull Configuration config,@NonNull PrivateKey signingKey,@NonNull List<@NonNull SamlCredential> decryptionKeys,
            @NonNull SamlReplayCache replay,@NonNull Clock clock,@NonNull String logoutPrefix){
        return SamlServiceProvider.withEntityId(config.entity()).assertionConsumerServiceUrl(config.origin().resolve("/saml/acs"))
                .singleLogoutServiceUrl(config.origin().resolve(logoutPrefix+"redirect")).postSingleLogoutServiceUrl(config.origin().resolve(logoutPrefix+"post"))
                .signingPrivateKey(signingKey).decryptionCredentials(decryptionKeys).clock(clock).clockSkew(Duration.ZERO)
                .maximumResponseAge(Duration.ofMinutes(5)).pendingAuthenticationLifetime(Duration.ofMinutes(5)).replayBudget(Duration.ofSeconds(1)).replayCache(replay).build();
    }
    ServletSamlSpRecipe(@NonNull Configuration config,@NonNull SamlServiceProvider sp,@NonNull Map<@NonNull String,@NonNull SamlServiceProvider> logoutReceivers,
            @NonNull StateSealer sealer,@NonNull PendingSamlAuthenticationStore pending,@NonNull Accounts accounts,@NonNull Admission admission,@NonNull Clock clock,@NonNull LongSupplier nanoTime){
        this.config=Objects.requireNonNull(config);this.sp=Objects.requireNonNull(sp);this.logoutReceivers=Map.copyOf(logoutReceivers);this.sealer=Objects.requireNonNull(sealer);this.pending=Objects.requireNonNull(pending);
        this.accounts=Objects.requireNonNull(accounts);this.admission=Objects.requireNonNull(admission);this.clock=Objects.requireNonNull(clock);this.nanoTime=Objects.requireNonNull(nanoTime);
        Map<String,Connection> configs=new LinkedHashMap<>();Map<String,SamlIdentityProvider> providers=new LinkedHashMap<>();
        for(Connection value:config.connections()){configs.put(value.id(),value);providers.put(value.id(),value.identityProvider());}
        if(!this.logoutReceivers.keySet().equals(configs.keySet()))throw new IllegalArgumentException("Exact logout receiver matrix required");
        this.connections=Map.copyOf(configs);this.idps=Map.copyOf(providers);
    }
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        Budget budget=new Budget(this.nanoTime);String clear=null;boolean locallyEnded=false;
        try{
            budget.check();String path=request.getPathInfo();
            if(path==null||!request.getRequestURI().equals(request.getContextPath()+request.getServletPath()+path)||!request.isSecure()||!request.getScheme().equals("https"))throw new Denied(400);
            Map<String,List<String>> headers=headers(request);if(!one(headers,"host").equalsIgnoreCase(this.config.origin().getRawAuthority())||headers.containsKey("authorization"))throw new Denied(400);
            if(request.getMethod().equals("GET")&&(request.getContentLengthLong()>0||headers.containsKey("transfer-encoding")))throw new Denied(400);
            if(path.equals("/acs")){
                if(!request.getMethod().equals("POST"))throw new Denied(405);
                SamlPostBindingMessage message=post(request,false);String value=cookie(headers,PENDING_COOKIE);Attempt attempt=attempt(value,false);Session old=session(headers,true);
                if(!callbackOrigin(headers,origin(this.connections.get(attempt.connection).postSso())))throw new Denied(403);
                if(!this.work.tryAcquire())throw new Denied(503);
                try{
                    claim(attempt,old);clear=PENDING_COOKIE;budget.check();
                    SamlAuthenticationResult result=this.sp.completeAuthenticationResult(message,PendingSamlAuthenticationSource.fromStore(this.pending,attempt.binding,this.sealer,AUTH_CONTEXT),this.idps.get(attempt.connection));budget.check();
                    if(!(result instanceof SamlAuthenticationResult.Succeeded success))throw new Denied(result instanceof SamlAuthenticationResult.Unavailable||result instanceof SamlAuthenticationResult.Indeterminate?503:400);
                    SamlAuthentication authentication=success.getAuthentication();live(attempt,old,budget);
                    String stable=authentication.getSubjectKey().orElseThrow(()->new Denied(403)).toStableString();
                    SamlSessionReference reference=authentication.getSessionReference();String encoded=reference.toSerializedForm();
                    if(stable.length()>2048||encoded.length()>4096||!ascii(stable)||!ascii(encoded))throw new Denied(403);
                    if(!attempt.connection.equals(authentication.getIdentityProviderConnectionId())||!this.connections.get(attempt.connection).entity().equals(authentication.getIdentityProviderEntityId()))throw new Denied(400);
                    checkedAuthentication(authentication,budget);Optional<Account> found=this.accounts.findAndAuthorizeLogin(attempt.connection,authentication.getIdentityProviderEntityId(),stable,budget.remaining());
                    checkedAuthentication(authentication,budget);live(attempt,old,budget);if(found.isEmpty())throw new Denied(403);Account account=found.orElseThrow();
                    if(!this.accounts.authorize(account,account.tenant(),account.id(),budget.remaining()))throw new Denied(403);
                    checkedAuthentication(authentication,budget);live(attempt,old,budget);
                    Instant now=this.clock.instant();Instant end=now.plusSeconds(1800);if(reference.getSessionNotOnOrAfter().isPresent()&&reference.getSessionNotOnOrAfter().orElseThrow().isBefore(end))end=reference.getSessionNotOnOrAfter().orElseThrow();
                    Session replacement=new Session(token(),token(),account,reference,encoded.length(),now,end,this.nanoTime.getAsLong()+Math.min(SESSION_NANOS,Duration.between(now,end).toNanos()));
                    synchronized(this.sessions){
                        live(attempt,old,budget);checkedAuthentication(authentication,budget);long released=attempt.charge+old.charge();
                        if(replacement.charge()>MAXIMUM_BYTES-(this.bytes-released)||this.sessions.containsKey(replacement.id))throw new Denied(503);
                        discard(attempt);remove(old);this.sessions.put(replacement.id,replacement);this.bytes+=replacement.charge();
                    }
                    send(response,request,303,JsonObject.builder().put("authenticated",true).build(),List.of(sessionCookie(replacement),pendingCookie(PENDING_COOKIE,"",0)),this.config.origin().resolve("/saml/session"));return;
                }finally{synchronized(this.sessions){if(attempt.claimed)discard(attempt);}this.work.release();}
            }
            if(path.startsWith("/logout-return/")){
                boolean post=path.equals("/logout-return/post");if(!post&&!path.equals("/logout-return/redirect"))throw new Denied(404);
                if(!request.getMethod().equals(post?"POST":"GET"))throw new Denied(405);
                SamlPostBindingMessage postMessage=post?post(request,true):null;SamlRedirectBindingMessage redirectMessage=post?null:redirect(request);
                Attempt attempt=attempt(cookie(headers,LOGOUT_COOKIE),true);
                if(attempt.post!=post)throw new Denied(400);
                List<String> origins=headers.getOrDefault("origin",List.of());if(post?!callbackOrigin(headers,origin(this.connections.get(attempt.connection).postSlo())):!origins.isEmpty()&&!origins.equals(List.of(origin(this.connections.get(attempt.connection).redirectSlo()))))throw new Denied(403);
                if(!this.work.tryAcquire())throw new Denied(503);
                try{
                    claim(attempt,null);PendingSamlLogoutSource source=PendingSamlLogoutSource.fromStore(this.pending,attempt.binding,this.sealer,LOGOUT_CONTEXT);
                    SamlLogoutResult result=post?this.sp.completeLogoutResult(Objects.requireNonNull(postMessage),source,this.idps.get(attempt.connection)):
                            this.sp.completeLogoutResult(Objects.requireNonNull(redirectMessage),source,this.idps.get(attempt.connection));budget.check();
                    if(result==SamlLogoutResult.Rejected.INSTANCE){synchronized(this.sessions){if(this.attempts.get(attempt.id)==attempt)attempt.claimed=false;}throw new Denied(400);}
                    clear=LOGOUT_COOKIE;
                    if(result!=SamlLogoutResult.Succeeded.INSTANCE)throw new Denied(result instanceof SamlLogoutResult.Unavailable||result instanceof SamlLogoutResult.Indeterminate?503:400);
                    synchronized(this.sessions){if(this.attempts.get(attempt.id)!=attempt||!attempt.live(this.clock.instant(),this.nanoTime.getAsLong()))throw new Denied(401);discard(attempt);}
                    send(response,request,200,JsonObject.builder().put("provider_logout_reported",true).build(),List.of(pendingCookie(LOGOUT_COOKIE,"",0)),null);return;
                }finally{synchronized(this.sessions){if(attempt.claimed)discard(attempt);}this.work.release();}
            }
            if(path.startsWith("/idp-logout/")){
                String[] parts=path.split("/",-1);if(parts.length!=4||!this.idps.containsKey(parts[2]))throw new Denied(404);boolean post=parts[3].equals("post");if(!post&&!parts[3].equals("redirect"))throw new Denied(404);
                if(!request.getMethod().equals(post?"POST":"GET"))throw new Denied(405);
                Connection connection=this.connections.get(parts[2]);List<String> origins=headers.getOrDefault("origin",List.of());
                if(post?!callbackOrigin(headers,origin(connection.postSlo())):!origins.isEmpty()&&!origins.equals(List.of(origin(connection.redirectSlo()))))throw new Denied(403);
                SamlPostBindingMessage postMessage=post?post(request,true):null;SamlRedirectBindingMessage redirectMessage=post?null:redirect(request);
                if(!this.work.tryAcquire())throw new Denied(503);
                try{
                    SamlServiceProvider receiver=this.logoutReceivers.get(connection.id());SamlIdentityProvider idp=this.idps.get(connection.id());
                    SamlLogoutRequestResult result=post?receiver.acceptLogoutRequestResult(Objects.requireNonNull(postMessage),idp):receiver.acceptLogoutRequestResult(Objects.requireNonNull(redirectMessage),idp);budget.check();
                    if(!(result instanceof SamlLogoutRequestResult.Accepted accepted))throw new Denied(result instanceof SamlLogoutRequestResult.Unavailable?503:400);
                    SamlLogoutRequest verified=accepted.getRequest();
                    synchronized(this.sessions){
                        List<Session> matching=new ArrayList<>();for(Session candidate:this.sessions.values())if(candidate.reference!=null&&matches(candidate.reference,verified,connection))matching.add(candidate);
                        budget.check();for(Session candidate:matching)remove(candidate);
                    }
                    if(post){SamlLogoutResponsePostResult reply=receiver.respondToPostLogoutRequestResult(verified,idp,SamlLogoutStatus.SUCCESS);budget.check();if(!(reply instanceof SamlLogoutResponsePostResult.Prepared prepared))throw new Denied(503);writeForm(response,prepared.getPostForm());}
                    else{SamlLogoutResponseRedirectResult reply=receiver.respondToLogoutRequestResult(verified,idp,SamlLogoutStatus.SUCCESS);budget.check();if(!(reply instanceof SamlLogoutResponseRedirectResult.Prepared prepared))throw new Denied(503);send(response,request,303,JsonObject.builder().put("logout_handled",true).build(),List.of(),prepared.getRedirectUri());}return;
                }finally{this.work.release();}
            }
            if(request.getQueryString()!=null)throw new Denied(400);
            if(path.equals("/session")&&request.getMethod().equals("GET")){
                Session selected=session(headers,false);send(response,request,200,selected==null?JsonObject.builder().put("authenticated",false).build():JsonObject.builder().put("authenticated",selected.account!=null).put("csrf",selected.csrf).build(),List.of(),null);return;
            }
            if(path.startsWith("/account/")){
                if(!request.getMethod().equals("GET"))throw new Denied(405);String[] parts=path.split("/",-1);if(parts.length!=4)throw new Denied(404);Session selected=session(headers,true);Account account=selected.account;
                if(account==null||!account.tenant().equals(parts[2])||!account.id().equals(parts[3]))throw new Denied(403);
                if(!this.work.tryAcquire())throw new Denied(503);try{if(!this.accounts.authorize(account,parts[2],parts[3],budget.remaining()))throw new Denied(403);budget.check();synchronized(this.sessions){if(!current(selected))throw new Denied(401);}
                    send(response,request,200,JsonObject.builder().put("access","permitted").build(),List.of(),null);return;}finally{this.work.release();}
            }
            if(!request.getMethod().equals("POST"))throw new Denied(405);
            if(!headers.getOrDefault("origin",List.of()).equals(List.of(this.config.origin().toString())))throw new Denied(403);
            if(!one(headers,"content-type").equalsIgnoreCase("application/x-www-form-urlencoded"))throw new Denied(415);
            if(request.getContentLengthLong()>128)throw new Denied(413);byte[] body=request.getInputStream().readNBytes(129);if(body.length>128)throw new Denied(413);
            if(path.equals("/session")){
                if(!MessageDigest.isEqual(body,"begin=1".getBytes(StandardCharsets.US_ASCII)))throw new Denied(400);if(!this.work.tryAcquire())throw new Denied(503);try{if(!this.admission.allow(request.getRemoteAddr(),budget.remaining()))throw new Denied(429);budget.check();
                Session selected=session(headers,false);synchronized(this.sessions){cleanup();if(selected==null){Instant now=this.clock.instant();selected=new Session(token(),token(),null,null,0,now,now.plusSeconds(1800),this.nanoTime.getAsLong()+SESSION_NANOS);
                    if(this.sessions.size()>=MAXIMUM_SESSIONS||selected.charge()>MAXIMUM_BYTES-this.bytes||this.sessions.containsKey(selected.id))throw new Denied(503);budget.check();this.sessions.put(selected.id,selected);this.bytes+=selected.charge();}else if(!current(selected))throw new Denied(401);}
                send(response,request,200,JsonObject.builder().put("authenticated",selected.account!=null).put("csrf",selected.csrf).build(),List.of(sessionCookie(selected)),null);return;}finally{this.work.release();}
            }
            Session selected=session(headers,true);if(!MessageDigest.isEqual(body,("csrf="+selected.csrf).getBytes(StandardCharsets.US_ASCII)))throw new Denied(403);
            boolean logout=path.startsWith("/logout/");String connection;boolean post;
            if(logout){
                synchronized(this.sessions){if(!current(selected))throw new Denied(401);remove(selected);if(selected.pendingId!=null){Attempt previous=this.attempts.get(selected.pendingId);if(previous!=null&&!previous.claimed)discard(previous);}}
                locallyEnded=true;response.addHeader("Set-Cookie",sessionCookie("",0,false));response.addHeader("Set-Cookie",pendingCookie(PENDING_COOKIE,"",0));
                if(path.equals("/logout/local")){send(response,request,200,JsonObject.builder().put("authenticated",false).build(),List.of(),null);return;}
                if(selected.reference==null)throw new Denied(400);connection=selected.reference.getIdentityProviderConnectionId();post=path.equals("/logout/post");if(!post&&!path.equals("/logout/redirect"))throw new Denied(404);
            }else{
                String[] parts=path.split("/",-1);if(parts.length!=4||!parts[1].equals("login")||!this.idps.containsKey(parts[2]))throw new Denied(404);connection=parts[2];post=parts[3].equals("post");if(!post&&!parts[3].equals("redirect"))throw new Denied(404);
            }
            if(!this.work.tryAcquire())throw new Denied(503);Attempt attempt=null;
            try{
                if(!this.admission.allow(request.getRemoteAddr(),budget.remaining()))throw new Denied(429);budget.check();
                synchronized(this.sessions){cleanup();if(!logout&&(!current(selected)||selected.account!=null||selected.pendingId!=null))throw new Denied(409);
                    Attempt prepared=new Attempt(token(),BrowserBinding.fresh(),connection,selected,logout,post,this.clock.instant(),this.nanoTime.getAsLong()+PENDING_NANOS);
                    if(this.attempts.size()>=MAXIMUM_ATTEMPTS||this.attempts.values().stream().filter(value->value.connection.equals(connection)).count()>=PER_CONNECTION_PENDING||prepared.charge+43>MAXIMUM_BYTES-this.bytes||this.attempts.containsKey(prepared.id))throw new Denied(503);
                    budget.check();if(!logout){selected.pendingId=prepared.id;this.bytes+=43;}this.attempts.put(prepared.id,prepared);this.bytes+=prepared.charge;attempt=prepared;
                }
                URI redirect=null;SamlPostForm form=null;SamlPendingSaveResult saved;
                if(logout){
                    if(post){SamlLogoutPostResult result=this.sp.beginPostLogoutResult(this.idps.get(connection),Objects.requireNonNull(selected.reference));if(!(result instanceof SamlLogoutPostResult.Prepared prepared))throw new Denied(503);form=prepared.getPostForm();saved=prepared.getPendingLogout().saveToResult(this.pending,this.sealer,LOGOUT_CONTEXT,attempt.binding,budget.remaining());}
                    else{SamlLogoutRedirectResult result=this.sp.beginLogoutResult(this.idps.get(connection),Objects.requireNonNull(selected.reference));if(!(result instanceof SamlLogoutRedirectResult.Prepared prepared))throw new Denied(503);redirect=prepared.getRedirectUri();saved=prepared.getPendingLogout().saveToResult(this.pending,this.sealer,LOGOUT_CONTEXT,attempt.binding,budget.remaining());}
                }else{
                    SamlAuthenticationRequestOptions options=SamlAuthenticationRequestOptions.builder().forceAuthn(true).build();
                    SamlAuthenticationRequestResult result=post?this.sp.beginPostAuthenticationResult(this.idps.get(connection),options):this.sp.beginAuthenticationResult(this.idps.get(connection),options);
                    PendingSamlAuthentication pending;
                    if(result instanceof SamlAuthenticationRequestResult.Prepared prepared){redirect=prepared.getRedirectUri();pending=prepared.getPendingAuthentication();}
                    else if(result instanceof SamlAuthenticationRequestResult.PostPrepared prepared){form=prepared.getPostForm();pending=prepared.getPendingAuthentication();}else throw new Denied(503);
                    saved=pending.saveToResult(this.pending,this.sealer,AUTH_CONTEXT,attempt.binding,budget.remaining());
                }
                if(saved!=SamlPendingSaveResult.SAVED)throw new Denied(503);budget.check();
                synchronized(this.sessions){if(this.attempts.get(attempt.id)!=attempt||!attempt.live(this.clock.instant(),this.nanoTime.getAsLong())||!logout&&!current(selected))throw new Denied(401);budget.check();attempt.ready=true;}
                response.addHeader("Set-Cookie",pendingCookie(logout?LOGOUT_COOKIE:PENDING_COOKIE,attempt.id+'.'+attempt.binding.toSecretString(),300));
                if(form!=null){writeForm(response,form);return;}
                send(response,request,303,JsonObject.builder().put("continue",true).build(),List.of(),Objects.requireNonNull(redirect));return;
            }finally{synchronized(this.sessions){if(attempt!=null&&!attempt.ready)discard(attempt);}this.work.release();}
        }catch(Denied denial){send(response,request,denial.status,JsonObject.builder().put("error",locallyEnded?"Local session ended; provider outcome unavailable":"Request denied").build(),clear==null?List.of():List.of(pendingCookie(clear,"",0)),null);}
        catch(Exception unavailable){send(response,request,503,JsonObject.builder().put("error",locallyEnded?"Local session ended; provider outcome unavailable":"Temporarily unavailable").build(),clear==null?List.of():List.of(pendingCookie(clear,"",0)),null);}
    }
    private void checkedAuthentication(@NonNull SamlAuthentication authentication,@NonNull Budget budget){budget.check();Instant now=this.clock.instant();if(now.isBefore(authentication.getAuthnInstant())||now.isAfter(authentication.getAuthnInstant().plusSeconds(300))||!now.isBefore(authentication.getAssertionExpiresAt())||authentication.getSessionNotOnOrAfter().isPresent()&&!now.isBefore(authentication.getSessionNotOnOrAfter().orElseThrow()))throw new Denied(401);}
    private void live(@NonNull Attempt attempt,@NonNull Session old,@NonNull Budget budget){budget.check();synchronized(this.sessions){if(this.attempts.get(attempt.id)!=attempt||!attempt.live(this.clock.instant(),this.nanoTime.getAsLong())||!current(old))throw new Denied(401);}}
    private @NonNull Attempt attempt(@Nullable String value,boolean logout){
        if(value==null||!value.matches("[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}"))throw new Denied(401);
        synchronized(this.sessions){Attempt attempt=this.attempts.get(value.substring(0,43));if(attempt!=null&&!attempt.claimed&&!attempt.live(this.clock.instant(),this.nanoTime.getAsLong())){discard(attempt);attempt=null;}if(attempt==null||attempt.claimed||!attempt.ready||attempt.logout!=logout||!same(attempt.binding.toSecretString(),value.substring(44)))throw new Denied(401);return attempt;}
    }
    private void claim(@NonNull Attempt attempt,@Nullable Session old){synchronized(this.sessions){if(this.attempts.get(attempt.id)!=attempt||attempt.claimed||!attempt.ready||!attempt.live(this.clock.instant(),this.nanoTime.getAsLong())||!attempt.logout&&(old!=attempt.old||old==null||!current(old)))throw new Denied(401);attempt.claimed=true;}}
    private @Nullable Session session(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,boolean required){String id=cookie(headers,SESSION_COOKIE);if(id==null){if(required)throw new Denied(401);return null;}if(!id.matches("[A-Za-z0-9_-]{43}"))throw new Denied(401);synchronized(this.sessions){Session value=this.sessions.get(id);if(value==null||!current(value)){if(required)throw new Denied(401);return null;}return value;}}
    private boolean current(@NonNull Session session){if(this.sessions.get(session.id)!=session)return false;if(session.live(this.clock.instant(),this.nanoTime.getAsLong()))return true;remove(session);return false;}
    private void remove(@NonNull Session session){if(this.sessions.remove(session.id,session)){this.bytes-=session.charge();if(session.pendingId!=null){Attempt attempt=this.attempts.get(session.pendingId);if(attempt!=null&&!attempt.claimed)discard(attempt);}}}
    private void discard(@NonNull Attempt attempt){if(this.attempts.remove(attempt.id,attempt)){this.bytes-=attempt.charge;if(attempt.id.equals(attempt.old.pendingId)){if(this.sessions.get(attempt.old.id)==attempt.old)this.bytes-=43;attempt.old.pendingId=null;}}}
    private void cleanup(){
        Instant now=this.clock.instant();long time=this.nanoTime.getAsLong();int count=0;List<Attempt> scanned=new ArrayList<>();
        for(Attempt value:this.attempts.values()){if(count++>=16)break;scanned.add(value);}
        for(Attempt value:scanned){if(!value.claimed&&!value.live(now,time))discard(value);else{this.attempts.remove(value.id);this.attempts.put(value.id,value);}}
        count=0;List<Session> selected=new ArrayList<>();for(Session value:this.sessions.values()){if(count++>=16)break;selected.add(value);}
        for(Session value:selected){if(!value.live(now,time))remove(value);else{this.sessions.remove(value.id);this.sessions.put(value.id,value);}}
    }
    private static final class Session{
        final @NonNull String id,csrf;final @Nullable Account account;final @Nullable SamlSessionReference reference;final int referenceBytes;final @NonNull Instant created,end;final long expires;@Nullable String pendingId;
        Session(@NonNull String id,@NonNull String csrf,@Nullable Account account,@Nullable SamlSessionReference reference,int referenceBytes,@NonNull Instant created,@NonNull Instant end,long expires){this.id=id;this.csrf=csrf;this.account=account;this.reference=reference;this.referenceBytes=referenceBytes;this.created=created;this.end=end;this.expires=expires;}
        long charge(){return 86+(this.pendingId==null?0:43)+this.referenceBytes+(this.account==null?0:this.account.id().length()+this.account.tenant().length()+8);}
        boolean live(@NonNull Instant now,long nanos){return !now.isBefore(this.created)&&now.isBefore(this.end)&&this.expires-nanos>0;}
    }
    private static final class Attempt{
        final @NonNull String id,connection;final @NonNull BrowserBinding binding;final @NonNull Session old;final boolean logout,post;final @NonNull Instant created;final long expires,charge;boolean ready,claimed;
        Attempt(@NonNull String id,@NonNull BrowserBinding binding,@NonNull String connection,@NonNull Session old,boolean logout,boolean post,@NonNull Instant created,long expires){this.id=id;this.binding=binding;this.connection=connection;this.old=old;this.logout=logout;this.post=post;this.created=created;this.expires=expires;this.charge=86+connection.length()+old.charge()+43;}
        boolean live(@NonNull Instant now,long nanos){return !now.isBefore(this.created)&&now.isBefore(this.created.plusSeconds(300))&&this.expires-nanos>0;}
    }
    private static final class Budget{
        final @NonNull LongSupplier time;final long end;Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(8).toNanos();}
        void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Denied(503);}
        @NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}
    }
    private static final class Denied extends RuntimeException{private static final long serialVersionUID=1L;final int status;Denied(int status){super("Request denied");this.status=status;}}
    private static boolean matches(@NonNull SamlSessionReference reference,@NonNull SamlLogoutRequest request,@NonNull Connection connection){
        SamlNameId expected=reference.getNameId(),actual=request.getNameId();
        return reference.getIdentityProviderConnectionId().equals(connection.id())&&request.getIdentityProviderConnectionId().equals(connection.id())
                &&reference.getIdentityProviderEntityId().equals(connection.entity())&&expected.getValue().equals(actual.getValue())
                &&expected.getFormat().equals(actual.getFormat())&&expected.getNameQualifier().equals(actual.getNameQualifier())
                &&expected.getSpNameQualifier().equals(actual.getSpNameQualifier())&&expected.getSpProvidedId().equals(actual.getSpProvidedId())
                &&(request.getSessionIndexes().isEmpty()||reference.getSessionIndex().isPresent()&&request.getSessionIndexes().contains(reference.getSessionIndex().orElseThrow()));
    }
    private static @NonNull SamlPostBindingMessage post(@NonNull HttpServletRequest request,boolean logout)throws IOException{
        if(request.getContentLengthLong()>65_536)throw new Denied(413);
        HttpServletRequest bounded=new HttpServletRequestWrapper(request){
            @Override public @NonNull ServletInputStream getInputStream()throws IOException{
                ServletInputStream source=super.getInputStream();
                return new ServletInputStream(){int count;
                    @Override public int read()throws IOException{int value=source.read();if(value>=0&&++this.count>65_536)throw new Denied(413);return value;}
                    @Override public int read(byte @NonNull [] bytes,int offset,int length)throws IOException{int value=source.read(bytes,offset,Math.min(length,65_537-this.count));if(value>0&&(this.count+=value)>65_536)throw new Denied(413);return value;}
                    @Override public boolean isFinished(){return source.isFinished();}
                    @Override public boolean isReady(){return source.isReady();}
                    @Override public void setReadListener(@NonNull ReadListener listener){throw new UnsupportedOperationException("Synchronous bounded recipe");}
                };
            }
        };
        SamlPostBindingParseResult parsed=logout?ServletSaml.postLogoutBindingResultFor(bounded):ServletSaml.postBindingResultFor(bounded);
        if(!(parsed instanceof SamlPostBindingParseResult.Parsed value))throw new Denied(400);return value.getMessage();
    }
    private static @NonNull SamlRedirectBindingMessage redirect(@NonNull HttpServletRequest request){SamlRedirectBindingParseResult parsed=ServletSaml.redirectBindingResultFor(request);if(!(parsed instanceof SamlRedirectBindingParseResult.Parsed value))throw new Denied(400);return value.getMessage();}
    // A provider form can deliberately suppress its Origin through Referrer-Policy. The saved
    // browser binding and verified protocol correlation are mandatory for either accepted value.
    private static boolean callbackOrigin(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String provider){List<String> values=headers.getOrDefault("origin",List.of());return values.equals(List.of(provider))||values.equals(List.of("null"));}
    private static void endpoint(@NonNull URI uri){Objects.requireNonNull(uri);if(!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null||uri.getPort()==0||uri.getPort()>65535)throw new IllegalArgumentException("Fixed HTTPS endpoint required");}
    private static @NonNull String origin(@NonNull URI uri){return uri.getScheme()+"://"+uri.getRawAuthority();}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){Enumeration<String> names=request.getHeaderNames();if(names==null)throw new Denied(400);Map<String,List<String>> result=new LinkedHashMap<>();int count=0,occurrences=0;long bytes=0;while(names.hasMoreElements()){if(++count>32)throw new Denied(400);String name=names.nextElement();if(name==null||!name.matches("[A-Za-z0-9-]{1,64}"))throw new Denied(400);Enumeration<String> values=request.getHeaders(name);if(values==null)throw new Denied(400);List<String> copy=new ArrayList<>();while(values.hasMoreElements()){if(++occurrences>32)throw new Denied(400);String value=values.nextElement();if(value==null||value.length()>4096||!ascii(value))throw new Denied(400);bytes+=name.length()+value.length();if(bytes>8192)throw new Denied(400);copy.add(value);}if(copy.isEmpty()||result.putIfAbsent(name.toLowerCase(Locale.ROOT),List.copyOf(copy))!=null)throw new Denied(400);}return Map.copyOf(result);}
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> values,@NonNull String name){List<String> found=values.getOrDefault(name,List.of());if(found.size()!=1)throw new Denied(400);return found.get(0);}
    private static @Nullable String cookie(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){String found=null;for(String line:headers.getOrDefault("cookie",List.of()))for(String raw:line.split(";",-1)){String pair=raw.stripLeading();int split=pair.indexOf('=');if(split<1)throw new Denied(400);if(pair.substring(0,split).equals(name)){String value=pair.substring(split+1);if(found!=null||value.length()>256||!value.matches("[A-Za-z0-9_.-]*"))throw new Denied(400);found=value;}}return found;}
    private static void writeForm(@NonNull HttpServletResponse response,@NonNull SamlPostForm form)throws IOException{response.setHeader("Content-Security-Policy","default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action "+origin(form.getAction()));ServletSaml.writePostForm(response,form,null);}
    private static boolean ascii(@NonNull String value){return value.chars().allMatch(c->c>=0x20&&c<=0x7e);}
    private static boolean same(@NonNull String expected,@NonNull String actual){return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII));}
    private @NonNull String token(){byte[] bytes=new byte[32];this.random.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static @NonNull String pendingCookie(@NonNull String name,@NonNull String value,int age){return name+'='+value+"; Path=/; Secure; HttpOnly; SameSite=None; Max-Age="+age;}
    private static @NonNull String sessionCookie(@NonNull Session session){return sessionCookie(session.id,1800,session.account==null);}
    private static @NonNull String sessionCookie(@NonNull String value,int age,boolean anonymous){return SESSION_COOKIE+'='+value+"; Path=/; Secure; HttpOnly; SameSite="+(anonymous?"None":"Lax")+"; Max-Age="+age;}
    private static void send(@NonNull HttpServletResponse response,@NonNull HttpServletRequest request,int status,@NonNull JsonObject body,@NonNull List<@NonNull String> cookies,@Nullable URI location)throws IOException{response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setHeader("Pragma","no-cache");response.setHeader("Referrer-Policy","no-referrer");response.setHeader("X-Content-Type-Options","nosniff");response.setContentType("application/json; charset=UTF-8");for(String cookie:cookies)response.addHeader("Set-Cookie",cookie);if(location!=null)response.setHeader("Location",location.toASCIIString());byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);if(!request.getMethod().equals("HEAD"))response.getOutputStream().write(bytes);}
    @NonNull Set<@NonNull String> sessionIds(){synchronized(this.sessions){return Set.copyOf(this.sessions.keySet());}}
    @NonNull JsonObject stateSnapshot(){synchronized(this.sessions){return JsonObject.builder().put("sessions",(long)this.sessions.size()).put("attempts",(long)this.attempts.size()).put("state_bytes",this.bytes).put("authenticated_sessions",this.sessions.values().stream().filter(value->value.account!=null).count()).put("pending_sessions",this.sessions.values().stream().filter(value->value.pendingId!=null).count()).build();}}
    @Override public @NonNull String toString(){return "ServletSamlSpRecipe{configuration/state=<redacted>}";}
}
