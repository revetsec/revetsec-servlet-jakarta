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

import com.revetsec.OperationBinding;
import com.revetsec.json.JsonObject;
import com.revetsec.servlet.jakarta.ServletWebAuthn;
import com.revetsec.servlet.jakarta.ServletWebAuthnBodyResult;
import com.revetsec.webauthn.*;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Single approved-account application; typed reauthentication authorizes one local selected action.
 * The host owns keys, account approval, the RP/store, TLS and the same reentrant recovery gate.
 * Sessions, pending actions and action grants are bounded and volatile; this is not a session product. */
@ThreadSafe
@SuppressWarnings("serial")
public final class ServletPasskeyActionsRecipe extends HttpServlet {
    private static final long serialVersionUID=1L;
    static final @NonNull String COOKIE="__Host-passkey-actions";
    static final int MAXIMUM_BODY=65_536;
    private final @NonNull String origin,authority,rpId,namespace,operatorAccessKey;
    private final byte @NonNull [] account;
    private final @NonNull WebAuthnRelyingParty relyingParty;
    private final @NonNull WebAuthnRecoveryGate gate;
    private final @NonNull WebAuthnSettings transport=WebAuthnSettings.builder().maximumResponseBodyBytes(MAXIMUM_BODY).build();
    final @NonNull Sessions sessions;
    private final @NonNull AtomicBoolean admissionOpen=new AtomicBoolean(true);
    private final @NonNull Semaphore work=new Semaphore(8);
    private final @NonNull AtomicInteger sensitiveEffects=new AtomicInteger(),removalCalls=new AtomicInteger();

    /** Inject an RP configured with this exact account scope, origin and the SAME reentrant gate.
     * The account and operator key are trusted configuration, never claims from a request.
     * The RP's body limits must be the same as or stricter than this application's65536byte cap. */
    public ServletPasskeyActionsRecipe(@NonNull String origin,@NonNull String rpId,@NonNull String operatorAccessKey,
            @NonNull Clock clock,byte @NonNull [] approvedAccount,@NonNull String expectedNamespace,
            @NonNull WebAuthnRelyingParty relyingParty,@NonNull WebAuthnRecoveryGate gate){
        URI parsed=URI.create(origin);
        if(!"https".equals(parsed.getScheme())||!rpId.equals(parsed.getHost())||parsed.getRawUserInfo()!=null||parsed.getRawQuery()!=null||parsed.getRawFragment()!=null||!parsed.getRawPath().isEmpty()||parsed.getPort()==0||parsed.getPort()>65535||!operatorAccessKey.matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("Fixed HTTPS origin, RP and independent operator key required");
        byte[] selectedAccount=approvedAccount.clone();Objects.requireNonNull(WebAuthnStoreKey.forAccountFence(expectedNamespace,rpId,selectedAccount));
        this.origin=origin;this.authority=parsed.getRawAuthority();this.rpId=rpId;this.namespace=expectedNamespace;this.operatorAccessKey=operatorAccessKey;this.account=selectedAccount;this.relyingParty=Objects.requireNonNull(relyingParty);this.gate=Objects.requireNonNull(gate);this.sessions=new Sessions(clock,selectedAccount,expectedNamespace,rpId);
    }

    @Override protected void service(@NonNull HttpServletRequest original,@NonNull HttpServletResponse response)throws IOException {
        long deadline=System.nanoTime()+Duration.ofSeconds(15).toNanos();boolean acquired=false,admitted=false;Output completed=null;
        try{
            Map<String,List<String>> headers=headers(original);String path=original.getPathInfo();
            if(path==null||!original.getRequestURI().equals(original.getContextPath()+original.getServletPath()+path)||original.getQueryString()!=null||!original.isSecure()||!original.getScheme().equals("https")||!one(headers,"host").equals(this.authority)||headers.containsKey("authorization")||headers.containsKey("content-encoding")||headers.keySet().stream().anyMatch(n->n.equals("forwarded")||n.startsWith("x-forwarded-")))throw new Denied(400);
            for(String name:List.of("host","origin","cookie","content-type","content-length","transfer-encoding","x-csrf-token","x-ceremony-id","x-credential-id","x-demo-access-key"))if(headers.containsKey(name)&&Objects.requireNonNull(headers.get(name)).size()!=1)throw new Denied(400);
            if(headers.containsKey("content-length")&&headers.containsKey("transfer-encoding"))throw new Denied(400);
            if(!this.admissionOpen.get())throw new Denied(503);
            if(!this.work.tryAcquire())throw new Denied(503);acquired=true;
            WebAuthnRecoveryGate.Permit permit=this.gate.acquire(remaining(deadline));if(permit==null)throw new Denied(503);
            try(permit){
                if(!current(permit))throw new Denied(503);
                completed=route(bounded(original,deadline),headers,path,deadline);
                if(!current(permit))throw new Denied(503);
            }
            check(deadline);if(!this.admissionOpen.get())throw new Denied(503);Output selected=Objects.requireNonNull(completed);if(selected.owner!=null&&!this.sessions.publishable(selected.owner,selected.grant))throw new Denied(503);check(deadline);if(!this.admissionOpen.get())throw new Denied(503);admitted=true;
            publish(response,Objects.requireNonNull(completed));
        }catch(Denied denied){if(admitted)throw new IOException("Response publication failed");send(response,denied.status,"Request denied.");}
        catch(RuntimeException unavailable){if(admitted)throw new IOException("Response publication failed");send(response,503,"Local application unavailable.");}
        finally{
            // Exact observed refusal cleanup MUST NOT call clocks, the RP/store, the gate or I/O.
            // A failed old response cannot burn a newer grant or one owned by another App.
            if(!admitted&&completed!=null&&completed.owner!=null&&completed.grant!=null)this.sessions.burn(completed.owner,completed.grant);
            if(acquired)this.work.release();
        }
    }

    private @NonNull Output route(@NonNull HttpServletRequest request,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String path,long deadline)throws IOException {
        if(path.equals("/session")&&request.getMethod().equals("GET")){
            if(request.getContentLengthLong()>0||headers.containsKey("transfer-encoding"))throw new Denied(400);
            Session session=find(headers);return json(200,JsonObject.builder().put("authenticated",session!=null&&session.authenticated).build());
        }
        if(!request.getMethod().equals("POST"))throw new Denied(405);
        if(!one(headers,"origin").equals(this.origin))throw new Denied(403);
        if(path.equals("/session")){
            empty(request);if(headers.containsKey("cookie"))throw new Denied(400);Session fresh=this.sessions.begin();return session(fresh);
        }
        Session session=find(headers);if(session==null||!equal(session.csrf,one(headers,"x-csrf-token")))throw new Denied(403);
        if(path.equals("/access-login")){
            empty(request);if(session.authenticated||!management(headers))throw new Denied(403);return session(this.sessions.rotate(session,true));
        }
        if(path.equals("/sign-in/start")){
            empty(request);if(session.authenticated)throw new Denied(403);return authenticationStart(this.relyingParty.beginAuthenticationResult(session.binding),session);
        }
        if(path.equals("/sign-in/finish")){
            if(session.authenticated)throw new Denied(403);byte[] body=credentialBody(request);String ceremony=ceremony(headers);
            WebAuthnAuthenticationResult result=this.relyingParty.completeAuthenticationResult(ceremony,body,session.binding);
            if(result instanceof WebAuthnAuthenticationResult.Succeeded success){
                WebAuthnAuthentication proof=success.getAuthentication();byte[] handle=proof.getUserHandle();boolean approved;
                try{approved=proof.getKind()==WebAuthnAuthentication.Kind.SIGN_IN&&this.namespace.equals(proof.getCredentialNamespace())&&this.rpId.equals(proof.getRelyingPartyId())&&MessageDigest.isEqual(this.account,handle);}finally{Arrays.fill(handle,(byte)0);}
                if(!approved)throw new Denied(403);check(deadline);return session(this.sessions.rotate(session,true));
            }
            if(result instanceof WebAuthnAuthenticationResult.ReconciliationRequired||result instanceof WebAuthnAuthenticationResult.Indeterminate)return unavailableAndClose();
            if(result instanceof WebAuthnAuthenticationResult.Rejected)throw new Denied(400);throw new Denied(503);
        }
        if(!session.authenticated||!this.sessions.current(session))throw new Denied(403);
        if(path.equals("/logout")){empty(request);return session(this.sessions.rotate(session,false));}
        if(path.equals("/register/start")){
            empty(request);if(!management(headers))throw new Denied(403);
            WebAuthnRegistrationRequestResult result=this.relyingParty.beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(this.account).userName("demo-account").userDisplayName("Demo Account").build(),session.binding);
            check(deadline);if(!this.sessions.current(session))throw new Denied(403);
            if(result instanceof WebAuthnRegistrationRequestResult.Prepared prepared)return owned(options(prepared.getRequest()),session);
            if(result instanceof WebAuthnRegistrationRequestResult.ReconciliationRequired||result instanceof WebAuthnRegistrationRequestResult.Indeterminate)return unavailableAndClose();
            if(result instanceof WebAuthnRegistrationRequestResult.Rejected)throw new Denied(400);throw new Denied(503);
        }
        if(path.equals("/register/finish")){
            if(!management(headers))throw new Denied(403);byte[] body=credentialBody(request);WebAuthnRegistrationResult result=this.relyingParty.completeRegistrationResult(ceremony(headers),body,session.binding);check(deadline);if(!this.sessions.current(session))throw new Denied(403);
            if(result instanceof WebAuthnRegistrationResult.Succeeded success){byte[] handle=success.getRegistration().getUserHandle();try{if(!MessageDigest.isEqual(this.account,handle))throw new Denied(403);}finally{Arrays.fill(handle,(byte)0);}return owned(text(200,"Passkey registered."),session);}
            if(result instanceof WebAuthnRegistrationResult.ReconciliationRequired||result instanceof WebAuthnRegistrationResult.Indeterminate)return unavailableAndClose();
            if(result instanceof WebAuthnRegistrationResult.Rejected)throw new Denied(400);throw new Denied(503);
        }
        if(path.equals("/credentials/list")){
            empty(request);WebAuthnCredentialListResult result=this.relyingParty.listCredentialsResult(this.account);check(deadline);if(!this.sessions.current(session))throw new Denied(403);
            if(!(result instanceof WebAuthnCredentialListResult.Listed listed))throw new Denied(503);
            var values=new ArrayList<com.revetsec.json.JsonValue>();for(byte[] id:listed.getCredentialIds())values.add(com.revetsec.json.JsonString.fromValue(encode(id)));
            return owned(json(200,JsonObject.builder().put("credentialIds",com.revetsec.json.JsonArray.fromElements(values)).build()),session);
        }
        if(path.equals("/reauth/start")||path.equals("/credentials/self-remove/start")){
            empty(request);Action action=path.startsWith("/reauth/")?Action.SENSITIVE:Action.SELF_REMOVAL;byte[] target=action==Action.SENSITIVE?new byte[0]:target(headers);
            if(action==Action.SELF_REMOVAL){
                WebAuthnCredentialListResult list=this.relyingParty.listCredentialsResult(this.account);if(!(list instanceof WebAuthnCredentialListResult.Listed listed))throw new Denied(503);boolean owned=false;for(byte[] id:listed.getCredentialIds())owned|=MessageDigest.isEqual(id,target);if(!owned)throw new Denied(403);
            }
            WebAuthnAuthenticationRequestResult result=this.relyingParty.beginReauthenticationResult(this.account,action.purpose,session.binding);check(deadline);
            if(result instanceof WebAuthnAuthenticationRequestResult.Prepared prepared){if(!this.sessions.remember(session,action,target,prepared.getRequest().getCeremonyId()))throw new Denied(403);return owned(options(prepared.getRequest()),session);}
            if(result instanceof WebAuthnAuthenticationRequestResult.ReconciliationRequired||result instanceof WebAuthnAuthenticationRequestResult.Indeterminate)return unavailableAndClose();
            if(result instanceof WebAuthnAuthenticationRequestResult.Rejected)throw new Denied(400);throw new Denied(503);
        }
        if(path.equals("/reauth/finish")||path.equals("/credentials/self-remove/finish")){
            Action action=path.startsWith("/reauth/")?Action.SENSITIVE:Action.SELF_REMOVAL;byte[] body=credentialBody(request);Pending pending=this.sessions.pending(session,action,ceremony(headers)).orElseThrow(()->new Denied(403));
            WebAuthnReauthenticationResult result=this.relyingParty.completeReauthenticationResult(this.account,action.purpose,pending.ceremony,body,session.binding);check(deadline);
            if(result instanceof WebAuthnReauthenticationResult.Succeeded success){
                Output prepared=text(200,"Selected action approved for one use.");Grant grant=this.sessions.complete(session,pending,success.getReauthentication()).orElseThrow(()->new Denied(403));
                try{return new Output(prepared.status,prepared.body,prepared.options,prepared.cookie,session,grant);}catch(Throwable refused){this.sessions.burn(session,grant);throw refused;}
            }
            if(result instanceof WebAuthnReauthenticationResult.ReconciliationRequired||result instanceof WebAuthnReauthenticationResult.Indeterminate)return unavailableAndClose();
            if(result instanceof WebAuthnReauthenticationResult.Rejected)throw new Denied(400);throw new Denied(503);
        }
        if(path.equals("/sensitive")){
            empty(request);if(!this.sessions.consume(session,Action.SENSITIVE,new byte[0]))throw new Denied(403);this.sensitiveEffects.incrementAndGet();return owned(text(200,"Demo sensitive action completed."),session);
        }
        if(path.equals("/credentials/self-remove")){
            empty(request);byte[] selected=target(headers);if(!this.sessions.consume(session,Action.SELF_REMOVAL,selected))throw new Denied(403);this.removalCalls.incrementAndGet();return owned(removal(this.relyingParty.removeCredentialResult(this.account,selected)),session);
        }
        if(path.equals("/credentials/remove")){
            empty(request);if(!management(headers))throw new Denied(403);byte[] selected=target(headers);this.removalCalls.incrementAndGet();return owned(removal(this.relyingParty.removeCredentialResult(this.account,selected)),session);
        }
        throw new Denied(404);
    }

    private @NonNull Output authenticationStart(@NonNull WebAuthnAuthenticationRequestResult result,@NonNull Session session){
        if(result instanceof WebAuthnAuthenticationRequestResult.Prepared prepared)return owned(options(prepared.getRequest()),session);
        if(result instanceof WebAuthnAuthenticationRequestResult.ReconciliationRequired||result instanceof WebAuthnAuthenticationRequestResult.Indeterminate)return unavailableAndClose();
        if(result instanceof WebAuthnAuthenticationRequestResult.Rejected)throw new Denied(400);throw new Denied(503);
    }
    private @NonNull Output removal(@NonNull WebAuthnCredentialRemovalResult result){
        if(result instanceof WebAuthnCredentialRemovalResult.Removed)return text(200,"Passkey removed.");
        if(result instanceof WebAuthnCredentialRemovalResult.ReconciliationRequired||result instanceof WebAuthnCredentialRemovalResult.Indeterminate)return unavailableAndClose();
        if(result instanceof WebAuthnCredentialRemovalResult.Absent)throw new Denied(404);throw new Denied(503);
    }
    private @NonNull Output unavailableAndClose(){this.admissionOpen.set(false);return text(503,"Local application unavailable; reconcile before further operations.");}
    private boolean current(WebAuthnRecoveryGate.@NonNull Permit permit){try{return this.admissionOpen.get()&&Boolean.TRUE.equals(permit.isCurrent());}catch(RuntimeException unavailable){return false;}}
    private boolean management(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){String key=optional(headers,"x-demo-access-key");return key!=null&&equal(this.operatorAccessKey,key);}
    private byte @NonNull [] credentialBody(@NonNull HttpServletRequest request){
        ServletWebAuthnBodyResult result=ServletWebAuthn.bodyResultFor(this.transport,request);
        if(result instanceof ServletWebAuthnBodyResult.Read read){byte[] body=read.getBodyWithPersonalData();if(body.length==0)throw new Denied(400);return body;}
        if(result instanceof ServletWebAuthnBodyResult.Rejected)throw new Denied(400);throw new Denied(503);
    }
    private @Nullable Session find(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){String raw=optional(headers,"cookie");if(raw==null)return null;String id=null;Set<String> names=new HashSet<>();if(raw.length()>4096)throw new Denied(400);for(String part:raw.split(";",-1)){String value=part.strip();int equals=value.indexOf('=');if(equals<1||names.size()>=16)throw new Denied(400);String name=value.substring(0,equals),text=value.substring(equals+1);if(!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")||!names.add(name)||text.length()>512||text.chars().anyMatch(ch->ch<33||ch>126||ch=='"'||ch==','||ch=='\\'))throw new Denied(400);if(name.equals(COOKIE))id=text;}return id==null?null:this.sessions.find(id).orElse(null);}
    private static @NonNull String ceremony(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){String value=one(headers,"x-ceremony-id");if(!value.matches("[A-Za-z0-9_-]{43}"))throw new Denied(400);return value;}
    private static byte @NonNull [] target(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){String value=one(headers,"x-credential-id");if(value.isEmpty()||value.length()>1364||!value.matches("[A-Za-z0-9_-]+"))throw new Denied(400);try{byte[] bytes=Base64.getUrlDecoder().decode(value);if(bytes.length<1||bytes.length>1023||!encode(bytes).equals(value))throw new Denied(400);return bytes;}catch(IllegalArgumentException malformed){throw new Denied(400);}}
    private static @NonNull String encode(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static boolean equal(@NonNull String a,@NonNull String b){return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),b.getBytes(StandardCharsets.UTF_8));}
    private static void empty(@NonNull HttpServletRequest request)throws IOException {if(request.getInputStream().read()!=-1)throw new Denied(400);}
    static long grantDeadline(long sessionDeadline,long now){return now+Math.min(Math.max(0L,sessionDeadline-now),Duration.ofSeconds(60).toNanos());}
    private static @NonNull Duration remaining(long deadline){check(deadline);return Duration.ofNanos(deadline-System.nanoTime());}
    private static void check(long deadline){if(System.nanoTime()-deadline>=0||Thread.currentThread().isInterrupted())throw new Denied(503);}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){Map<String,List<String>> result=new LinkedHashMap<>();Enumeration<String> names=request.getHeaderNames();int count=0,bytes=0;while(names!=null&&names.hasMoreElements()){String name=names.nextElement().toLowerCase(Locale.ROOT);Enumeration<String> values=request.getHeaders(name);List<String> selected=new ArrayList<>();while(values!=null&&values.hasMoreElements()){String value=values.nextElement();if(++count>48||(bytes+=name.length()+value.length())>16_384)throw new Denied(400);selected.add(value);}result.computeIfAbsent(name,n->new ArrayList<>()).addAll(selected);}return result;}
    private static @Nullable String optional(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){List<String> values=headers.get(name);if(values==null)return null;if(values.size()!=1)throw new Denied(400);return values.get(0);}
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){String value=optional(headers,name);if(value==null)throw new Denied(400);return value;}
    private static @NonNull Output text(int status,@NonNull String text){return json(status,JsonObject.builder().put("message",text).build());}
    private static @NonNull Output json(int status,@NonNull JsonObject json){return new Output(status,json.toJson().getBytes(StandardCharsets.UTF_8),null,null,null,null);}
    private static @NonNull Output owned(@NonNull Output value,@NonNull Session session){return new Output(value.status,value.body,value.options,value.cookie,session,value.grant);}
    private static @NonNull Output options(@NonNull WebAuthnBrowserRequest request){return new Output(200,new byte[0],request,null,null,null);}
    private static @NonNull Output session(@NonNull Session session){Output value=json(200,JsonObject.builder().put("authenticated",session.authenticated).put("csrf",session.csrf).build());return new Output(value.status,value.body,null,COOKIE+'='+session.id+"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600",session,null);}
    private void publish(@NonNull HttpServletResponse response,@NonNull Output output)throws IOException {
        try{
            if(output.cookie!=null)response.addHeader("Set-Cookie",output.cookie);
            if(output.options!=null)ServletWebAuthn.writeBrowserRequest(response,output.options);
            else{response.setStatus(output.status);response.setHeader("Content-Type","application/json; charset=UTF-8");response.setHeader("Cache-Control","no-store");response.setHeader("Referrer-Policy","no-referrer");response.setHeader("X-Content-Type-Options","nosniff");response.setContentLength(output.body.length);response.getOutputStream().write(output.body);}
        }catch(Throwable failure){if(output.owner!=null&&output.grant!=null)this.sessions.burn(output.owner,output.grant);throw failure;}
    }
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull String text)throws IOException {byte[] bytes=JsonObject.builder().put("message",text).build().toJson().getBytes(StandardCharsets.UTF_8);response.setStatus(status);response.setHeader("Content-Type","application/json; charset=UTF-8");response.setHeader("Cache-Control","no-store");response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    private static @NonNull HttpServletRequest bounded(@NonNull HttpServletRequest request,long deadline){return new HttpServletRequestWrapper(request){private @Nullable ServletInputStream stream;@Override public @NonNull ServletInputStream getInputStream()throws IOException {if(this.stream==null){ServletInputStream source=super.getInputStream();this.stream=new ServletInputStream(){@Override public int read()throws IOException{check(deadline);int value=source.read();check(deadline);return value;}@Override public int read(byte @NonNull [] bytes,int offset,int length)throws IOException{check(deadline);int value=source.read(bytes,offset,length);check(deadline);return value;}@Override public boolean isFinished(){return source.isFinished();}@Override public boolean isReady(){return source.isReady();}@Override public void setReadListener(@NonNull ReadListener listener){throw new UnsupportedOperationException("Synchronous sample only");}};}return Objects.requireNonNull(this.stream);}};}
    @NonNull JsonObject stateSnapshot(){return JsonObject.builder().put("sessions",this.sessions.snapshot()).put("sensitive_effects",this.sensitiveEffects.longValue()).put("removal_calls",this.removalCalls.longValue()).put("admission_open",this.admissionOpen.get()).build();}
    private record Output(int status,byte @NonNull [] body,@Nullable WebAuthnBrowserRequest options,@Nullable String cookie,@Nullable Session owner,@Nullable Grant grant){@Override public @NonNull String toString(){return "PasskeyOutput{<redacted>}";}}
    private static final class Denied extends RuntimeException {private static final long serialVersionUID=1L;final int status;Denied(int status){this.status=status;}}

    enum Action {SENSITIVE("demo-sensitive-action"),SELF_REMOVAL("demo-remove-passkey");final @NonNull String purpose;Action(@NonNull String purpose){this.purpose=purpose;}}
    static final class Session {
        final @NonNull Object applicationOwner;final @NonNull String id,csrf;final @NonNull OperationBinding binding;final @NonNull Instant expires;final long deadline;final boolean authenticated;private final byte @NonNull [] account;
        @Nullable Pending pending;@Nullable Grant grant;boolean closed;
        Session(@NonNull Object owner,@NonNull String id,@NonNull String csrf,@NonNull OperationBinding binding,@NonNull Instant expires,long deadline,boolean authenticated,byte @NonNull [] account){this.applicationOwner=owner;this.id=id;this.csrf=csrf;this.binding=binding;this.expires=expires;this.deadline=deadline;this.authenticated=authenticated;this.account=account.clone();}
        @Override public @NonNull String toString(){return "PasskeySession{<redacted>}";}
    }
    static final class Pending {
        final @NonNull Session owner;final @NonNull Action action;private final byte @NonNull [] target,account;private final @NonNull String namespace,rpId;final @NonNull String ceremony;
        Pending(@NonNull Session owner,@NonNull Action action,byte @NonNull [] target,byte @NonNull [] account,@NonNull String namespace,@NonNull String rpId,@NonNull String ceremony){this.owner=owner;this.action=action;this.target=target.clone();this.account=account.clone();this.namespace=namespace;this.rpId=rpId;this.ceremony=ceremony;}
        @Override public @NonNull String toString(){return "PendingPasskeyAction{<redacted>}";}
    }
    static final class Grant {
        final @NonNull Object applicationOwner;final @NonNull Pending context;final @NonNull Instant expires;final long deadline;
        Grant(@NonNull Object owner,@NonNull Pending context,@NonNull Instant expires,long deadline){this.applicationOwner=owner;this.context=context;this.expires=expires;this.deadline=deadline;}
        @Override public @NonNull String toString(){return "AuthorizedPasskeyAction{<redacted>}";}
    }
    static final class Sessions {
        private final @NonNull Object applicationOwner=new Object();private final @NonNull Clock clock;private final byte @NonNull [] account;private final @NonNull String namespace,rpId;private final @NonNull Map<@NonNull String,@NonNull Session> entries=new LinkedHashMap<>();
        Sessions(@NonNull Clock clock,byte @NonNull [] account,@NonNull String namespace,@NonNull String rpId){this.clock=Objects.requireNonNull(clock);this.account=account.clone();this.namespace=namespace;this.rpId=rpId;}
        synchronized @NonNull Session begin(){cleanup();if(this.entries.size()>=64)throw new Denied(503);Session created=fresh(false);this.entries.put(created.id,created);return created;}
        synchronized @NonNull Optional<@NonNull Session> find(@NonNull String id){cleanup();return Optional.ofNullable(this.entries.get(id));}
        synchronized boolean current(@NonNull Session session){cleanup();return this.entries.get(session.id)==session&&!session.closed&&session.applicationOwner==this.applicationOwner;}
        synchronized @NonNull Session rotate(@NonNull Session old,boolean authenticated){cleanup();if(!current(old))throw new Denied(403);Session replacement=fresh(authenticated);old.closed=true;old.pending=null;old.grant=null;this.entries.remove(old.id);this.entries.put(replacement.id,replacement);return replacement;}
        synchronized boolean remember(@NonNull Session session,@NonNull Action action,byte @NonNull [] target,@NonNull String ceremony){cleanup();if(!currentAuthenticated(session))return false;if(!ceremony.matches("[A-Za-z0-9_-]{43}")||target.length>1023||(action==Action.SENSITIVE?target.length!=0:target.length==0))throw new IllegalArgumentException("Bounded pending action required");session.pending=new Pending(session,action,target,this.account,this.namespace,this.rpId,ceremony);session.grant=null;return true;}
        synchronized @NonNull Optional<@NonNull Pending> pending(@NonNull Session session,@NonNull Action action,@NonNull String ceremony){cleanup();Pending pending=session.pending;return currentAuthenticated(session)&&pending!=null&&pending.owner==session&&pending.action==action&&pending.ceremony.equals(ceremony)?Optional.of(pending):Optional.empty();}
        synchronized @NonNull Optional<@NonNull Grant> complete(@NonNull Session session,@NonNull Pending pending,@NonNull WebAuthnReauthentication proof){
            cleanup();if(!currentAuthenticated(session)||session.pending!=pending||pending.owner!=session||!this.namespace.equals(proof.getCredentialNamespace())||!this.rpId.equals(proof.getRelyingPartyId())||!pending.namespace.equals(proof.getCredentialNamespace())||!pending.rpId.equals(proof.getRelyingPartyId())||!pending.action.purpose.equals(proof.getActionPurpose())||!pending.ceremony.equals(proof.getCeremonyId()))return Optional.empty();
            byte[] handle=proof.getUserHandle(),authenticatingCredential=proof.getCredentialId();
            try{
                if(!MessageDigest.isEqual(this.account,handle)||!MessageDigest.isEqual(pending.account,handle)||authenticatingCredential.length<1||authenticatingCredential.length>1023)return Optional.empty();
                // The core-authoritative authenticating credential is NOT the removal target.
                // No stale credential-list snapshot or target-ID equality grants permission here.
            }finally{Arrays.fill(handle,(byte)0);Arrays.fill(authenticatingCredential,(byte)0);}
            Instant expires=this.clock.instant().plusSeconds(60);if(session.expires.isBefore(expires))expires=session.expires;
            Grant grant=new Grant(this.applicationOwner,pending,expires,grantDeadline(session.deadline,System.nanoTime()));session.pending=null;session.grant=grant;return Optional.of(grant);
        }
        synchronized boolean consume(@NonNull Session session,@NonNull Action action,byte @NonNull [] target){
            Grant grant=session.grant;session.grant=null;cleanup();if(!currentAuthenticated(session)||grant==null)return false;Pending context=grant.context;
            return grant.applicationOwner==this.applicationOwner&&context.owner==session&&context.action==action&&this.namespace.equals(context.namespace)&&this.rpId.equals(context.rpId)&&MessageDigest.isEqual(this.account,context.account)&&MessageDigest.isEqual(target,context.target)&&this.clock.instant().isBefore(grant.expires)&&System.nanoTime()-grant.deadline<0;
        }
        synchronized boolean publishable(@NonNull Session session,@Nullable Grant exact){
            cleanup();if(!current(session))return false;if(exact==null)return true;
            return currentAuthenticated(session)&&session.grant==exact&&exact.applicationOwner==this.applicationOwner&&this.clock.instant().isBefore(exact.expires)&&System.nanoTime()-exact.deadline<0;
        }
        synchronized void burn(@NonNull Session owner,@NonNull Grant exact){
            // No clock/cleanup/store/gate/callback: a failing collaborator cannot prevent burning.
            if(owner.applicationOwner==this.applicationOwner&&exact.applicationOwner==this.applicationOwner&&owner.grant==exact){owner.grant=null;if(owner.pending==exact.context)owner.pending=null;}
        }
        synchronized @NonNull JsonObject snapshot(){cleanup();return rawSnapshot();}
        synchronized @NonNull JsonObject rawSnapshot(){return JsonObject.builder().put("sessions",(long)this.entries.size()).put("authenticated",this.entries.values().stream().filter(s->s.authenticated).count()).put("pending",this.entries.values().stream().filter(s->s.pending!=null).count()).put("grants",this.entries.values().stream().filter(s->s.grant!=null).count()).build();}
        private boolean currentAuthenticated(@NonNull Session session){return current(session)&&session.authenticated&&MessageDigest.isEqual(this.account,session.account);}
        private @NonNull Session fresh(boolean authenticated){return new Session(this.applicationOwner,random(),random(),OperationBinding.fresh(),this.clock.instant().plusSeconds(600),System.nanoTime()+Duration.ofMinutes(10).toNanos(),authenticated,this.account);}
        private void cleanup(){Instant now=this.clock.instant();long nanos=System.nanoTime();this.entries.values().removeIf(session->{if(!now.isBefore(session.expires)||nanos-session.deadline>=0){session.closed=true;session.pending=null;session.grant=null;return true;}return false;});}
        private static @NonNull String random(){byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return encode(bytes);}
    }
}
