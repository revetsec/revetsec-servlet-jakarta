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

import com.revetsec.json.JsonObject;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.server.*;
import com.revetsec.servlet.jakarta.ServletBearer;
import com.revetsec.servlet.jakarta.ServletOAuthAuthorizationServer;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import jakarta.servlet.http.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Semaphore;

/** Owned HTTP composition fixture; fixed synthetic account, real issuer/Servlet/store paths. Never deploy. */
@ThreadSafe
@SuppressWarnings("serial")
public final class DurableIssuerServlet extends HttpServlet {
    private static final long serialVersionUID=1L;
    private final @NonNull DurableIssuerFixture fixture=create();
    private final @NonNull Semaphore work=new Semaphore(8);
    private static @NonNull DurableIssuerFixture create(){try{return new DurableIssuerFixture();}catch(Exception unavailable){throw new IllegalStateException("Owned issuer fixture startup refused");}}
    @Override protected void service(@NonNull HttpServletRequest original,@NonNull HttpServletResponse response)throws IOException {
        long deadline=System.nanoTime()+4_000_000_000L;boolean acquired=false;
        try{
            Map<String,List<String>> headers=headers(original);
            String expected=DurableIssuerFixture.required("REVETSEC_DURABLE_FIXTURE_CREDENTIAL");String supplied=optional(headers,"x-fixture-credential");
            if(supplied==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),supplied.getBytes(StandardCharsets.US_ASCII)))throw new DurableIssuerFixture.Denied(401);
            if(!one(headers,"host").equals("issuer.example")||!original.isSecure()||!original.getScheme().equals("https")||headers.keySet().stream().anyMatch(k->k.equals("forwarded")||k.startsWith("x-forwarded-")))throw new DurableIssuerFixture.Denied(400);
            for(String critical:List.of("host","origin","content-type","content-length","transfer-encoding","cookie","authorization","x-fixture-credential","x-fixture-csrf"))if(headers.containsKey(critical)&&Objects.requireNonNull(headers.get(critical)).size()!=1)throw new DurableIssuerFixture.Denied(400);
            if(headers.containsKey("content-length")&&headers.containsKey("transfer-encoding"))throw new DurableIssuerFixture.Denied(400);
            String path=original.getPathInfo();if(path==null||!original.getRequestURI().equals(original.getContextPath()+original.getServletPath()+path))throw new DurableIssuerFixture.Denied(400);
            if(!path.equals("/authorize")&&original.getQueryString()!=null)throw new DurableIssuerFixture.Denied(400);
            if(original.getMethod().equals("GET")&&(original.getContentLengthLong()>0||headers.containsKey("transfer-encoding")))throw new DurableIssuerFixture.Denied(400);
            if(path.startsWith("/fixture/")){
                if(!original.getMethod().equals("GET"))throw new DurableIssuerFixture.Denied(405);
                send(response,200,this.fixture.control(path.substring(9)));return;
            }
            if(!this.fixture.admitted.get())throw new DurableIssuerFixture.Denied(503);
            if(path.equals("/session")&&original.getMethod().equals("GET")){send(response,200,JsonObject.builder().put("current",session(headers,false)!=null).build());return;}
            if(path.equals("/session")){
                requirePost(original);browserOrigin(headers);Map<String,String> body=form(read(original,128,deadline));
                DurableIssuerFixture.Session old=session(headers,false);
                if(!body.getOrDefault("begin","").equals("1")||body.size()!=(old==null?1:2)||old!=null&&!old.csrf.equals(body.get("csrf")))throw new DurableIssuerFixture.Denied(403);
                check(deadline);DurableIssuerFixture.Session fresh=this.fixture.bootstrap(old);cookie(response,fresh.id,600);send(response,200,JsonObject.builder().put("csrf",fresh.csrf).build());return;
            }
            if(path.equals("/logout")){
                requirePost(original);browserOrigin(headers);DurableIssuerFixture.Session session=session(headers,true);Map<String,String> body=form(read(original,128,deadline));if(body.size()!=1||!session.csrf.equals(body.get("csrf")))throw new DurableIssuerFixture.Denied(403);this.fixture.close(session);cookie(response,"",0);send(response,204,JsonObject.builder().build());return;
            }
            if(!this.work.tryAcquire())throw new DurableIssuerFixture.Denied(503);acquired=true;check(deadline);
            HttpServletRequest request=bounded(original,deadline);
            if(path.equals("/authorize")){
                if(!request.getMethod().equals("GET"))throw new DurableIssuerFixture.Denied(405);browserOrigin(headers);DurableIssuerFixture.Session session=session(headers,true);csrf(headers,session);
                OAuthAuthorizationResult result=ServletOAuthAuthorizationServer.beginAuthorizationResultFor(this.fixture.server,request,session.binding);check(deadline);if(!this.fixture.current(session))throw new DurableIssuerFixture.Denied(401);
                if(result instanceof OAuthAuthorizationResult.InteractionRequired required)send(response,200,JsonObject.builder().put("interaction",required.getInteraction().getInteractionValue()).build());else authorization(response,result);return;
            }
            if(path.equals("/approve")){
                requirePost(request);browserOrigin(headers);DurableIssuerFixture.Session session=session(headers,true);Map<String,String> body=form(read(request,8192,deadline));
                if(body.size()!=2||!session.csrf.equals(body.get("csrf"))||!body.containsKey("interaction"))throw new DurableIssuerFixture.Denied(403);
                OAuthAuthorizationResult result=this.fixture.server.completeAuthorizationResult(Objects.requireNonNull(body.get("interaction")),session.binding,DurableIssuerFixture.decision());check(deadline);if(!this.fixture.current(session))throw new DurableIssuerFixture.Denied(401);authorization(response,result);return;
            }
            if(headers.containsKey("cookie")||headers.containsKey("origin"))throw new DurableIssuerFixture.Denied(400);
            if(path.equals("/metadata")||path.equals("/jwks")){
                OAuthServerResponse prepared=path.equals("/metadata")?this.fixture.server.metadataResponse(request.getMethod()):this.fixture.server.jwksResponse(request.getMethod());check(deadline);ServletOAuthAuthorizationServer.writeResponse(response,prepared);return;
            }
            if(path.equals("/token")){
                requirePost(request);OAuthTokenResult result=ServletOAuthAuthorizationServer.tokenResultFor(this.fixture.server,request);check(deadline);ServletOAuthAuthorizationServer.writeResponse(response,result instanceof OAuthTokenResult.Succeeded success?success.getResponse():((OAuthTokenResult.Rejected)result).getResponse());return;
            }
            if(path.equals("/revoke")){
                requirePost(request);OAuthRevocationResult result=ServletOAuthAuthorizationServer.revocationResultFor(this.fixture.server,request);check(deadline);ServletOAuthAuthorizationServer.writeResponse(response,result instanceof OAuthRevocationResult.Succeeded success?success.getResponse():((OAuthRevocationResult.Rejected)result).getResponse());return;
            }
            if(path.equals("/introspect")){
                requirePost(request);OAuthIntrospectionResult result=ServletOAuthAuthorizationServer.introspectionResultFor(this.fixture.server,request);check(deadline);ServletOAuthAuthorizationServer.writeResponse(response,result instanceof OAuthIntrospectionResult.Succeeded success?success.getResponse():((OAuthIntrospectionResult.Rejected)result).getResponse());return;
            }
            if(path.startsWith("/resource/")){
                if(!request.getMethod().equals("GET"))throw new DurableIssuerFixture.Denied(405);BearerTokenResult parsed=ServletBearer.bearerTokenResultFor(request);
                if(!(parsed instanceof BearerTokenResult.Present present)){if(parsed instanceof BearerTokenResult.Absent){response.setHeader("WWW-Authenticate","Bearer");throw new DurableIssuerFixture.Denied(401);}throw new DurableIssuerFixture.Denied(400);}
                OAuthIssuerAccessTokenResult checked=this.fixture.server.validateAccessTokenResult(present.getToken(),DurableIssuerFixture.RESOURCE);check(deadline);
                if(!(checked instanceof OAuthIssuerAccessTokenResult.Succeeded success)){response.setHeader("WWW-Authenticate","Bearer error=\"invalid_token\"");throw new DurableIssuerFixture.Denied(401);}
                if(!success.getAccessToken().getIssuer().equals(DurableIssuerFixture.ISSUER)||!success.getAccessToken().getSubject().orElse("").equals(DurableIssuerFixture.SUBJECT)||!success.getAccessToken().getScopes().contains("read")||!path.equals("/resource/tenant/alice")||!this.fixture.enabled.get())throw new DurableIssuerFixture.Denied(403);
                check(deadline);send(response,200,JsonObject.builder().put("protected",true).build());return;
            }
            throw new DurableIssuerFixture.Denied(404);
        }catch(OAuthServerException failure){this.fixture.record(failure);ServletOAuthAuthorizationServer.writeResponse(response,this.fixture.server.responseForFailure(failure));}
        catch(DurableIssuerFixture.Denied denied){send(response,denied.status,JsonObject.builder().put("error","Request denied").build());}
        catch(IllegalArgumentException malformed){send(response,400,JsonObject.builder().put("error","Request denied").build());}
        finally{if(acquired)this.work.release();}
    }
    private static void authorization(@NonNull HttpServletResponse response,@NonNull OAuthAuthorizationResult result)throws IOException {
        OAuthServerResponse prepared;if(result instanceof OAuthAuthorizationResult.Completed completed)prepared=completed.getResponse();else if(result instanceof OAuthAuthorizationResult.Rejected rejected)prepared=rejected.getResponse();else if(result instanceof OAuthAuthorizationResult.Denied denied)prepared=denied.getResponse();else throw new DurableIssuerFixture.Denied(503);ServletOAuthAuthorizationServer.writeResponse(response,prepared);
    }
    private DurableIssuerFixture.@Nullable Session session(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,boolean required){
        String raw=optional(headers,"cookie");if(raw==null){if(required)throw new DurableIssuerFixture.Denied(401);return null;}
        if(!raw.startsWith(DurableIssuerFixture.COOKIE+'=')||raw.indexOf(';')>=0)throw new DurableIssuerFixture.Denied(400);String id=raw.substring(DurableIssuerFixture.COOKIE.length()+1);if(!id.matches("[A-Za-z0-9_-]{43}"))throw new DurableIssuerFixture.Denied(400);
        DurableIssuerFixture.Session session=this.fixture.find(id);if(session==null||!this.fixture.current(session)){if(required)throw new DurableIssuerFixture.Denied(401);return null;}return session;
    }
    private static void csrf(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,DurableIssuerFixture.@NonNull Session session){if(!session.csrf.equals(one(headers,"x-fixture-csrf")))throw new DurableIssuerFixture.Denied(403);}
    private static void browserOrigin(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){if(!one(headers,"origin").equals(DurableIssuerFixture.ORIGIN)||headers.containsKey("authorization"))throw new DurableIssuerFixture.Denied(403);}
    private static void requirePost(@NonNull HttpServletRequest request){if(!request.getMethod().equals("POST"))throw new DurableIssuerFixture.Denied(405);}
    private static void check(long deadline){if(System.nanoTime()-deadline>=0||Thread.currentThread().isInterrupted())throw new DurableIssuerFixture.Denied(503);}
    private static byte @NonNull [] read(@NonNull HttpServletRequest request,int maximum,long deadline)throws IOException {
        if(!Objects.equals(request.getContentType(),"application/x-www-form-urlencoded"))throw new DurableIssuerFixture.Denied(400);ByteArrayOutputStream body=new ByteArrayOutputStream();byte[] block=new byte[1024];InputStream stream=request.getInputStream();int count;
        while(true){check(deadline);count=stream.read(block,0,Math.min(block.length,maximum+1-body.size()));check(deadline);if(count<0)break;body.write(block,0,count);if(body.size()>maximum)throw new DurableIssuerFixture.Denied(413);}return body.toByteArray();
    }
    private static @NonNull Map<@NonNull String,@NonNull String> form(byte @NonNull [] bytes){String raw=new String(bytes,StandardCharsets.US_ASCII);if(!Arrays.equals(bytes,raw.getBytes(StandardCharsets.US_ASCII)))throw new DurableIssuerFixture.Denied(400);Map<String,String> values=new LinkedHashMap<>();for(String pair:raw.split("&",-1)){String[] parts=pair.split("=",-1);if(parts.length!=2||!parts[0].matches("[a-z_]+")||!parts[1].matches("[A-Za-z0-9_.-]+")||values.putIfAbsent(parts[0],parts[1])!=null)throw new DurableIssuerFixture.Denied(400);}return values;}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){Map<String,List<String>> headers=new LinkedHashMap<>();Enumeration<String> names=request.getHeaderNames();int bytes=0,count=0;while(names!=null&&names.hasMoreElements()){String name=names.nextElement().toLowerCase(Locale.ROOT);Enumeration<String> values=request.getHeaders(name);List<String> all=new ArrayList<>();while(values!=null&&values.hasMoreElements()){String value=values.nextElement();bytes+=name.length()+value.length();if(++count>48||bytes>16384)throw new DurableIssuerFixture.Denied(400);all.add(value);}headers.computeIfAbsent(name,k->new ArrayList<>()).addAll(all);}return headers;}
    private static @Nullable String optional(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){List<String> values=headers.get(name);if(values==null)return null;if(values.size()!=1)throw new DurableIssuerFixture.Denied(400);return values.get(0);}
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){String value=optional(headers,name);if(value==null)throw new DurableIssuerFixture.Denied(400);return value;}
    private static void cookie(@NonNull HttpServletResponse response,@NonNull String value,int seconds){response.addHeader("Set-Cookie",DurableIssuerFixture.COOKIE+'='+value+"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="+seconds);}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject value)throws IOException {response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setHeader("Content-Type","application/json; charset=UTF-8");byte[] bytes=status==204?new byte[0]:value.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    private static @NonNull HttpServletRequest bounded(@NonNull HttpServletRequest request,long deadline){return new HttpServletRequestWrapper(request){
        private @Nullable ServletInputStream stream;
        @Override public @NonNull ServletInputStream getInputStream()throws IOException {
            if(this.stream==null){ServletInputStream source=super.getInputStream();this.stream=new ServletInputStream(){
                @Override public int read()throws IOException{check(deadline);int value=source.read();check(deadline);return value;}
                @Override public int read(byte @NonNull [] b,int off,int len)throws IOException{check(deadline);int value=source.read(b,off,len);check(deadline);return value;}
                @Override public boolean isFinished(){return source.isFinished();}@Override public boolean isReady(){return source.isReady();}@Override public void setReadListener(@NonNull ReadListener listener){throw new UnsupportedOperationException("Synchronous fixture only");}
            };}return Objects.requireNonNull(this.stream);
        }
    };}
}
