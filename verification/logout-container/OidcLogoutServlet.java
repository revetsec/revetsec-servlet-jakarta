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

import example.logout.LocalFirstLogout;
import example.logout.LogoutFixture;
import com.revetsec.json.JsonObject;
import com.revetsec.oidc.OidcClient;
import jakarta.servlet.http.*;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.WriteListener;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Disposable carrier controls backed only by the separate JUnit-free genuine-flow fixture JAR. */
@ThreadSafe
@SuppressWarnings("serial")
public final class OidcLogoutServlet extends HttpServlet{
    private static final long serialVersionUID=1L;
    private final @NonNull LogoutFixture fixture;
    private final @NonNull ServletOidcLogoutRecipe recipe;
    private final @NonNull Set<@NonNull String> issued=new LinkedHashSet<>();
    private final @NonNull AtomicBoolean carrierInterrupt=new AtomicBoolean(),timeoutObserved=new AtomicBoolean(),timeoutInterrupted=new AtomicBoolean(),lastHandlerInterrupted=new AtomicBoolean();
    private final @NonNull AtomicBoolean interruptObserved=new AtomicBoolean(),interruptLeftSet=new AtomicBoolean(),interruptSafe=new AtomicBoolean();
    public OidcLogoutServlet(){
        verifyOrigin(OidcClient.class,"CORE");verifyOrigin(LocalFirstLogout.class,"COMMON");verifyOrigin(LogoutFixture.class,"FIXTURE");
        try{int padding=Integer.parseInt(System.getenv().getOrDefault("REVETSEC_LOGOUT_PADDING","0"));if(padding!=0&&padding!=6000)throw new IllegalArgumentException("Fixture padding");this.fixture=new LogoutFixture("logout-rp","x".repeat(padding));}
        catch(Exception unavailable){throw new IllegalStateException("Fixture unavailable");}
        LocalFirstLogout.Delivery mode=System.getenv().getOrDefault("REVETSEC_LOGOUT_DELIVERY","form").equals("get")?LocalFirstLogout.Delivery.GET_REDIRECT:LocalFirstLogout.Delivery.FORM_POST;
        this.recipe=new ServletOidcLogoutRecipe(this.fixture.application(mode),new ServletOidcLogoutRecipe.TransportAssurance(true,true,true,true));
    }
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        String expected=System.getenv().getOrDefault("REVETSEC_LOGOUT_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        String path=request.getPathInfo();
        if(request.getServletPath().equals("/fixture")){
            try{
                if(request.getQueryString()!=null)throw new IllegalArgumentException("Fixture route");
                if("/login".equals(path)){
                    if(!request.getMethod().equals("POST")||!Arrays.equals(request.getInputStream().readNBytes(9),"begin=1".getBytes(StandardCharsets.US_ASCII)))throw new IllegalArgumentException("Fixture login");
                    LogoutFixture.Browser browser=this.fixture.login();synchronized(this.issued){if(this.issued.size()>=128)this.issued.removeIf(id->!this.fixture.live(id));if(this.issued.size()>=128)throw new IllegalStateException("Fixture capacity");this.issued.add(browser.session());}
                    response.addHeader("Set-Cookie",LocalFirstLogout.SESSION_COOKIE+'='+browser.session()+"; Path=/; Secure; HttpOnly; SameSite=Lax");
                    send(response,200,JsonObject.builder().put("csrf",browser.csrf()).put("genuine_authentication",browser.authentication().getSessionReference()!=null).build());return;
                }
                if(!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture control");
                if("/live".equals(path)){String cookie=one(request,"Cookie");String prefix=LocalFirstLogout.SESSION_COOKIE+'=';boolean live=cookie!=null&&cookie.startsWith(prefix)&&this.fixture.live(cookie.substring(prefix.length()));send(response,200,JsonObject.builder().put("live",live).build());return;}
                if(path==null||!path.startsWith("/control/"))throw new IllegalArgumentException("Fixture control");
                JsonObject shared=this.fixture.control(path.substring(9));send(response,200,JsonObject.builder().put("shared",shared).put("origin_verified",true).put("interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptLeftSet.get()).put("handler_cancel_no_publication",this.interruptSafe.get()).put("timeout_observed",this.timeoutObserved.get()).put("timeout_interrupt_set",this.timeoutInterrupted.get()).put("last_handler_interrupt_set",this.lastHandlerInterrupted.get()).build());return;
            }catch(Exception rejected){send(response,400,JsonObject.builder().put("error","Fixture denied").build());return;}
        }
        Set<String> before=liveIds();BufferedResponse buffered=new BufferedResponse(response);HttpServletRequest selected=request;
        String fault=one(request,"X-Fixture-Carrier");
        if("insecure".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public boolean isSecure(){return false;}@Override public @NonNull String getScheme(){return "http";}};
        if("stream-io".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public @NonNull ServletInputStream getInputStream()throws IOException{throw new IOException("Fixture input unavailable");}};
        if("stream-interrupt".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public @NonNull ServletInputStream getInputStream()throws IOException{carrierInterrupt.set(true);throw new InterruptedIOException("Fixture interrupted input");}};
        if("stream-timeout".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public @NonNull ServletInputStream getInputStream()throws IOException{throw new java.net.SocketTimeoutException("Fixture input timeout");}};
        this.recipe.service(selected,buffered);
        this.lastHandlerInterrupted.set(Thread.currentThread().isInterrupted());
        if("stream-timeout".equals(fault)){this.timeoutObserved.set(true);this.timeoutInterrupted.set(Thread.currentThread().isInterrupted());}
        if(this.fixture.takeInjectedInterrupt()|this.carrierInterrupt.getAndSet(false)){
            this.interruptObserved.set(true);this.interruptLeftSet.set(Thread.currentThread().isInterrupted());
            this.interruptSafe.set(buffered.withheld()&&before.containsAll(liveIds()));Thread.interrupted();
        }
        buffered.writeTo(response);
    }
    private @NonNull Set<@NonNull String> liveIds(){synchronized(this.issued){Set<String> result=new LinkedHashSet<>();for(String id:this.issued)if(this.fixture.live(id))result.add(id);return Set.copyOf(result);}}
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String value=values.nextElement();return values.hasMoreElements()?null:value;}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject body)throws IOException{response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setContentType("application/json; charset=UTF-8");byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind){try{Path expected=Path.of(Objects.requireNonNull(System.getenv("REVETSEC_LOGOUT_"+kind+"_JAR"))).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)));if(!expected.equals(actual)||!hash.equals(System.getenv("REVETSEC_LOGOUT_"+kind+"_SHA256")))throw new IllegalStateException("Artifact origin mismatch");}catch(Exception mismatch){throw new IllegalStateException("Artifact origin mismatch");}}
    private static final class BufferedResponse extends HttpServletResponseWrapper{
        private final @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers=new LinkedHashMap<>();
        private final @NonNull ByteArrayOutputStream body=new ByteArrayOutputStream();
        private int status=200;
        private final @NonNull ServletOutputStream stream=new ServletOutputStream(){
            @Override public boolean isReady(){return true;}
            @Override public void setWriteListener(@NonNull WriteListener listener){throw new UnsupportedOperationException("Synchronous fixture only");}
            @Override public void write(int value){if(body.size()>=131_072)throw new IllegalStateException("Fixture response overflow");body.write(value);}
        };
        BufferedResponse(@NonNull HttpServletResponse response){super(response);}
        @Override public void setStatus(int status){this.status=status;}
        @Override public void setHeader(@NonNull String name,@NonNull String value){this.headers.put(name,new ArrayList<>(List.of(value)));}
        @Override public void addHeader(@NonNull String name,@NonNull String value){this.headers.computeIfAbsent(name,ignored->new ArrayList<>()).add(value);}
        @Override public void setContentType(@NonNull String value){setHeader("Content-Type",value);}
        @Override public void setContentLength(int length){setHeader("Content-Length",Integer.toString(length));}
        @Override public @NonNull ServletOutputStream getOutputStream(){return this.stream;}
        boolean withheld(){return this.status==503&&!this.headers.containsKey("Location")&&!this.body.toString(StandardCharsets.UTF_8).contains("id_token_hint")&&!this.body.toString(StandardCharsets.UTF_8).contains("<form")&&this.headers.entrySet().stream().noneMatch(entry->entry.getKey().equalsIgnoreCase("Set-Cookie")&&entry.getValue().stream().anyMatch(cookie->(cookie.startsWith(LocalFirstLogout.PENDING_COOKIE+'=')&&!cookie.startsWith(LocalFirstLogout.PENDING_COOKIE+"=;"))||(cookie.startsWith(LocalFirstLogout.SESSION_COOKIE+'=')&&!cookie.startsWith(LocalFirstLogout.SESSION_COOKIE+"=;"))));}
        void writeTo(@NonNull HttpServletResponse response)throws IOException{
            response.setStatus(this.status);
            this.headers.forEach((name,values)->{for(String value:values)response.addHeader(name,value);});
            response.getOutputStream().write(this.body.toByteArray());
        }
    }
    @Override public void destroy(){this.fixture.close();super.destroy();}
}
