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

import com.revetsec.json.JsonObject;
import jakarta.servlet.http.*;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.WriteListener;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Protected disposable S4 fixture controls, never deployment endpoints. */
@ThreadSafe
@SuppressWarnings("serial")
public final class ScimDirectoryServlet extends HttpServlet{
    private static final long serialVersionUID=1L;
    private final @NonNull ScimDirectoryFixture fixture;
    private final @NonNull AtomicBoolean interruptObserved=new AtomicBoolean(),interruptLeftSet=new AtomicBoolean(),interruptSafe=new AtomicBoolean(),lastHandlerInterrupted=new AtomicBoolean();
    public ScimDirectoryServlet(){try{this.fixture=new ScimDirectoryFixture();}catch(IOException unavailable){throw new IllegalStateException("Fixture unavailable");}}
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        String expected=System.getenv().getOrDefault("REVETSEC_SCIM_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        if(request.getServletPath().equals("/fixture")){
            try{
                if(request.getQueryString()!=null)throw new IllegalArgumentException("Fixture route");String path=request.getPathInfo();if(path==null)throw new IllegalArgumentException("Fixture route");
                if(path.startsWith("/token/")){
                    String[] parts=path.split("/",-1);if(parts.length!=4||!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture token");
                    if(!Set.of("valid","wrong-key","wrong-issuer","wrong-audience","expired","future","unmapped","missing-client","missing-tenant","wrong-tenant","no-scope","read-only","role-claim-admin","wrong-type").contains(parts[3]))throw new IllegalArgumentException("Fixture token mode");
                    send(response,200,JsonObject.builder().put("token",this.fixture.token(parts[2],parts[3])).build());return;
                }
                if(path.startsWith("/password/")){
                    String[] parts=path.split("/",-1);if(parts.length!=4||!request.getMethod().equals("POST"))throw new IllegalArgumentException("Fixture password oracle");byte[] bytes=request.getInputStream().readNBytes(1025);if(bytes.length>1024)throw new IllegalArgumentException("Fixture password bound");
                    char[] password=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString().toCharArray();send(response,200,JsonObject.builder().put("matched",this.fixture.passwordMatches(parts[2],parts[3],password)).build());Arrays.fill(bytes,(byte)0);return;
                }
                if(!path.startsWith("/control/")||!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture control");
                send(response,200,JsonObject.builder().put("fixture",this.fixture.control(path.substring(9))).put("interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptLeftSet.get()).put("handler_cancel_no_publication",this.interruptSafe.get()).put("last_handler_interrupt_set",this.lastHandlerInterrupted.get()).build());return;
            }catch(Exception malformed){send(response,400,JsonObject.builder().put("error","Fixture denied").build());return;}
        }
        long before=this.fixture.writes();BufferedResponse buffered=new BufferedResponse(response);HttpServletRequest selected=request;String fault=one(request,"X-Fixture-Carrier");
        if("insecure".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public boolean isSecure(){return false;}@Override public @NonNull String getScheme(){return "http";}};
        if("stream-io".equals(fault))selected=new HttpServletRequestWrapper(request){@Override public @NonNull ServletInputStream getInputStream()throws IOException{throw new IOException("Fixture unavailable input");}};
        this.fixture.recipe().service(selected,buffered);this.lastHandlerInterrupted.set(Thread.currentThread().isInterrupted());
        if(this.fixture.takeInjectedInterrupt()){this.interruptObserved.set(true);this.interruptLeftSet.set(Thread.currentThread().isInterrupted());this.interruptSafe.set(before==this.fixture.writes()&&buffered.withheld());Thread.interrupted();}
        buffered.writeTo(response);
    }
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String value=values.nextElement();return values.hasMoreElements()?null:value;}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject body)throws IOException{response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setContentType("application/json; charset=UTF-8");byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    private static final class BufferedResponse extends HttpServletResponseWrapper{
        private final @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers=new LinkedHashMap<>();
        private final @NonNull ByteArrayOutputStream body=new ByteArrayOutputStream();
        private int status=200;
        private final @NonNull ServletOutputStream stream=new ServletOutputStream(){
            @Override public boolean isReady(){return true;}
            @Override public void setWriteListener(@NonNull WriteListener listener){throw new UnsupportedOperationException("Synchronous fixture only");}
            @Override public void write(int value){if(body.size()>=65_536)throw new IllegalStateException("Fixture response overflow");body.write(value);}
        };
        BufferedResponse(@NonNull HttpServletResponse response){super(response);}
        @Override public void setStatus(int status){this.status=status;}
        @Override public void setHeader(@NonNull String name,@NonNull String value){this.headers.put(name,new ArrayList<>(List.of(value)));}
        @Override public void addHeader(@NonNull String name,@NonNull String value){this.headers.computeIfAbsent(name,ignored->new ArrayList<>()).add(value);}
        @Override public void setContentType(@NonNull String value){setHeader("Content-Type",value);}
        @Override public void setContentLength(int length){setHeader("Content-Length",Integer.toString(length));}
        @Override public @NonNull ServletOutputStream getOutputStream(){return this.stream;}
        boolean withheld(){return this.status==503&&!this.headers.containsKey("Location")&&!this.headers.keySet().stream().anyMatch(name->name.equalsIgnoreCase("Set-Cookie"))&&!this.body.toString(StandardCharsets.UTF_8).contains("\"userName\"")&&!this.body.toString(StandardCharsets.UTF_8).contains("\"Resources\"");}
        void writeTo(@NonNull HttpServletResponse response)throws IOException{
            response.setStatus(this.status);
            this.headers.forEach((name,values)->{for(String value:values)response.addHeader(name,value);});
            response.getOutputStream().write(this.body.toByteArray());
        }
    }
    @Override public void destroy(){this.fixture.close();super.destroy();}
}
