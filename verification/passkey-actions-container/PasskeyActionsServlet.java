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
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Test-only control/authenticator and explicit writer-refusal seam around the unchanged app. */
@ThreadSafe
@SuppressWarnings("serial")
public final class PasskeyActionsServlet extends HttpServlet {
    private static final long serialVersionUID=1L;
    private final @NonNull PasskeyActionsFixture fixture=new PasskeyActionsFixture();
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException {
        String expected=System.getenv().getOrDefault("REVETSEC_PASSKEY_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        String path=request.getPathInfo();
        if(path!=null&&path.startsWith("/fixture/")){
            try{
                if(request.getQueryString()!=null||!PasskeyActionsFixture.RP.equals(one(request,"Host")))throw new IllegalArgumentException("Fixed fixture route");String route=path.substring(9);
                if(route.startsWith("mint/")){
                    if(!request.getMethod().equals("POST"))throw new IllegalArgumentException("Fixture method");String[] parts=route.split("/",-1);if(parts.length!=3)throw new IllegalArgumentException("Fixture mint route");byte[] body=request.getInputStream().readNBytes(4097);if(body.length>4096)throw new IllegalArgumentException("Fixture body cap");String form=new String(body,StandardCharsets.US_ASCII);if(!form.startsWith("challenge=")||form.indexOf('&')>=0)throw new IllegalArgumentException("Fixture fields");String challenge=URLDecoder.decode(form.substring(10),StandardCharsets.UTF_8);send(response,200,this.fixture.mint(parts[1],parts[2],challenge));return;
                }
                if(!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture control");
                if(route.startsWith("proof/")){send(response,200,this.fixture.proofGuard(route.substring(6)));return;}
                send(response,200,this.fixture.control(route));return;
            }catch(Exception malformed){send(response,400,JsonObject.builder().put("error","Fixture control rejected").build());return;}
        }
        String selected=path!=null&&(path.equals("/reauth/finish")||path.equals("/credentials/self-remove/finish"))?this.fixture.writerMode.getAndSet("normal"):"normal";
        // Explicit injected interruption ONLY: observe handler flag + burned grant before fixture
        // clears that flag, then hand this bounded buffer to Tomcat. Not production transport behavior.
        BufferedResponse interruptBuffer=this.fixture.gate.mode.get().equals("close-interrupt")?new BufferedResponse(response):null;
        HttpServletResponse target=interruptBuffer==null?response:interruptBuffer;
        if(!selected.equals("normal"))target=new HttpServletResponseWrapper(target){
            private @Nullable ServletOutputStream stream;
            @Override public @NonNull ServletOutputStream getOutputStream(){
                if(this.stream==null)this.stream=new ServletOutputStream(){@Override public boolean isReady(){return true;}@Override public void setWriteListener(@NonNull WriteListener listener){throw new UnsupportedOperationException("Synchronous fixture only");}
                    @Override public void write(int ignored)throws IOException {refuse();}
                    @Override public void write(byte @NonNull [] bytes,int offset,int length)throws IOException {refuse();}
                    private void refuse()throws IOException {
                        fixture.writerAttempts.incrementAndGet();if(selected.equals("writer-runtime"))throw new IllegalStateException("Declared test-only runtime writer refusal");
                        if(selected.equals("writer-block-throw")){PasskeyActionsFixture.Latch value=new PasskeyActionsFixture.Latch();fixture.writerLatch.set(value);value.waitHere();}
                        if(selected.equals("writer-clock-throw"))fixture.clock.fail.set(true);
                        throw new IOException("Declared test-only synchronous writer refusal");
                    }
                };return Objects.requireNonNull(this.stream);
            }
        };
        boolean writeFailure=false;
        try{this.fixture.application.service(request,target);}
        catch(IOException|RuntimeException observed){writeFailure=true;if(!selected.equals("normal"))this.fixture.observedWriterFailure();}
        finally{this.fixture.observedPostClose();}
        if(!writeFailure&&interruptBuffer!=null)interruptBuffer.flushTo(response);
        if(writeFailure&&!response.isCommitted()){response.reset();send(response,503,JsonObject.builder().put("error","Fixture observed writer refusal").build());}
    }
    private static final class BufferedResponse extends HttpServletResponseWrapper {
        private final @NonNull ByteArrayOutputStream body=new ByteArrayOutputStream();private final @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields=new LinkedHashMap<>();private int status=200;
        BufferedResponse(@NonNull HttpServletResponse response){super(response);}
        @Override public void setStatus(int status){this.status=status;}
        @Override public void setHeader(@NonNull String name,@NonNull String value){this.fields.put(name,new ArrayList<>(List.of(value)));}
        @Override public void addHeader(@NonNull String name,@NonNull String value){this.fields.computeIfAbsent(name,ignored->new ArrayList<>()).add(value);}
        @Override public void setContentLength(int length){setHeader("Content-Length",Integer.toString(length));}
        @Override public void setContentLengthLong(long length){setHeader("Content-Length",Long.toString(length));}
        @Override public @NonNull ServletOutputStream getOutputStream(){return new ServletOutputStream(){@Override public boolean isReady(){return true;}@Override public void setWriteListener(@NonNull WriteListener listener){throw new UnsupportedOperationException("Injected synchronous fixture only");}@Override public void write(int value)throws IOException{if(body.size()>=65_536)throw new IOException("Fixture response cap");body.write(value);}};}
        void flushTo(@NonNull HttpServletResponse response)throws IOException{response.setStatus(this.status);for(var entry:this.fields.entrySet())for(String value:entry.getValue())response.addHeader(entry.getKey(),value);response.getOutputStream().write(this.body.toByteArray());}
    }
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String first=values.nextElement();return values.hasMoreElements()?null:first;}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject value)throws IOException {byte[] body=value.toJson().getBytes(StandardCharsets.UTF_8);response.setStatus(status);response.setHeader("Content-Type","application/json; charset=UTF-8");response.setHeader("Cache-Control","no-store");response.setContentLength(body.length);response.getOutputStream().write(body);}
}
