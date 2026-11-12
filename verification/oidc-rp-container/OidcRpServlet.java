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
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponseWrapper;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;

/** Private disposable S1 host; do not deploy its account/clock/provider/fault controls. */
@ThreadSafe
@SuppressWarnings("serial")
public final class OidcRpServlet extends HttpServlet{
    private static final long serialVersionUID=1L;
    private final @NonNull OidcProviderFixture fixture;
    public OidcRpServlet(){try{this.fixture=new OidcProviderFixture();}catch(IOException unavailable){throw new IllegalStateException("Fixture unavailable");}}
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        String expected=System.getenv().getOrDefault("REVETSEC_OIDC_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        String path=request.getPathInfo();
        {
            if(path!=null&&path.startsWith("/fixture/")){
                if(!request.getMethod().equals("GET")||request.getQueryString()!=null||request.getContentLengthLong()>0){send(response,400,JsonObject.builder().put("error","Fixture denied").build());return;}
                try{send(response,200,this.fixture.control(path.substring("/fixture/".length())));}catch(IllegalArgumentException malformed){send(response,400,JsonObject.builder().put("error","Fixture denied").build());}return;
            }
            Set<String> priorIds=this.fixture.recipe().sessionIds();
            BufferedResponse buffered=new BufferedResponse(response);
            this.fixture.recipe().service(request,buffered);
            // Observe before clearing, and only consume the explicitly injected fixture cancellation.
            if(this.fixture.takeInjectedInterrupt()){
                this.fixture.recordCancellation(Thread.currentThread().isInterrupted(),
                        priorIds.equals(this.fixture.recipe().sessionIds())&&buffered.withheld());
                Thread.interrupted();
            }
            buffered.writeTo(response);
        }
    }
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String value=values.nextElement();return values.hasMoreElements()?null:value;}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject body)throws IOException{response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setContentType("application/json; charset=UTF-8");byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    /** Test-only buffered decision observation; ordinary transport interruption may close the real socket. */
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
        boolean withheld(){return this.status==503&&this.headers.entrySet().stream().noneMatch(entry->entry.getKey().equalsIgnoreCase("Location")||entry.getKey().equalsIgnoreCase("Set-Cookie")&&entry.getValue().stream().anyMatch(cookie->cookie.startsWith(ServletOidcRpRecipe.SESSION_COOKIE+'=')))&&this.body.toString(StandardCharsets.UTF_8).equals("{\"error\":\"Request denied\"}");}
        void writeTo(@NonNull HttpServletResponse response)throws IOException{
            response.setStatus(this.status);
            this.headers.forEach((name,values)->{for(String value:values)response.addHeader(name,value);});
            response.getOutputStream().write(this.body.toByteArray());
        }
    }
    @Override public void destroy(){this.fixture.close();super.destroy();}
}
