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

/** Test-only control/authenticator around the unchanged application and actual reference store. */
@ThreadSafe
@SuppressWarnings("serial")
public final class DurablePasskeyServlet extends HttpServlet {
    private static final long serialVersionUID=1L;
    private final @NonNull DurablePasskeyFixture fixture=create();
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException {
        String expected=System.getenv().getOrDefault("REVETSEC_DURABLE_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        String path=request.getPathInfo();
        if(path!=null&&path.startsWith("/fixture/")){
            try{
                if(request.getQueryString()!=null||!DurablePasskeyFixture.RP.equals(one(request,"Host")))throw new IllegalArgumentException("Fixed fixture route");String route=path.substring(9);
                if(route.startsWith("mint/")){
                    if(!request.getMethod().equals("POST"))throw new IllegalArgumentException("Fixture method");String[] parts=route.split("/",-1);if(parts.length!=3)throw new IllegalArgumentException("Fixture mint route");byte[] body=request.getInputStream().readNBytes(4097);if(body.length>4096)throw new IllegalArgumentException("Fixture body cap");String form=new String(body,StandardCharsets.US_ASCII);if(!form.startsWith("challenge=")||form.indexOf('&')>=0)throw new IllegalArgumentException("Fixture fields");String challenge=URLDecoder.decode(form.substring(10),StandardCharsets.UTF_8);send(response,200,this.fixture.mint(parts[1],parts[2],challenge));return;
                }
                if(!request.getMethod().equals("GET")||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture control");
                send(response,200,this.fixture.control(route));return;
            }catch(Exception malformed){send(response,400,JsonObject.builder().put("error","Fixture control rejected").build());return;}
        }
        this.fixture.application.service(request,response);
    }
    private static @NonNull DurablePasskeyFixture create(){try{return new DurablePasskeyFixture();}catch(Exception failure){throw new IllegalStateException("Owned durable fixture preparation refused");}}
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String first=values.nextElement();return values.hasMoreElements()?null:first;}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject value)throws IOException {byte[] body=value.toJson().getBytes(StandardCharsets.UTF_8);response.setStatus(status);response.setHeader("Content-Type","application/json; charset=UTF-8");response.setHeader("Cache-Control","no-store");response.setContentLength(body.length);response.getOutputStream().write(body);}
}
