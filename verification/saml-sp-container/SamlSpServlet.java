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
import jakarta.servlet.WriteListener;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Disposable S3 carrier; authenticated fixture controls and synthetic IdP are never deployment routes. */
@ThreadSafe
@SuppressWarnings("serial")
public final class SamlSpServlet extends HttpServlet{
    private static final long serialVersionUID=1L;
    private final @NonNull SamlSpFixture fixture=new SamlSpFixture();
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        String expected=System.getenv().getOrDefault("REVETSEC_SAML_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
        if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){send(response,401,JsonObject.builder().put("error","Fixture denied").build());return;}
        String path=request.getPathInfo();
        try{
            if(path!=null&&path.startsWith("/fixture/")){
                String command=path.substring(9);
                if(command.startsWith("mint/")||command.startsWith("idp-logout/")){
                    String[] parts=command.split("/",-1);if(parts.length!=4||!request.getMethod().equals("POST")||request.getQueryString()!=null)throw new IllegalArgumentException("Fixture route");
                    byte[] bytes=request.getInputStream().readNBytes(131_073);if(bytes.length>131_072)throw new IllegalArgumentException("Fixture bound");
                    send(response,200,parts[0].equals("mint")?this.fixture.mint(parts[1],parts[2],parts[3],new String(bytes,StandardCharsets.US_ASCII)):this.fixture.idpLogout(parts[1],parts[2],parts[3].equals("POST")));return;
                }
                if(!request.getMethod().equals("GET")||request.getQueryString()!=null||request.getContentLengthLong()>0)throw new IllegalArgumentException("Fixture route");
                send(response,200,this.fixture.control(command));return;
            }
            if(request.getServletPath().equals("/idp")){
                String host=one(request,"Host"),connection=host!=null&&host.startsWith("idpa.example.test")?"idp-a":host!=null&&host.startsWith("idpb.example.test")?"idp-b":"";
                if(connection.isEmpty()||!Set.of("/sso","/slo").contains(path))throw new IllegalArgumentException("Fixture IdP route");
                byte[] bytes=request.getInputStream().readNBytes(131_073);if(bytes.length>131_072)throw new IllegalArgumentException("Fixture IdP bound");
                String raw=request.getMethod().equals("GET")?request.getQueryString():new String(bytes,StandardCharsets.US_ASCII);if(raw==null)throw new IllegalArgumentException("Fixture IdP fields");
                JsonObject result=this.fixture.mint(connection,"valid",request.getMethod(),raw);
                String method=((com.revetsec.json.JsonString)result.getMembers().get("method")).getValue(),action=((com.revetsec.json.JsonString)result.getMembers().get("action")).getValue(),body=((com.revetsec.json.JsonString)result.getMembers().get("body")).getValue();
                if(method.equals("GET")){response.setStatus(303);response.setHeader("Location",action+'?'+body);response.setHeader("Cache-Control","no-store");return;}
                StringBuilder form=new StringBuilder("<!doctype html><meta charset=utf-8><title>Synthetic IdP</title><form method=post action=\"").append(escape(action)).append("\">");
                for(var field:SamlSpFixture.form(body).entrySet())form.append("<input type=hidden name=\"").append(escape(field.getKey())).append("\" value=\"").append(escape(field.getValue())).append("\">");
                form.append("<button id=continue type=submit>Continue</button></form>");html(response,form.toString(),this.fixture.idpReferrerPolicy());return;
            }
            if("/home".equals(path)&&request.getMethod().equals("GET")){
                html(response,"<!doctype html><meta charset=utf-8><title>SAML SP</title><button id=bootstrap>Start session</button><div id=controls></div><script>document.querySelector('#bootstrap').onclick=async()=>{let r=await fetch('/saml/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'begin=1'});let d=await r.json();if(!r.ok)throw Error('bootstrap');let out=document.querySelector('#controls');for(let p of ['login/idp-a/redirect','login/idp-a/post','login/idp-b/post','logout/local','logout/redirect','logout/post']){let f=document.createElement('form');f.method='post';f.action='/saml/'+p;let i=document.createElement('input');i.type='hidden';i.name='csrf';i.value=d.csrf;f.append(i);let b=document.createElement('button');b.textContent=p;b.id=p.replaceAll('/','-');f.append(b);out.append(f);}}</script>");return;
            }
            Set<String> prior=this.fixture.recipe().sessionIds();BufferedResponse buffered=new BufferedResponse(response);this.fixture.recipe().service(request,buffered);
            if(this.fixture.takeInjectedInterrupt()){this.fixture.recordCancellation(Thread.currentThread().isInterrupted(),prior.equals(this.fixture.recipe().sessionIds())&&buffered.withheld());Thread.interrupted();}
            buffered.writeTo(response);
        }catch(Exception rejected){send(response,400,JsonObject.builder().put("error","Fixture request rejected").build());}
    }
    private static @Nullable String one(@NonNull HttpServletRequest request,@NonNull String name){Enumeration<String> values=request.getHeaders(name);if(values==null||!values.hasMoreElements())return null;String value=values.nextElement();return values.hasMoreElements()?null:value;}
    private static @NonNull String escape(@NonNull String value){return value.replace("&","&amp;").replace("\"","&quot;").replace("<","&lt;").replace(">","&gt;");}
    private static void send(@NonNull HttpServletResponse response,int status,@NonNull JsonObject body)throws IOException{response.setStatus(status);response.setHeader("Cache-Control","no-store");response.setContentType("application/json; charset=UTF-8");byte[] bytes=body.toJson().getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
    private static void html(@NonNull HttpServletResponse response,@NonNull String body)throws IOException{html(response,body,"strict-origin");}
    private static void html(@NonNull HttpServletResponse response,@NonNull String body,@NonNull String policy)throws IOException{response.setStatus(200);response.setHeader("Cache-Control","no-store");response.setHeader("Referrer-Policy",policy);response.setContentType("text/html; charset=UTF-8");byte[] bytes=body.getBytes(StandardCharsets.UTF_8);response.setContentLength(bytes.length);response.getOutputStream().write(bytes);}
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
        boolean withheld(){return this.status==503&&this.headers.entrySet().stream().noneMatch(entry->entry.getKey().equalsIgnoreCase("Location")||entry.getKey().equalsIgnoreCase("Set-Cookie")&&entry.getValue().stream().anyMatch(cookie->cookie.startsWith(ServletSamlSpRecipe.SESSION_COOKIE+'=')))&&this.body.toString(StandardCharsets.UTF_8).equals("{\"error\":\"Request denied\"}");}
        void writeTo(@NonNull HttpServletResponse response)throws IOException{
            response.setStatus(this.status);
            this.headers.forEach((name,values)->{for(String value:values)response.addHeader(name,value);});
            response.getOutputStream().write(this.body.toByteArray());
        }
    }
}
