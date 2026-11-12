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
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.util.*;

/** Unpublished root-context carrier for one injected local-first RP logout application. */
@ThreadSafe
@SuppressWarnings("serial")
public final class ServletOidcLogoutRecipe extends HttpServlet {
    private static final long serialVersionUID=1L;
    private static final int MAXIMUM_BODY=4096;
    /**
     * A required startup declaration from the deployment owner, not transport verification.
     * Qualify the actual connector/edge; do not infer these properties from Servlet accessors.
     */
    public record TransportAssurance(boolean authenticatedHttps,boolean originalRawTarget,
            boolean unambiguousPhysicalHeaders,boolean boundedFramingAndReadTime){
        public TransportAssurance{if(!authenticatedHttps||!originalRawTarget||!unambiguousPhysicalHeaders||!boundedFramingAndReadTime)throw new IllegalArgumentException("Qualified deployment transport is required");}
    }
    private final @NonNull LocalFirstLogout application;
    public ServletOidcLogoutRecipe(@NonNull LocalFirstLogout application,@NonNull TransportAssurance assurance){this.application=Objects.requireNonNull(application);Objects.requireNonNull(assurance);}
    @Override protected void service(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response)throws IOException{
        String rawPath=request.getRequestURI();LocalFirstLogout.Reply reply;
        try{
            String info=request.getPathInfo();String canonical=request.getServletPath()+(info==null?"":info);
            // The shared recipe's fixed callback is /logout/callback at this origin's root.
            // Never reconstruct routing or HTTPS/peer identity from forwarding headers.
            if(!request.getContextPath().isEmpty()||!request.getServletPath().equals("/logout")||!rawPath.equals(canonical)){
                throw new CarrierRefusal(400);
            }
            if(Thread.currentThread().isInterrupted()){throw new CarrierRefusal(503);}
            if(!request.isSecure()||!request.getScheme().equals("https")){throw new CarrierRefusal(400);}
            Map<String,List<String>> headers=headers(request);
            if(request.getContentLengthLong()>MAXIMUM_BODY){throw new CarrierRefusal(413);}
            // Read cap+1 even without a Content-Length. An over-limit prefix is never success.
            byte[] body=request.getInputStream().readNBytes(MAXIMUM_BODY+1);
            if(body.length>MAXIMUM_BODY){throw new CarrierRefusal(413);}
            reply=this.application.handle(new LocalFirstLogout.Request(request.getMethod(),rawPath,
                    request.getQueryString(),headers,body,false,true,request.getRemoteAddr()));
        }catch(CarrierRefusal refused){reply=this.application.rejectCarrierRequest(rawPath,refused.status);}
        catch(IllegalArgumentException malformed){reply=this.application.rejectCarrierRequest(rawPath,400);}
        catch(IOException unavailable){if(unavailable instanceof java.io.InterruptedIOException&&!(unavailable instanceof java.net.SocketTimeoutException))Thread.currentThread().interrupt();reply=this.application.rejectCarrierRequest(rawPath,503);}
        catch(RuntimeException unavailable){reply=this.application.rejectCarrierRequest(rawPath,503);}
        // Output failure is a transport failure; never reinterpret it as an unapplied logout.
        write(response,request,reply);
    }
    private static final class CarrierRefusal extends RuntimeException{private static final long serialVersionUID=1L;final int status;CarrierRefusal(int status){super("Carrier refused");this.status=status;}}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull HttpServletRequest request){
        Enumeration<String> names=request.getHeaderNames();if(names==null)throw new IllegalArgumentException("Raw headers unavailable");
        Map<String,List<String>> result=new LinkedHashMap<>();int count=0,occurrences=0;long bytes=0;
        while(names.hasMoreElements()){
            if(++count>32)throw new IllegalArgumentException("Header budget exceeded");String name=names.nextElement();
            if(name==null||!name.matches("[A-Za-z0-9-]{1,64}"))throw new IllegalArgumentException("Header budget exceeded");
            Enumeration<String> values=request.getHeaders(name);if(values==null)throw new IllegalArgumentException("Raw headers unavailable");List<String> copy=new ArrayList<>();
            while(values.hasMoreElements()){
                if(++occurrences>32)throw new IllegalArgumentException("Header budget exceeded");String value=values.nextElement();
                if(value==null||value.length()>4096||!value.chars().allMatch(c->c>=0x20&&c<=0x7e))throw new IllegalArgumentException("Header budget exceeded");
                bytes+=name.length()+value.length();if(bytes>8192)throw new IllegalArgumentException("Header budget exceeded");copy.add(value);
            }
            if(copy.isEmpty()||result.putIfAbsent(name.toLowerCase(Locale.ROOT),List.copyOf(copy))!=null)throw new IllegalArgumentException("Ambiguous headers");
        }
        return Map.copyOf(result);
    }
    private static void write(@NonNull HttpServletResponse response,@NonNull HttpServletRequest request,LocalFirstLogout.@NonNull Reply reply)throws IOException{
        response.setStatus(reply.status());reply.headers().forEach(response::setHeader);
        // Logout completion requires independent local-session and pending-binding cookie fields.
        for(String cookie:reply.cookies())response.addHeader("Set-Cookie",cookie);
        byte[] bytes=reply.body();response.setContentLength(bytes.length);if(!request.getMethod().equals("HEAD"))response.getOutputStream().write(bytes);
    }
    @Override public @NonNull String toString(){return "ServletOidcLogoutRecipe{<redacted>}";}
}
