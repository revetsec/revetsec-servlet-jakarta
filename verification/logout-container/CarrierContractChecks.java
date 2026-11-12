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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import org.jspecify.annotations.NonNull;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;

/** Focused carrier contract: output failure escapes once; a startup declaration is mandatory. */
public final class CarrierContractChecks {
    private CarrierContractChecks(){}
    public static void main(@NonNull String @NonNull [] arguments)throws Exception{
        int denied=0;
        for(int missing=0;missing<4;missing++){
            try{new ServletOidcLogoutRecipe.TransportAssurance(missing!=0,missing!=1,missing!=2,missing!=3);throw new AssertionError("Missing startup assurance accepted");}
            catch(IllegalArgumentException expected){denied++;}
        }
        try(LogoutFixture fixture=new LogoutFixture()){
            var recipe=new ServletOidcLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),new ServletOidcLogoutRecipe.TransportAssurance(true,true,true,true));
            HttpServletRequest request=(HttpServletRequest)Proxy.newProxyInstance(CarrierContractChecks.class.getClassLoader(),new Class<?>[]{HttpServletRequest.class},(proxy,method,args)->switch(method.getName()){
                case "getRequestURI"->"/logout/callback";case "getContextPath"->"";case "getServletPath"->"/logout";case "getPathInfo"->"/callback";case "getMethod"->"GET";case "isSecure"->false;case "getScheme"->"http";default->throw new UnsupportedOperationException("Unexpected input access");});
            AtomicInteger writes=new AtomicInteger();
            HttpServletResponse response=(HttpServletResponse)Proxy.newProxyInstance(CarrierContractChecks.class.getClassLoader(),new Class<?>[]{HttpServletResponse.class},(proxy,method,args)->{
                if(method.getName().equals("getOutputStream")){writes.incrementAndGet();return new ServletOutputStream(){@Override public boolean isReady(){return true;}@Override public void setWriteListener(@NonNull WriteListener listener){throw new UnsupportedOperationException("Synchronous check");}@Override public void write(int value)throws IOException{throw new IOException("TEST-ONLY output failure");}};}
                if(method.getName().startsWith("set")||method.getName().equals("addHeader"))return null;throw new UnsupportedOperationException("Unexpected output access");
            });
            boolean escaped=false;try{recipe.service(request,response);}catch(IOException expected){escaped=true;}
            if(!escaped||writes.get()!=1)throw new AssertionError("output-failure-propagates-once; writes="+writes.get());
            if(fixture.control("state").getMembers().get("closes").toJson().equals("0")==false)throw new AssertionError("Carrier refusal invoked close");
        }
        System.out.println("{\"passed\":true,\"startupRefusals\":"+denied+",\"outputFailures\":1}");
    }
}
