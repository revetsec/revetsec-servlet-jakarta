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
package com.revetsec.servlet.jakarta;

import com.revetsec.saml.InMemorySamlReplayCache;
import com.revetsec.saml.SamlAuthenticationRequestResult;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlLogoutPostResult;
import com.revetsec.saml.SamlLogoutResponsePostResult;
import com.revetsec.saml.SamlLogoutRequestResult;
import com.revetsec.saml.SamlLogoutResult;
import com.revetsec.saml.SamlLogoutStatus;
import com.revetsec.saml.SamlRedirectBindingMessage;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import com.revetsec.saml.SamlServiceProvider;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ServletSamlTests {
    @Test void postBindingUsesOriginalBodyAndEveryContentTypeHeader() throws Exception {
        String xml = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol'/>";
        String body = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)
                + "&RelayState=handle";
        HttpServletRequest request = request("POST", null, List.of("application/x-www-form-urlencoded"),
                body.getBytes(StandardCharsets.US_ASCII));
        assertEquals("handle", assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                ServletSaml.postBindingResultFor(request)).getMessage().getRelayState().orElseThrow());
        HttpServletRequest duplicate = request("POST", null,
                List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"),
                body.getBytes(StandardCharsets.US_ASCII));
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                ServletSaml.postBindingResultFor(duplicate));
        HttpServletRequest wrongMedia = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, called, arguments) -> switch (called.getName()) {
                    case "getMethod" -> "POST";
                    case "getQueryString" -> null;
                    case "getHeaders" -> Collections.enumeration(List.of("text/plain"));
                    case "getInputStream" -> throw new AssertionError("invalid media must not read the body");
                    default -> null;
                });
        assertEquals(SamlPostBindingParseResult.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                        ServletSaml.postBindingResultFor(wrongMedia)).getReason());
        assertThrows(IllegalArgumentException.class, () -> ServletSaml.postBindingResultFor(
                request("GET", null, List.of("application/x-www-form-urlencoded"), new byte[0])));
    }

    @Test void redirectBindingPassesRawQueryWithoutParameterDecoding() {
        byte[] xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol'/>"
                .getBytes(StandardCharsets.UTF_8);
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(xml);
        deflater.finish();
        byte[] compressed = new byte[256];
        int length = deflater.deflate(compressed);
        deflater.end();
        String query = "SAMLRequest=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                Arrays.copyOf(compressed, length)), StandardCharsets.UTF_8)
                + "&RelayState=alpha%2Bbeta&SigAlg=" + URLEncoder.encode(
                        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", StandardCharsets.UTF_8)
                + "&Signature=" + URLEncoder.encode(Base64.getEncoder().encodeToString(new byte[64]),
                        StandardCharsets.UTF_8);
        SamlRedirectBindingMessage parsed = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                ServletSaml.redirectBindingResultFor(request("GET", query, List.of(), new byte[0])))
                .getMessage();
        assertEquals(SamlRedirectBindingMessage.Kind.REQUEST, parsed.getKind());
        assertEquals("alpha+beta", parsed.getRelayState().orElseThrow());
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                ServletSaml.redirectBindingResultFor(request("POST", query, List.of(), new byte[0])));
    }

    @Test void logoutPostKeepsRawInputAndLeavesAcsResponseOnly() throws Exception {
        for (String field : List.of("SAMLRequest", "SAMLResponse")) {
            byte[] body = (field + "=PGEvPg%3D%3D&RelayState=alpha%2Bbeta").getBytes(StandardCharsets.US_ASCII);
            SamlPostBindingMessage parsed = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                    ServletSaml.postLogoutBindingResultFor(request("POST", "tenant=one",
                            List.of("application/x-www-form-urlencoded"), body))).getMessage();
            assertEquals("SAMLRequest".equals(field) ? SamlPostBindingMessage.Kind.REQUEST
                    : SamlPostBindingMessage.Kind.RESPONSE, parsed.getKind());
            assertEquals("alpha+beta", parsed.getRelayState().orElseThrow());
            assertEquals(SamlPostBindingParseResult.Reason.CONTENT_TYPE, assertInstanceOf(
                    SamlPostBindingParseResult.Rejected.class, ServletSaml.postLogoutBindingResultFor(
                            request("POST", null, List.of("application/x-www-form-urlencoded",
                                    "application/x-www-form-urlencoded"), body))).getReason());
            assertEquals(SamlPostBindingParseResult.Reason.QUERY, assertInstanceOf(
                    SamlPostBindingParseResult.Rejected.class, ServletSaml.postLogoutBindingResultFor(
                            request("POST", "SAMLRequest=evil", List.of("application/x-www-form-urlencoded"), body))).getReason());
        }
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class, ServletSaml.postBindingResultFor(
                request("POST", null, List.of("application/x-www-form-urlencoded"),
                        "SAMLRequest=PGEvPg%3D%3D".getBytes(StandardCharsets.US_ASCII))));
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class, ServletSaml.postLogoutBindingResultFor(
                request("POST", null, List.of("application/x-www-form-urlencoded"), new byte[1_061_129])));
        assertThrows(IllegalArgumentException.class, () -> ServletSaml.postLogoutBindingResultFor(
                request("GET", null, List.of(), new byte[0])));
    }

    @Test void logoutFormsAndCallbacksUseCoreValidationAndReplayFence() throws Exception {
        SamlPostLogoutFixture fixture = new SamlPostLogoutFixture();
        SamlLogoutPostResult.Prepared begin = assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                fixture.sp.beginPostLogoutResult(fixture.idp, fixture.session));
        String nonce = "abcdefghijklmnopqrstuvwxyz012345";
        ResponseCapture outbound = new ResponseCapture();
        ServletSaml.writeLogoutPostForm(outbound.response(), begin, nonce);
        assertEquals(200, outbound.status);
        assertEquals("no-store", outbound.headers.get("Cache-Control"));
        assertEquals("no-referrer", outbound.headers.get("Referrer-Policy"));
        assertEquals(outbound.body.size(), outbound.contentLength);
        assertArrayEquals(begin.getPostForm().toHtml(nonce).getBytes(StandardCharsets.UTF_8), outbound.body.toByteArray());
        assertTrue(begin.getPostForm().getFields().containsKey("SAMLRequest"));
        assertFalse(begin.getPostForm().getFields().containsKey("SAMLResponse"));
        SamlPostBindingMessage response = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                ServletSaml.postLogoutBindingResultFor(request("POST", null, List.of("application/x-www-form-urlencoded"),
                        fixture.responseBody(begin.getPendingLogout())))).getMessage();
        var pending = fixture.pendingSource(begin.getPendingLogout());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                fixture.sp.completeLogoutResult(response, pending, fixture.idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                fixture.sp.completeLogoutResult(response, pending, fixture.idp));

        SamlPostBindingMessage request = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                ServletSaml.postLogoutBindingResultFor(request("POST", null, List.of("application/x-www-form-urlencoded"),
                        fixture.requestBody("_idp-logout")))).getMessage();
        var accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                fixture.sp.acceptLogoutRequestResult(request, fixture.idp));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                fixture.sp.acceptLogoutRequestResult(request, fixture.idp));
        SamlLogoutResponsePostResult.Prepared reply = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                fixture.sp.respondToPostLogoutRequestResult(accepted.getRequest(), fixture.idp, SamlLogoutStatus.SUCCESS));
        ResponseCapture answer = new ResponseCapture();
        ServletSaml.writeLogoutResponsePostForm(answer.response(), reply, null);
        assertEquals(200, answer.status);
        assertEquals(answer.body.size(), answer.contentLength);
        assertArrayEquals(reply.getPostForm().toHtml(null).getBytes(StandardCharsets.UTF_8), answer.body.toByteArray());
        assertTrue(reply.getPostForm().getFields().containsKey("SAMLResponse"));
        assertFalse(reply.getPostForm().getFields().containsKey("SAMLRequest"));
    }

    @Test void responsesKeepPreparedUriAndFormBytes() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 4)).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test")
                .connectionId("test")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .postSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(generator.generateKeyPair().getPublic())).build();
        SamlAuthenticationRequestResult.Prepared redirect = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));
        ResponseCapture capture = new ResponseCapture();
        ServletSaml.writeAuthenticationRedirect(capture.response(), redirect);
        assertEquals(302, capture.status);
        assertEquals(redirect.getRedirectUri().toASCIIString(), capture.headers.get("Location"));
        assertEquals("no-store", capture.headers.get("Cache-Control"));
        SamlAuthenticationRequestResult.PostPrepared prepared = assertInstanceOf(
                SamlAuthenticationRequestResult.PostPrepared.class, sp.beginPostAuthenticationResult(idp));
        ResponseCapture page = new ResponseCapture();
        ServletSaml.writePostForm(page.response(), prepared.getPostForm(), null);
        assertEquals(200, page.status);
        assertEquals(page.body.size(), page.contentLength);
        assertEquals("text/html; charset=UTF-8", page.headers.get("Content-Type"));
        assertTrue(page.body.toString(StandardCharsets.UTF_8).contains(
                "action=\"https://idp.example.test/sso\""));
    }

    private static @NonNull HttpServletRequest request(@NonNull String method, @Nullable String query,
            @NonNull List<@NonNull String> contentTypes, byte @NonNull [] body) {
        ByteArrayInputStream input = new ByteArrayInputStream(body);
        ServletInputStream stream = new ServletInputStream() {
            @Override public int read() { return input.read(); }
            @Override public boolean isFinished() { return input.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(@Nullable ReadListener listener) { }
        };
        InvocationHandler handler = (proxy, called, arguments) -> switch (called.getName()) {
            case "getMethod" -> method;
            case "getQueryString" -> query;
            case "getHeaders" -> Collections.enumeration(contentTypes);
            case "getInputStream" -> stream;
            default -> null;
        };
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, handler);
    }

    private static final class ResponseCapture {
        private final @NonNull Map<@NonNull String, @NonNull String> headers = new HashMap<>();
        private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream();
        private int status;
        private int contentLength;

        private @NonNull HttpServletResponse response() {
            ServletOutputStream stream = new ServletOutputStream() {
                @Override public void write(int value) { body.write(value); }
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(@Nullable WriteListener listener) { }
            };
            InvocationHandler handler = (proxy, called, arguments) -> {
                switch (called.getName()) {
                    case "setStatus" -> status = (Integer) arguments[0];
                    case "setHeader" -> headers.put((String) arguments[0], (String) arguments[1]);
                    case "setContentLength" -> contentLength = (Integer) arguments[0];
                    case "getOutputStream" -> { return stream; }
                    default -> { return null; }
                }
                return null;
            };
            return (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class}, handler);
        }
    }
}
