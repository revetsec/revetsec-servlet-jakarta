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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.saml.PendingSamlLogoutSource;
import com.revetsec.saml.InMemorySamlReplayCache;
import com.revetsec.saml.PendingSamlLogout;
import com.revetsec.saml.SamlAuthenticationResult;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlServiceProvider;
import com.revetsec.saml.SamlSessionReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;


/** Builds checked session references through core's public authentication API. */
final class SamlFixture {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private final KeyPair idpKey;
    private final Clock clock;
    final SamlServiceProvider sp;
    final SamlIdentityProvider idp;
    final SamlSessionReference session;

    SamlFixture() throws Exception {
        clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        idpKey = generator.generateKeyPair();
        KeyPair spKey = generator.generateKeyPair();
        sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .postSingleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(spKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32)).clock(clock).build();
        idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("test")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .postSingleLogoutService(URI.create("https://idp.example.test/logout"))
                .signingKeys(List.of(idpKey.getPublic())).allowUnsolicitedResponses(true).build();
        String assertion = "<p:Response xmlns:p='" + PROTOCOL + "' xmlns:a='" + ASSERTION
                + "' ID='_login-response' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/acs'><a:Issuer>https://idp.example.test/saml</a:Issuer>"
                + "<p:Status><p:StatusCode Value='" + SUCCESS + "'/></p:Status>"
                + "<a:Assertion ID='_login-assertion' Version='2.0' IssueInstant='2026-10-09T00:01:00Z'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer><a:Subject><a:NameID>alice</a:NameID>"
                + "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
                + "<a:SubjectConfirmationData Recipient='https://sp.example.test/acs' "
                + "NotOnOrAfter='2026-10-09T00:06:00Z'/></a:SubjectConfirmation></a:Subject>"
                + "<a:Conditions NotBefore='2026-10-09T00:01:00Z' NotOnOrAfter='2026-10-09T00:06:00Z'>"
                + "<a:AudienceRestriction><a:Audience>https://sp.example.test/saml</a:Audience>"
                + "</a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant='2026-10-09T00:01:00Z' "
                + "SessionIndex='session-123'><a:AuthnContext><a:AuthnContextClassRef>"
                + "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                + "</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion></p:Response>";
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form("SAMLResponse", sign(assertion, "Assertion"), null),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        session = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeUnsolicitedAuthenticationResult(message, idp))
                .getAuthentication().getSessionReference();
    }

    PendingSamlLogoutSource pendingSource(PendingSamlLogout pending) {
        byte[] secret = new byte[32];
        new java.security.SecureRandom().nextBytes(secret);
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("test",
                Base64.getEncoder().encodeToString(secret))).clock(clock).build();
        return PendingSamlLogoutSource.fromSealedForm(pending.toSealedForm(sealer, "logout"), sealer, "logout");
    }

    byte [] requestBody(String requestId) throws Exception {
        String xml = "<p:LogoutRequest xmlns:p='" + PROTOCOL + "' xmlns:a='" + ASSERTION
                + "' ID='" + requestId + "' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer><a:NameID>alice</a:NameID>"
                + "<p:SessionIndex>session-123</p:SessionIndex></p:LogoutRequest>";
        return form("SAMLRequest", sign(xml, "LogoutRequest"), "opaque+relay");
    }

    byte [] responseBody(PendingSamlLogout pending) throws Exception {
        String xml = "<p:LogoutResponse xmlns:p='" + PROTOCOL + "' xmlns:a='" + ASSERTION
                + "' ID='_logout-response' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout' InResponseTo='" + pending.getRequestId() + "'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer><p:Status><p:StatusCode Value='"
                + SUCCESS + "'/></p:Status></p:LogoutResponse>";
        return form("SAMLResponse", sign(xml, "LogoutResponse"), pending.getRelayStateHandle());
    }

    private byte [] sign(String xml, String localName) throws Exception {
        DocumentBuilderFactory parser = DocumentBuilderFactory.newInstance();
        parser.setNamespaceAware(true);
        Document document = parser.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element target = (Element) document.getElementsByTagNameNS(
                "Assertion".equals(localName) ? ASSERTION : PROTOCOL, localName).item(0);
        target.setIdAttribute("ID", true);
        XMLSignatureFactory signatures = XMLSignatureFactory.getInstance("DOM");
        var reference = signatures.newReference("#" + target.getAttribute("ID"),
                signatures.newDigestMethod(DigestMethod.SHA256, null),
                List.of(signatures.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        signatures.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                null, null);
        var information = signatures.newSignedInfo(signatures.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                signatures.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(idpKey.getPrivate(), target, target.getFirstChild().getNextSibling());
        context.setDefaultNamespacePrefix("ds");
        signatures.newXMLSignature(information, null).sign(context);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    private static <T> T assertInstanceOf(Class<T> type, Object result) {
        if (!type.isInstance(result)) throw new IllegalStateException("Fixture core operation rejected");
        return type.cast(result);
    }

    private static byte [] form(String field, byte [] xml, String relay) {
        String body = field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(xml), StandardCharsets.UTF_8);
        if (relay != null) body += "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8);
        return body.getBytes(StandardCharsets.US_ASCII);
    }
}
