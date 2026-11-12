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
import com.revetsec.json.JsonObject;
import com.revetsec.saml.*;
import com.revetsec.servlet.jakarta.ServletSaml;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.XMLConstants;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;
import java.util.function.Predicate;
import java.util.zip.Deflater;
import java.util.zip.InflaterInputStream;

/** Private synthetic signed-XML IdPs/current account and fault controls, never a deployment component. */
@ThreadSafe
final class SamlSpFixture {
    private static final @NonNull String P="urn:oasis:names:tc:SAML:2.0:protocol",A="urn:oasis:names:tc:SAML:2.0:assertion",SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final @NonNull String PERSISTENT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private final @NonNull MutableClock clock=new MutableClock();
    private final @NonNull AtomicLong nanos=new AtomicLong(),sequence=new AtomicLong(),generation=new AtomicLong(1);
    private final @NonNull AtomicInteger lookups=new AtomicInteger(),authorizations=new AtomicInteger(),saves=new AtomicInteger(),consumes=new AtomicInteger(),verifiedRequests=new AtomicInteger(),marksA=new AtomicInteger(),marksB=new AtomicInteger();
    private final @NonNull AtomicBoolean noReferrer=new AtomicBoolean();
    private final @NonNull AtomicBoolean enabled=new AtomicBoolean(true),admitted=new AtomicBoolean(true),injectedInterrupt=new AtomicBoolean(),interruptObserved=new AtomicBoolean(),interruptSet=new AtomicBoolean(),interruptSafe=new AtomicBoolean();
    private final @NonNull AtomicReference<@NonNull String> saveMode=new AtomicReference<>("normal"),consumeMode=new AtomicReference<>("normal"),lookupMode=new AtomicReference<>("normal");
    private final @NonNull AtomicReference<@Nullable Block> block=new AtomicReference<>();
    private final @NonNull Map<@NonNull String,@NonNull KeyPair> keys=Map.of("idp-a",key(),"idp-b",key());
    private final @NonNull KeyPair spKey=key(),other=key();
    private final @NonNull EncryptionKeys encryption=encryptionKeys();
    private final @NonNull AtomicInteger encryptedMinted=new AtomicInteger(),roundtrips=new AtomicInteger(),innerVerified=new AtomicInteger(),outerVerified=new AtomicInteger();
    private final ServletSamlSpRecipe.@NonNull Configuration config;
    private final @NonNull ServletSamlSpRecipe recipe;
    SamlSpFixture(){
        verifyOrigin(SamlServiceProvider.class,"CORE");verifyOrigin(ServletSaml.class,"ADAPTER");
        URI origin=URI.create(System.getenv().getOrDefault("REVETSEC_SAML_ORIGIN","https://sp.example.test"));
        URI a=URI.create(System.getenv().getOrDefault("REVETSEC_SAML_IDP_A","https://idpa.example.test")),b=URI.create(System.getenv().getOrDefault("REVETSEC_SAML_IDP_B","https://idpb.example.test"));
        this.config=new ServletSamlSpRecipe.Configuration(origin,origin.resolve("/saml/entity").toString(),List.of(connection("idp-a",a),connection("idp-b",b)));
        SamlReplayCache backingReplay=InMemorySamlReplayCache.fromConnectionLimits(this.clock,Map.of("idp-a",64,"idp-b",64));
        SamlReplayCache replay=new SamlReplayCache(){
            @Override public @NonNull MarkResult markIfAbsent(@NonNull String k,@NonNull Instant end,@NonNull Duration remaining){return MarkResult.UNAVAILABLE;}
            @Override public @NonNull MarkResult markIfAbsent(@NonNull String connection,@NonNull String k,@NonNull Instant end,@NonNull Duration remaining){pause("replay");MarkResult result=backingReplay.markIfAbsent(connection,k,end,remaining);if(result==MarkResult.MARKED)(connection.equals("idp-a")?marksA:marksB).incrementAndGet();return result;}
        };
        SamlServiceProvider sp=ServletSamlSpRecipe.provider(this.config,this.spKey.getPrivate(),List.of(this.encryption.credential()),replay,this.clock,"/saml/logout-return/");
        Map<String,SamlServiceProvider> receivers=new LinkedHashMap<>();for(var c:this.config.connections())receivers.put(c.id(),ServletSamlSpRecipe.provider(this.config,this.spKey.getPrivate(),List.of(this.encryption.credential()),replay,this.clock,"/saml/idp-logout/"+c.id()+'/'));
        byte[] secret=new byte[32];new SecureRandom().nextBytes(secret);StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",Base64.getEncoder().encodeToString(secret))).clock(this.clock).maximumSealedLength(8192).build();
        PendingSamlAuthenticationStore backing=InMemoryPendingSamlAuthenticationStore.fromLimit(this.clock,256);
        PendingSamlAuthenticationStore pending=new PendingSamlAuthenticationStore(){
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String binding,@NonNull String relay,@NonNull String opaque,@NonNull Instant end,@NonNull Duration remaining){String mode=saveMode.getAndSet("normal");if(mode.equals("unavailable"))return SamlPendingSaveResult.UNAVAILABLE;SamlPendingSaveResult result=backing.save(binding,relay,opaque,end,remaining);if(result==SamlPendingSaveResult.SAVED)saves.incrementAndGet();return result==SamlPendingSaveResult.SAVED&&mode.equals("unknown")?SamlPendingSaveResult.INDETERMINATE:result;}
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String binding,@NonNull String relay,@NonNull Duration remaining){SamlPendingConsumeResult result=backing.consume(binding,relay,remaining);if(result instanceof SamlPendingConsumeResult.Consumed)consumes.incrementAndGet();return consumeMode.getAndSet("normal").equals("unknown")?SamlPendingConsumeResult.Indeterminate.INSTANCE:result;}
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String binding,@NonNull String relay,@NonNull Predicate<@NonNull String> predicate,@NonNull Duration remaining){SamlPendingConsumeResult result=backing.consumeIfMatches(binding,relay,predicate,remaining);if(result instanceof SamlPendingConsumeResult.Consumed)consumes.incrementAndGet();return consumeMode.getAndSet("normal").equals("unknown")?SamlPendingConsumeResult.Indeterminate.INSTANCE:result;}
        };
        var accounts=new ServletSamlSpRecipe.Accounts(){
            @Override public @NonNull Optional<ServletSamlSpRecipe.@NonNull Account> findAndAuthorizeLogin(@NonNull String connection,@NonNull String entity,@NonNull String stable,@NonNull Duration remaining){lookups.incrementAndGet();pause("account");switch(lookupMode.getAndSet("normal")){case "expire"->clock.advance(120);case "late"->nanos.addAndGet(Duration.ofSeconds(9).toNanos());case "interrupt"->{injectedInterrupt.set(true);Thread.currentThread().interrupt();}default->{}}
                boolean trusted=config.connections().stream().anyMatch(c->c.id().equals(connection)&&c.entity().equals(entity));
                return trusted&&enabled.get()&&stable.equals("saml-nameid-v1:"+PERSISTENT.length()+':'+PERSISTENT+"11:fixture-sub"+entity.length()+':'+entity+config.entity().length()+':'+config.entity())?Optional.of(new ServletSamlSpRecipe.Account("alice","tenant",generation.get())):Optional.empty();}
            @Override public boolean authorize(ServletSamlSpRecipe.@NonNull Account account,@NonNull String tenant,@NonNull String owner,@NonNull Duration remaining){authorizations.incrementAndGet();pause("authorize");return enabled.get()&&account.generation()==generation.get()&&account.id().equals(owner)&&account.tenant().equals(tenant);}
        };
        this.recipe=new ServletSamlSpRecipe(this.config,sp,receivers,sealer,pending,accounts,(peer,remaining)->this.admitted.get(),this.clock,()->System.nanoTime()+this.nanos.get());
    }
    private ServletSamlSpRecipe.@NonNull Connection connection(@NonNull String id,@NonNull URI origin){return new ServletSamlSpRecipe.Connection(id,origin.resolve("/idp/entity").toString(),origin.resolve("/idp/sso"),origin.resolve("/idp/sso"),origin.resolve("/idp/slo"),origin.resolve("/idp/slo"),List.of(this.keys.get(id).getPublic()));}
    @NonNull String idpReferrerPolicy(){return this.noReferrer.get()?"no-referrer":"strict-origin";}
    @NonNull ServletSamlSpRecipe recipe(){return this.recipe;}
    boolean takeInjectedInterrupt(){return this.injectedInterrupt.getAndSet(false);}
    void recordCancellation(boolean set,boolean safe){this.interruptObserved.set(true);this.interruptSet.set(set);this.interruptSafe.set(safe);}
    @NonNull JsonObject control(@NonNull String command){
        switch(command){
            case "state"->{}case "idp-no-referrer"->this.noReferrer.set(true);case "deny"->this.enabled.set(false);case "allow"->this.enabled.set(true);case "generation"->this.generation.incrementAndGet();case "admission-deny"->this.admitted.set(false);case "admission-allow"->this.admitted.set(true);
            case "advance-pending"->this.clock.advance(301);case "advance-session"->this.clock.advance(1801);case "rollback"->this.clock.value.set(Instant.parse("2026-11-05T00:00:00Z"));case "recover-clock"->this.clock.recover();
            case "save-unavailable"->this.saveMode.set("unavailable");case "save-unknown"->this.saveMode.set("unknown");case "consume-unknown"->this.consumeMode.set("unknown");case "lookup-expire"->this.lookupMode.set("expire");case "lookup-late"->this.lookupMode.set("late");case "lookup-interrupt"->this.lookupMode.set("interrupt");
            case "block-account"->this.block.set(new Block("account"));case "block-authorize"->this.block.set(new Block("authorize"));case "block-replay"->this.block.set(new Block("replay"));case "release"->{Block value=this.block.getAndSet(null);if(value!=null)value.release.countDown();}
            default->throw new IllegalArgumentException("Unknown fixture command");
        }
        Block paused=this.block.get();return JsonObject.builder().put("origin_verified",true).put("host",this.recipe.stateSnapshot()).put("lookups",this.lookups.longValue()).put("authorizations",this.authorizations.longValue()).put("saved",this.saves.longValue()).put("consumed",this.consumes.longValue())
                .put("encrypted_minted",this.encryptedMinted.longValue()).put("jca_roundtrips",this.roundtrips.longValue()).put("jca_inner_verified",this.innerVerified.longValue()).put("jca_outer_verified",this.outerVerified.longValue()).put("signed_requests_verified",this.verifiedRequests.longValue()).put("marks_a",this.marksA.longValue()).put("marks_b",this.marksB.longValue()).put("blocked",paused!=null&&paused.entered.getCount()==0).put("blocked_count",paused==null?0L:paused.active.longValue())
                .put("interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptSet.get()).put("handler_cancel_no_publication",this.interruptSafe.get()).build();
    }
    @NonNull JsonObject mint(@NonNull String connection,@NonNull String mode,@NonNull String method,@NonNull String raw)throws Exception{
        Map<String,String> values=form(raw);String field=values.containsKey("SAMLRequest")?"SAMLRequest":"SAMLResponse";byte[] decoded=Base64.getDecoder().decode(required(values,field));
        if(method.equals("GET")){
            String input=field+'='+enc(required(values,field));if(values.containsKey("RelayState"))input+="&RelayState="+enc(values.get("RelayState"));input+="&SigAlg="+enc(required(values,"SigAlg"));
            if(!required(values,"SigAlg").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))throw new IllegalArgumentException("Fixture signature algorithm");
            Signature signature=Signature.getInstance("SHA256withRSA");signature.initVerify(this.spKey.getPublic());signature.update(input.getBytes(StandardCharsets.US_ASCII));if(!signature.verify(Base64.getDecoder().decode(required(values,"Signature"))))throw new IllegalArgumentException("Fixture SP signature rejected");
            try(var compressed=new InflaterInputStream(new ByteArrayInputStream(decoded),new java.util.zip.Inflater(true))){decoded=compressed.readNBytes(65_537);if(decoded.length>65_536)throw new IllegalArgumentException("Fixture inflated bound");}
        }
        Document request=parse(decoded);Element root=request.getDocumentElement();if(!method.equals("GET"))verify(request,this.spKey.getPublic());this.verifiedRequests.incrementAndGet();
        String requestId=root.getAttribute("ID"),relay=required(values,"RelayState");if(requestId.isEmpty())throw new IllegalArgumentException("Fixture missing request ID");
        boolean login=root.getLocalName().equals("AuthnRequest");String destination=login?this.config.origin().resolve("/saml/acs").toString():this.config.origin().resolve("/saml/logout-return/"+(method.equals("GET")?"redirect":"post")).toString();
        byte[] xml=login?response(connection,mode,requestId,destination):logoutResponse(connection,mode,requestId,destination);
        if(!login&&method.equals("GET")){Document d=parse(xml);var signatures=d.getElementsByTagNameNS(XMLSignature.XMLNS,"Signature");if(signatures.getLength()>0)signatures.item(0).getParentNode().removeChild(signatures.item(0));xml=serialize(d);}
        String target=login?"POST":method;
        return JsonObject.builder().put("action",destination).put("method",target).put("body",target.equals("POST")?body("SAMLResponse",xml,relay):redirectQuery("SAMLResponse",xml,relay,(mode.equals("wrong-key")?this.other:this.keys.get(connection)).getPrivate())).put("request_id_sha256",sha(requestId)).put("xml_sha256",sha(xml)).put("mutation",mode).build();
    }
    @NonNull JsonObject idpLogout(@NonNull String connection,@NonNull String mode,boolean post)throws Exception{
        var c=connectionFor(connection);String name=mode.equals("wrong-name")?"other-sub":"fixture-sub",qualifier=mode.equals("wrong-qualifier")?"https://wrong.invalid/entity":c.entity();String index=mode.equals("wrong-index")?"other-session":"session-"+connection;
        String destination=this.config.origin().resolve("/saml/idp-logout/"+connection+(post?"/post":"/redirect")).toString();
        String xml="<p:LogoutRequest xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_idp-logout-"+this.sequence.incrementAndGet()+"' Version='2.0' IssueInstant='"+this.clock.instant()+"' Destination='"+destination+"'><a:Issuer>"+c.entity()+"</a:Issuer>"+nameId(name,qualifier,this.config.entity())+(mode.equals("all-indexes")?"":"<p:SessionIndex>"+index+"</p:SessionIndex>")+"</p:LogoutRequest>";
        if(mode.equals("wrong-format"))xml=xml.replace(PERSISTENT,"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        if(mode.equals("wrong-sp-qualifier"))xml=xml.replace("SPNameQualifier='"+this.config.entity()+"'","SPNameQualifier='https://wrong.invalid/sp'");
        if(mode.equals("wrong-sp-provided"))xml=xml.replace("<a:NameID ","<a:NameID SPProvidedID='other' ");
        byte[] bytes=xml.getBytes(StandardCharsets.UTF_8);if(post)bytes=sign(bytes,"LogoutRequest",mode.equals("wrong-key")?this.other:this.keys.get(connection));
        return JsonObject.builder().put("action",destination).put("method",post?"POST":"GET").put("body",post?body("SAMLRequest",bytes,"fixture-relay"):redirectQuery("SAMLRequest",bytes,"fixture-relay",(mode.equals("wrong-key")?this.other:this.keys.get(connection)).getPrivate())).build();
    }
    private byte @NonNull [] response(@NonNull String connection,@NonNull String mode,@NonNull String requestId,@NonNull String destination)throws Exception{
        var c=connectionFor(connection);Instant now=this.clock.instant();long id=this.sequence.incrementAndGet();String issuer=mode.equals("wrong-issuer")?"https://attacker.invalid/entity":c.entity();String target=mode.equals("wrong-destination")?"https://attacker.invalid/acs":destination;
        String correlated=mode.equals("wrong-request")?"_different-request":requestId;String subject=mode.equals("unmapped")?"not-mapped":"fixture-sub";String expiry=(mode.equals("expired")?now:now.plusSeconds(120)).toString();
        String assertion="<a:Assertion ID='_assertion-"+id+"' Version='2.0' IssueInstant='"+now+"'><a:Issuer>"+issuer+"</a:Issuer><a:Subject>"+nameId(subject,c.entity(),this.config.entity())
                +"<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData Recipient='"+(mode.equals("wrong-recipient")?"https://wrong.invalid/acs":destination)+"' NotOnOrAfter='"+expiry+"' InResponseTo='"+correlated+"'/></a:SubjectConfirmation></a:Subject>"
                +"<a:Conditions NotBefore='"+now+"' NotOnOrAfter='"+expiry+"'><a:AudienceRestriction><a:Audience>"+(mode.equals("wrong-audience")?"https://wrong.invalid/sp":this.config.entity())+"</a:Audience></a:AudienceRestriction></a:Conditions>"
                +"<a:AuthnStatement AuthnInstant='"+(mode.equals("future-authn")?now.plusSeconds(1):mode.equals("prior-request-authn")?now.minusSeconds(1):mode.equals("old-authn")?now.minusSeconds(301):now)+"' SessionIndex='session-"+connection+"' SessionNotOnOrAfter='"+now.plusSeconds(1800)+"'><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion>";
        String xml="<p:Response xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_response-"+id+"' Version='2.0' IssueInstant='"+now+"' Destination='"+target+"' InResponseTo='"+correlated+"'><a:Issuer>"+issuer+"</a:Issuer><p:Status><p:StatusCode Value='"+SUCCESS+"'/></p:Status>"+assertion+"</p:Response>";
        return encrypted(xml, connection, mode);
    }
    private byte @NonNull [] encrypted(@NonNull String xml,@NonNull String connection,@NonNull String mode)throws Exception {
        Document original=parse(xml.getBytes(StandardCharsets.UTF_8));
        Element assertion=(Element)original.getElementsByTagNameNS(A,"Assertion").item(0);
        Document standalone=parse(elementBytes(assertion));
        byte[] plain=elementBytes(standalone.getDocumentElement());
        if(!mode.equals("missing-inner-signature"))plain=sign(plain,"Assertion",mode.equals("inner-wrong-key")?this.other:this.keys.get(connection));
        if(mode.equals("inner-tamper"))plain=new String(plain,StandardCharsets.UTF_8).replace("fixture-sub","changed-sub").getBytes(StandardCharsets.UTF_8);
        boolean validInner=signatureValid(parse(plain),this.keys.get(connection).getPublic());
        if(validInner)this.innerVerified.incrementAndGet();
        if(validInner!=!Set.of("missing-inner-signature","inner-wrong-key","inner-tamper").contains(mode))throw new IllegalStateException("Fixture inner signature oracle");
        KeyGenerator generator=KeyGenerator.getInstance("AES");generator.init(256);byte[] cek=generator.generateKey().getEncoded(),iv=new byte[12];new SecureRandom().nextBytes(iv);
        Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");aes.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(cek,"AES"),new GCMParameterSpec(128,iv));byte[] ciphertext=aes.doFinal(plain),wire=new byte[iv.length+ciphertext.length];System.arraycopy(iv,0,wire,0,iv.length);System.arraycopy(ciphertext,0,wire,iv.length,ciphertext.length);
        Cipher rsa=Cipher.getInstance("RSA/ECB/OAEPPadding");OAEPParameterSpec parameters=new OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.ENCRYPT_MODE,mode.equals("wrong-recipient-key")?this.other.getPublic():this.encryption.credential().getCertificate().getPublicKey(),parameters);byte[] wrapped=rsa.doFinal(cek);
        if(mode.equals("wrong-recipient-key")){
            boolean refused=false;try{rsa.init(Cipher.DECRYPT_MODE,this.encryption.privateKey(),parameters);rsa.doFinal(wrapped);}catch(GeneralSecurityException expected){refused=true;}if(!refused)throw new IllegalStateException("Fixture recipient oracle");
        }else{
            rsa.init(Cipher.DECRYPT_MODE,this.encryption.privateKey(),parameters);byte[] opened=rsa.doFinal(wrapped);Cipher oracle=Cipher.getInstance("AES/GCM/NoPadding");oracle.init(Cipher.DECRYPT_MODE,new SecretKeySpec(opened,"AES"),new GCMParameterSpec(128,iv));if(!MessageDigest.isEqual(plain,oracle.doFinal(ciphertext)))throw new IllegalStateException("Fixture encryption roundtrip");this.roundtrips.incrementAndGet();
        }
        if(mode.equals("bad-tag"))wire[wire.length-1]^=1;
        if(mode.equals("bad-ciphertext"))wire[12]^=1;
        if(Set.of("bad-tag","bad-ciphertext").contains(mode)){
            Cipher oracle=Cipher.getInstance("AES/GCM/NoPadding");oracle.init(Cipher.DECRYPT_MODE,new SecretKeySpec(cek,"AES"),new GCMParameterSpec(128,iv));boolean refused=false;try{oracle.doFinal(Arrays.copyOfRange(wire,12,wire.length));}catch(GeneralSecurityException expected){refused=true;}if(!refused)throw new IllegalStateException("Fixture GCM mutation oracle");
        }
        String dataAlgorithm=mode.equals("unsupported-data-algorithm")?"urn:fixture:unsupported-cipher":"http://www.w3.org/2009/xmlenc11#aes256-gcm";
        String keyAlgorithm=mode.equals("unsupported-key-algorithm")?"http://www.w3.org/2001/04/xmlenc#rsa-1_5":"http://www.w3.org/2009/xmlenc11#rsa-oaep";
        String encrypted="<a:EncryptedAssertion xmlns:a='"+A+"' xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' xmlns:xenc11='http://www.w3.org/2009/xmlenc11#' xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><xenc:EncryptedData Type='http://www.w3.org/2001/04/xmlenc#Element'><xenc:EncryptionMethod Algorithm='"+dataAlgorithm+"'/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm='"+keyAlgorithm+"'><ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/><xenc11:MGF Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha256'/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>"+Base64.getEncoder().encodeToString(wrapped)+"</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>"+Base64.getEncoder().encodeToString(wire)+"</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></a:EncryptedAssertion>";
        assertion.getParentNode().replaceChild(original.importNode(parse(encrypted.getBytes(StandardCharsets.UTF_8)).getDocumentElement(),true),assertion);
        byte[] response=serialize(original);
        if(!mode.equals("missing-outer-signature"))response=sign(response,"Response",mode.equals("outer-wrong-key")?this.other:this.keys.get(connection));
        if(mode.equals("outer-tamper")){
            Document changed=parse(response);Element value=(Element)changed.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","CipherValue").item(1);String text=value.getTextContent();value.setTextContent((text.charAt(0)=='A'?'B':'A')+text.substring(1));response=serialize(changed);
        }
        boolean validOuter=signatureValid(parse(response),this.keys.get(connection).getPublic());if(validOuter)this.outerVerified.incrementAndGet();
        if(validOuter!=!Set.of("missing-outer-signature","outer-wrong-key","outer-tamper").contains(mode))throw new IllegalStateException("Fixture outer signature oracle");
        this.encryptedMinted.incrementAndGet();return response;
    }
    private static byte @NonNull [] elementBytes(@NonNull Element element)throws Exception {
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);Document copy=f.newDocumentBuilder().newDocument();copy.appendChild(copy.importNode(element,true));return serialize(copy);
    }
    private static boolean signatureValid(@NonNull Document document,@NonNull PublicKey key) {
        try{verify(document,key);return true;}catch(Exception rejected){return false;}
    }
    private static @NonNull EncryptionKeys encryptionKeys() {
        try{
            String key=fixtureText("REVETSEC_SAML_ENCRYPTION_KEY"),certificate=fixtureText("REVETSEC_SAML_ENCRYPTION_CERTIFICATE");
            SamlCredential credential=SamlCredential.fromPem(key,certificate);
            String body=key.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replaceAll("\\s","");
            PrivateKey parsed=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            return new EncryptionKeys(credential,parsed);
        }catch(Exception rejected){throw new IllegalStateException("Fixture encryption credential unavailable");}
    }
    private static @NonNull String fixtureText(@NonNull String name)throws IOException {
        Path path=Path.of(Objects.requireNonNull(System.getenv(name)));try(var input=Files.newInputStream(path)){byte[] bytes=input.readNBytes(16_385);if(bytes.length==0||bytes.length>16_384)throw new IOException("Fixture key bound");return new String(bytes,StandardCharsets.US_ASCII);}
    }
    private record EncryptionKeys(@NonNull SamlCredential credential,@NonNull PrivateKey privateKey) {
        @Override public @NonNull String toString(){return "EncryptionKeys{<redacted>}";}
    }
    private byte @NonNull [] logoutResponse(@NonNull String connection,@NonNull String mode,@NonNull String requestId,@NonNull String destination)throws Exception{
        String xml="<p:LogoutResponse xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_logout-response-"+this.sequence.incrementAndGet()+"' Version='2.0' IssueInstant='"+this.clock.instant()+"' Destination='"+destination+"' InResponseTo='"+(mode.equals("wrong-request")?"_different":requestId)+"'><a:Issuer>"+connectionFor(connection).entity()+"</a:Issuer><p:Status><p:StatusCode Value='"+(mode.equals("non-success")?"urn:oasis:names:tc:SAML:2.0:status:Responder":SUCCESS)+"'/></p:Status></p:LogoutResponse>";
        return sign(xml.getBytes(StandardCharsets.UTF_8),"LogoutResponse",mode.equals("wrong-key")?this.other:this.keys.get(connection));
    }
    private ServletSamlSpRecipe.@NonNull Connection connectionFor(@NonNull String id){return this.config.connections().stream().filter(c->c.id().equals(id)).findFirst().orElseThrow();}
    private static @NonNull String nameId(@NonNull String value,@NonNull String qualifier,@NonNull String sp){return "<a:NameID Format='"+PERSISTENT+"' NameQualifier='"+qualifier+"' SPNameQualifier='"+sp+"'>"+value+"</a:NameID>";}
    static @NonNull Map<@NonNull String,@NonNull String> form(@NonNull String raw){if(raw.length()>131_072)throw new IllegalArgumentException("Fixture bound");Map<String,String> values=new LinkedHashMap<>();for(String item:raw.split("&",-1)){int split=item.indexOf('=');if(split<=0)throw new IllegalArgumentException("Fixture form");String name=URLDecoder.decode(item.substring(0,split),StandardCharsets.UTF_8),value=URLDecoder.decode(item.substring(split+1),StandardCharsets.UTF_8);if(values.size()>=8||values.putIfAbsent(name,value)!=null)throw new IllegalArgumentException("Fixture duplicate");}return values;}
    private static @NonNull String required(@NonNull Map<@NonNull String,@NonNull String> values,@NonNull String key){String found=values.get(key);if(found==null)throw new IllegalArgumentException("Fixture missing field");return found;}
    private static @NonNull String enc(@NonNull String value){return URLEncoder.encode(value,StandardCharsets.UTF_8).replace("+","%20");}
    static @NonNull String body(@NonNull String field,byte @NonNull [] xml,@NonNull String relay){return field+'='+enc(Base64.getEncoder().encodeToString(xml))+"&RelayState="+enc(relay);}
    private static @NonNull String redirectQuery(@NonNull String field,byte @NonNull [] xml,@NonNull String relay,@NonNull PrivateKey key)throws Exception{Deflater deflater=new Deflater(Deflater.DEFAULT_COMPRESSION,true);deflater.setInput(xml);deflater.finish();ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] chunk=new byte[2048];while(!deflater.finished()){int count=deflater.deflate(chunk);out.write(chunk,0,count);}deflater.end();String input=field+'='+enc(Base64.getEncoder().encodeToString(out.toByteArray()))+"&RelayState="+enc(relay)+"&SigAlg="+enc("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key);signature.update(input.getBytes(StandardCharsets.US_ASCII));return input+"&Signature="+enc(Base64.getEncoder().encodeToString(signature.sign()));}
    private static byte @NonNull [] sign(byte @NonNull [] xml,@NonNull String targetName,@NonNull KeyPair key)throws Exception{
        Document d=parse(xml);Element target=(Element)d.getElementsByTagNameNS(targetName.equals("Assertion")?A:P,targetName).item(0);target.setIdAttribute("ID",true);XMLSignatureFactory f=XMLSignatureFactory.getInstance("DOM");
        Reference reference=f.newReference('#'+target.getAttribute("ID"),f.newDigestMethod(DigestMethod.SHA256,null),List.of(f.newTransform(Transform.ENVELOPED,(TransformParameterSpec)null),f.newTransform(CanonicalizationMethod.EXCLUSIVE,(TransformParameterSpec)null)),null,null);
        SignedInfo info=f.newSignedInfo(f.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec)null),f.newSignatureMethod(SignatureMethod.RSA_SHA256,null),List.of(reference));
        DOMSignContext context=new DOMSignContext(key.getPrivate(),target,target.getFirstChild().getNextSibling());context.setDefaultNamespacePrefix("ds");f.newXMLSignature(info,null).sign(context);return serialize(d);
    }
    private static void verify(@NonNull Document d,@NonNull PublicKey key)throws Exception{Element root=d.getDocumentElement();root.setIdAttribute("ID",true);Element sig=(Element)d.getElementsByTagNameNS(XMLSignature.XMLNS,"Signature").item(0);if(sig==null||sig.getParentNode()!=root)throw new IllegalArgumentException("Fixture SP root signature missing");DOMValidateContext context=new DOMValidateContext(key,sig);context.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);if(!XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context))throw new IllegalArgumentException("Fixture SP signature invalid");}
    private static @NonNull Document parse(byte @NonNull [] xml)throws Exception{DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));}
    private static byte @NonNull [] serialize(@NonNull Document d)throws Exception{TransformerFactory f=TransformerFactory.newInstance();f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");ByteArrayOutputStream out=new ByteArrayOutputStream();f.newTransformer().transform(new DOMSource(d),new StreamResult(out));return out.toByteArray();}
    private static @NonNull KeyPair key(){try{KeyPairGenerator f=KeyPairGenerator.getInstance("RSA");f.initialize(2048);return f.generateKeyPair();}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Fixture crypto unavailable");}}
    private void pause(@NonNull String stage){Block value=this.block.get();if(value!=null&&value.stage.equals(stage)){value.active.incrementAndGet();value.entered.countDown();try{if(!value.release.await(4,TimeUnit.SECONDS))throw new IllegalStateException("Fixture latch timed out");}catch(InterruptedException cancelled){Thread.currentThread().interrupt();throw new IllegalStateException("Fixture cancelled");}finally{value.active.decrementAndGet();}}}
    private static final class Block{final @NonNull String stage;final @NonNull CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);final @NonNull AtomicInteger active=new AtomicInteger();Block(@NonNull String stage){this.stage=stage;}}
    private static final class MutableClock extends Clock{final @NonNull AtomicReference<@NonNull Instant> value=new AtomicReference<>(Instant.parse("2026-11-05T12:00:00Z"));final @NonNull AtomicReference<@NonNull Instant> high=new AtomicReference<>(this.value.get());void advance(long seconds){this.value.updateAndGet(now->now.plusSeconds(seconds));this.high.accumulateAndGet(this.value.get(),(a,b)->a.isAfter(b)?a:b);}void recover(){this.value.set(this.high.get().plusSeconds(1));}@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException("Fixture UTC only");return this;}@Override public @NonNull Instant instant(){return this.value.get();}}
    private static @NonNull String sha(@NonNull String text){return sha(text.getBytes(StandardCharsets.UTF_8));}
    private static @NonNull String sha(byte @NonNull [] value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}catch(GeneralSecurityException unavailable){throw new IllegalStateException("Digest unavailable");}}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind){try{Path expected=Path.of(Objects.requireNonNull(System.getenv("REVETSEC_SAML_"+kind+"_JAR"))).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();String digest=sha(Files.readAllBytes(actual));if(!actual.equals(expected)||!digest.equals(System.getenv("REVETSEC_SAML_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact origin mismatch");}catch(Exception unavailable){throw new IllegalStateException("Selected artifact origin mismatch");}}
    @Override public @NonNull String toString(){return "SamlSpFixture{<redacted>}";}
}
