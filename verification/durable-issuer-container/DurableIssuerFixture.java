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

import com.revetsec.BrowserBinding;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.server.*;
import com.revetsec.servlet.jakarta.ServletOAuthAuthorizationServer;
import example.pending.PostgresqlIssuerStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Synthetic account/time/fault controls around actual reference-store transactions. Never deploy. */
@ThreadSafe
public final class DurableIssuerFixture {
    static final @NonNull String ISSUER="https://issuer.example/issuer",ORIGIN="https://issuer.example",RESOURCE="https://resource.example/api",CLIENT="durable-client",REDIRECT="https://client.example/cb",SUBJECT="alice";
    static final @NonNull String NAMESPACE="servlet_issuer",COOKIE="__Host-durable-issuer";
    static final @NonNull Instant START=Instant.parse("2026-11-05T12:00:00Z");
    final @NonNull OAuthAuthorizationServer server;
    final @NonNull AtomicBoolean enabled=new AtomicBoolean(true),keysAvailable=new AtomicBoolean(true),authorityAvailable=new AtomicBoolean(true),admitted=new AtomicBoolean(true);
    final @NonNull AtomicLong generation=new AtomicLong(1);
    private final @NonNull AtomicReference<@NonNull Instant> workerNow=new AtomicReference<>(START),authorityNow=new AtomicReference<>(START);
    private final @NonNull AtomicReference<@NonNull String> fault=new AtomicReference<>("normal");
    private final @NonNull AtomicInteger observations=new AtomicInteger(),connections=new AtomicInteger(),commits=new AtomicInteger(),appliedCommits=new AtomicInteger(),unknownFaults=new AtomicInteger(),knownFaults=new AtomicInteger(),unavailableFailures=new AtomicInteger(),unknownFailures=new AtomicInteger(),knownFailures=new AtomicInteger(),openRefusals=new AtomicInteger();
    private final @NonNull Map<@NonNull String,@NonNull Session> sessions=new LinkedHashMap<>();
    private final @NonNull Clock clock=new Clock(){
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!ZoneOffset.UTC.equals(zone))throw new IllegalArgumentException("Fixture UTC only");return this;}
        @Override public @NonNull Instant instant(){return workerNow.get();}
    };
    DurableIssuerFixture()throws Exception {
        verifyOrigin(OAuthAuthorizationServer.class,"CORE");verifyOrigin(ServletOAuthAuthorizationServer.class,"ADAPTER");verifyOrigin(PostgresqlIssuerStore.class,"STORE");verifyOrigin(com.pyranid.Database.class,"PYRANID");verifyOrigin(org.postgresql.Driver.class,"DRIVER");
        for(String absent:List.of("org.junit.jupiter.api.Test","org.jspecify.annotations.NonNull","org.checkerframework.checker.nullness.qual.Nullable")){
            try{Class.forName(absent);throw new IllegalStateException("Runtime annotation/test dependency present");}catch(ClassNotFoundException expected){ }
        }
        Path directory=Path.of(required("REVETSEC_DURABLE_SECRETS"));KeyFactory factory=KeyFactory.getInstance("RSA");
        PrivateKey privateKey=factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("private.der"))));
        PublicKey publicKey=factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(directory.resolve("public.der"))));
        String secret=Files.readString(directory.resolve("sealer.txt"),StandardCharsets.US_ASCII);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",secret)).clock(this.clock).maximumSealedLength(16384).build();
        OAuthIssuerKeySnapshot keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("fixture",privateKey,publicKey)).generation("fixture-g1").publishedAt(START.minusSeconds(120)).build();
        OAuthServerClientRegistration client=OAuthServerClientRegistration.withClientId(CLIENT).configurationVersion("fixture-v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();
        OAuthServerClientRegistration resource=OAuthServerClientRegistration.withClientId("resource").configurationVersion("fixture-v1").authorizationCodePermitted(false).introspectionResources(Set.of(RESOURCE))
                .authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,bytes,budget)->MessageDigest.isEqual(bytes,"test-only-resource-secret".getBytes(StandardCharsets.US_ASCII)))).build();
        OAuthAuthorizationServer.Builder configured=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks"))
                .revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect")).clientRepository((id,budget)->Optional.ofNullable(id.equals(CLIENT)?client:id.equals("resource")?resource:null))
                .signingKeys(budget->{if(!this.keysAvailable.get())throw new IllegalStateException("Fixture signing provider unavailable");return keys;}).stateSealer(sealer).maximumStoreRecordBytes(16384).resources(Map.of(RESOURCE,Set.of("read"))).clock(this.clock).clockSkew(Duration.ZERO)
                .accessTokenLifetime(Duration.ofMinutes(2)).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(3)).refreshTokensEnabled(true)
                .grantPolicy((context,budget)->this.enabled.get()&&context.getSubject().equals(SUBJECT)?decision():OAuthAuthorizationDecision.deniedInstance());
        this.server=ServletDurableBackendRecipe.withIssuerStore(configured,NAMESPACE,identity("issuer-physical/"+NAMESPACE),this::connection,4096,this::observe).build();
        if(required("REVETSEC_DURABLE_STARTUP").equals("fresh")){
            if(this.server.initializeFreshIssuer().getStatus()!=OAuthStoreCommitStatus.COMMITTED)throw new IllegalStateException("Fresh issuer initialization refused");
            this.server.establishNewSubject(SUBJECT);
        }else if(!required("REVETSEC_DURABLE_STARTUP").equals("established"))throw new IllegalArgumentException("Explicit startup required");
        this.server.warmUp();
    }
    static @NonNull OAuthAuthorizationDecision decision(){return OAuthAuthorizationDecision.withSubject(SUBJECT).authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();}
    private @NonNull StoreTimeObservation observe(@NonNull String physical,@NonNull Duration remaining){
        if(!physical.equals(identity("issuer-physical/"+NAMESPACE))||remaining.isZero()||remaining.isNegative()||Thread.currentThread().isInterrupted())throw new IllegalStateException("Scripted authority unavailable");
        this.observations.incrementAndGet();StoreAdmission admission=StoreAdmission.fromIdentifiers(identity("issuer-authority/"+NAMESPACE),identity("issuer-recovery/"+NAMESPACE));
        return this.authorityAvailable.get()?StoreTimeObservation.Healthy.fromObservation(admission,identity("issuer-clock/"+NAMESPACE),this.authorityNow.get(),Duration.ZERO):StoreTimeObservation.Unavailable.fromAdmission(admission);
    }
    private @NonNull Connection connection(@NonNull Duration remaining)throws SQLException {
        if(remaining.isNegative()||remaining.isZero()||Thread.currentThread().isInterrupted())throw new SQLException("Original connection budget exhausted");
        if(this.fault.get().equals("open-unavailable")){this.openRefusals.incrementAndGet();throw new SQLException("Injected sustained unavailable connection before callback");}
        int seconds=Math.max(1,(int)Math.min(3,(remaining.toMillis()+999)/1000));Properties properties=new Properties();properties.setProperty("user",required("REVETSEC_DURABLE_DB_USER"));properties.setProperty("password",required("REVETSEC_DURABLE_DB_PASSWORD"));properties.setProperty("connectTimeout",Integer.toString(seconds));properties.setProperty("socketTimeout",Integer.toString(seconds));properties.setProperty("gssEncMode","disable");
        Connection actual=DriverManager.getConnection(required("REVETSEC_DURABLE_DB_URL"),properties);this.connections.incrementAndGet();AtomicBoolean wrote=new AtomicBoolean();
        return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            if(method.getName().equals("commit")&&wrote.get()){
                this.commits.incrementAndGet();String mode=this.fault.getAndSet("normal");
                if(mode.equals("unknown-before")){this.unknownFaults.incrementAndGet();throw new SQLException("Injected uncertain commit before effect");}
                actual.commit();this.appliedCommits.incrementAndGet();
                if(mode.equals("unknown-after")){this.unknownFaults.incrementAndGet();throw new SQLException("Injected lost acknowledgement after actual commit");}
                if(mode.equals("known-after")){this.knownFaults.incrementAndGet();this.authorityAvailable.set(false);}
                return null;
            }
            try{
                Object value=method.invoke(actual,args);
                if(method.getName().equals("prepareStatement")&&args!=null&&args[0]instanceof String sql&&value instanceof PreparedStatement statement){
                    boolean mutation=sql.stripLeading().matches("(?is)^(INSERT|UPDATE|DELETE).*" );
                    return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{
                        try{Object returned=m.invoke(statement,a);if(mutation&&Set.of("execute","executeUpdate","executeLargeUpdate","executeBatch","executeLargeBatch").contains(m.getName()))wrote.set(true);return returned;}catch(InvocationTargetException failure){throw failure.getCause();}
                    });
                }
                return value;
            }catch(InvocationTargetException failure){throw failure.getCause();}
        });
    }
    synchronized @NonNull Session bootstrap(@Nullable Session old){
        cleanup();if(!this.admitted.get()||!this.enabled.get())throw new Denied(503);
        if(old!=null){if(!current(old))throw new Denied(401);this.sessions.remove(old.id);old.closed=true;}
        if(this.sessions.size()>=128)throw new Denied(503);
        Session session=new Session(random(),random(),BrowserBinding.fresh(),this.clock.instant().plusSeconds(600),System.nanoTime()+Duration.ofMinutes(10).toNanos(),this.generation.get());this.sessions.put(session.id,session);return session;
    }
    synchronized @Nullable Session find(@NonNull String id){cleanup();return this.sessions.get(id);}
    synchronized boolean current(@NonNull Session session){cleanup();return this.sessions.get(session.id)==session&&!session.closed&&session.generation==this.generation.get()&&this.enabled.get();}
    synchronized void close(@NonNull Session session){this.sessions.remove(session.id);session.closed=true;}
    private void cleanup(){this.sessions.values().removeIf(s->{boolean expired=!this.clock.instant().isBefore(s.end)||System.nanoTime()-s.deadline>=0;if(expired)s.closed=true;return expired;});}
    @NonNull JsonObject control(@NonNull String command){
        switch(command){
            case "state"->{}case "allow"->this.enabled.set(true);case "deny"->this.enabled.set(false);case "generation"->this.generation.incrementAndGet();case "admission-deny"->this.admitted.set(false);case "admission-allow"->this.admitted.set(true);
            case "keys-unavailable"->this.keysAvailable.set(false);case "keys-healthy"->this.keysAvailable.set(true);
            case "authority-unavailable"->this.authorityAvailable.set(false);case "authority-healthy"->this.authorityAvailable.set(true);
            case "connections-healthy"->{String active=this.fault.get();if(!active.equals("open-unavailable")||!this.fault.compareAndSet(active,"normal"))throw new IllegalStateException("No connection outage active");}
            case "worker-forward"->this.workerNow.updateAndGet(t->t.plusSeconds(700));case "worker-restore"->this.workerNow.set(START);
            case "unknown-before","unknown-after","known-after","open-unavailable"->{if(!this.fault.compareAndSet("normal",command))throw new IllegalStateException("Fault already armed");}
            case "revoke-subject"->this.server.revokeSubject(SUBJECT);case "revoke-issuer"->this.server.revokeAllGrants();
            default->throw new IllegalArgumentException("Unknown private control");
        }
        synchronized(this){cleanup();return JsonObject.builder().put("selected_origins",true).put("sessions",(long)this.sessions.size()).put("authority_observations",this.observations.longValue()).put("connections",this.connections.longValue()).put("open_refusals",this.openRefusals.longValue()).put("commit_attempts",this.commits.longValue()).put("actual_applied_commits",this.appliedCommits.longValue()).put("injected_unknown",this.unknownFaults.longValue()).put("injected_known",this.knownFaults.longValue()).put("unknown_failures",this.unknownFailures.longValue()).put("known_failures",this.knownFailures.longValue()).put("unavailable_failures",this.unavailableFailures.longValue()).build();}
    }
    void record(@NonNull OAuthServerException failure){if(failure.getReason()==OAuthServerException.Reason.COMMIT_OUTCOME_UNKNOWN)this.unknownFailures.incrementAndGet();else if(failure.getReason()==OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED)this.knownFailures.incrementAndGet();else this.unavailableFailures.incrementAndGet();}
    static @NonNull String random(){byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    static @NonNull String identity(@NonNull String text){try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}catch(GeneralSecurityException failure){throw new IllegalStateException("Required digest unavailable");}}
    static @NonNull String required(@NonNull String name){return Objects.requireNonNull(System.getenv(name));}
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind)throws Exception {
        Path selected=Path.of(required("REVETSEC_DURABLE_"+kind+"_JAR")).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if(!selected.equals(actual)||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(required("REVETSEC_DURABLE_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact origin mismatch");
    }
    public static void main(@NonNull String @NonNull [] args)throws Exception {
        if(args.length!=2||!args[0].equals("keygen"))throw new IllegalArgumentException("Private fixture key preparation only");Path directory=Path.of(args[1]);KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair keys=generator.generateKeyPair();Files.write(directory.resolve("private.der"),keys.getPrivate().getEncoded());Files.write(directory.resolve("public.der"),keys.getPublic().getEncoded());byte[] sealer=new byte[32];new SecureRandom().nextBytes(sealer);Files.writeString(directory.resolve("sealer.txt"),Base64.getEncoder().encodeToString(sealer),StandardCharsets.US_ASCII);Arrays.fill(sealer,(byte)0);
    }
    static final class Session {
        final @NonNull String id,csrf;final @NonNull BrowserBinding binding;final @NonNull Instant end;final long deadline,generation;volatile boolean closed;
        Session(@NonNull String id,@NonNull String csrf,@NonNull BrowserBinding binding,@NonNull Instant end,long deadline,long generation){this.id=id;this.csrf=csrf;this.binding=binding;this.end=end;this.deadline=deadline;this.generation=generation;}
        @Override public @NonNull String toString(){return "Session{<redacted>}";}
    }
    static final class Denied extends RuntimeException {private static final long serialVersionUID=1L;final int status;Denied(int status){this.status=status;}}
    @Override public @NonNull String toString(){return "DurableIssuerFixture{<redacted>}";}
}
