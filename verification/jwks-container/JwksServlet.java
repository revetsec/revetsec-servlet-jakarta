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

import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import com.revetsec.servlet.jakarta.ServletJwks;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/** Disposable public-certificate publisher for the standalone JWKS transport probe. */
public final class JwksServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final JwksPublisher publisher = publisher();

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ServletJwks.writeResponse(this.publisher, request, response);
    }

    private static JwksPublisher publisher() {
        try {
            X509Certificate leaf = certificate("/publisher-leaf.pem");
            X509Certificate root = certificate("/publisher-root.pem");
            return JwksPublisher.withKeys(List.of(PublishedJwk.withPublicKey(leaf.getPublicKey())
                    .keyId("epic-prod").algorithm(JwsAlgorithm.RS384).certificateChain(List.of(leaf, root)).build()))
                    .httpCacheMaxAge(Duration.ofHours(1)).build();
        } catch (GeneralSecurityException | IOException failure) {
            throw new IllegalStateException("Unable to load public test certificate chain", failure);
        }
    }

    private static X509Certificate certificate(String path) throws GeneralSecurityException, IOException {
        try (InputStream input = JwksServlet.class.getResourceAsStream(path)) {
            if (input == null) throw new IllegalStateException("Missing public test certificate");
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }
}
