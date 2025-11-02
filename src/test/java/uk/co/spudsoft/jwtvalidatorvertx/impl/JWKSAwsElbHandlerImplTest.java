/*
 * Copyright (C) 2025 njt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetAwsElbHandler;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler;

/**
 *
 * @author njt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(VertxExtension.class)
public class JWKSAwsElbHandlerImplTest {
  
  private static final Logger logger = LoggerFactory.getLogger(JWKSAwsElbHandlerImplTest.class);
  
  private int port;
  private ExecutorService exeSvc;
  private HttpServer server;
  private AtomicInteger getCount = new AtomicInteger();
  
  private void sendResponse(HttpExchange exchange, int responseCode, String body) throws IOException {
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(responseCode, bodyBytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bodyBytes);
    }
  }
  
  @BeforeAll
  final void createAlbHandler() throws IOException {
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    logger.debug("Starting ELB handler on {}", port);
    exeSvc = Executors.newFixedThreadPool(2);
    server = HttpServer.create(new InetSocketAddress(port), 2);
    server.setExecutor(exeSvc);
    server.createContext("/keys", exchange -> {
      logger.debug("Got request to {}", exchange.getRequestURI());
      if ("/keys/8dcb467a-d467-4ba3-99de-5c77d15387f4".equals(exchange.getRequestURI().getPath())) {
        String pem = "-----BEGIN PUBLIC KEY-----\n" +
                      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOvCytZ9aXtRyLPDvcqW4wxCcNoay\n" +
                      "3laYl5lmVnuZA6KCH5QdO13Epzy4KXrc0NhU8f0QWVXf1bFS2PXeiNwqcQ==\n" +
                      "-----END PUBLIC KEY-----";
        getCount.incrementAndGet();
        sendResponse(exchange, 200, pem);        
      } else {
        sendResponse(exchange, 404, "Not found");
      }
    });
    server.start();
  }
  
  @AfterAll
  final void shutdown() {
    if(server != null) {
      server.stop(1);
    }
    if (exeSvc != null) {
      exeSvc.shutdownNow();
    }
    logger.debug("Stopped ELB handler on {}", port);
  }
  
  
  @Test
  public void testFindJwk(Vertx vertx, VertxTestContext testContext) {
    
    WebClient webClient = WebClient.create(vertx);

    List<String> urls = Arrays.asList(
                    "http://localhost:" + port + "/keys"
                    , "http://localhost:" + port + "/bad/"
            );
    
    JsonWebKeySetHandler albHandler = JsonWebKeySetAwsElbHandler.create(webClient, urls, Duration.ofHours(1));
    albHandler.optimize();
    assertEquals("The kid is not a valid AWS ELB kid.", assertThrows(IllegalArgumentException.class, () -> {
      albHandler.findJwk(null, "£!$%£$%");
    }).getMessage());
    albHandler.findJwk(null, "8dcb467a-d467-4ba3-99de-5c77d15387f4")
            .compose(jwk -> {
              testContext.verify(() -> {
                assertNotNull(jwk);
                assertEquals("ES256", jwk.getAlgorithm());
                assertEquals(1, getCount.get());
              });
              return Future.succeededFuture();
            })
            .compose(v -> {
              return albHandler.findJwk(null, "8dcb467a-d467-4ba3-99de-5c77d15387f4");
            })
            .compose(jwk -> {
              testContext.verify(() -> {
                assertNotNull(jwk);
                assertEquals("ES256", jwk.getAlgorithm());
                assertEquals(1, getCount.get());
              });
              return Future.succeededFuture();
            })
            .compose(v -> {
              return albHandler.findJwk(null, "bad");
            })
            .andThen(testContext.failingThenComplete());
  }
  
}
