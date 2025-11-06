package uk.co.spudsoft.jwtvalidatorvertx.vertx;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.restassured.RestAssured;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.IssuerAcceptabilityHandler;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;
import uk.co.spudsoft.jwtvalidatorvertx.JwtValidator;

/**
 * Integration-style unit tests for VertxJwksHandler using a real Vert.x HttpServer and RestAssured.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ExtendWith(VertxExtension.class)
public class VertxJwksHandlerTokenTest {
  
  private static final Logger logger = LoggerFactory.getLogger(VertxJwksHandlerTokenTest.class);
  
  @Test
  void testBuildToken(Vertx vertx, VertxTestContext testContext) throws Exception {
    Cache<String, AlgorithmAndKeyPair> cache = emptyCache();
    Map.Entry<String, AlgorithmAndKeyPair> entry = rsaKey("kid-rsa-1");
    cache.put(entry.getKey(), entry.getValue());
    
    HttpServer httpServer = vertx.createHttpServer();
    
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }    
    
    VertxJwksHandler handler = new VertxJwksHandler(null, null, "localhost", port, "/authy", true);
    
    handler.setKeyCache(cache);

    Router router = Router.router(vertx);
    router.route("/authy/*").handler(handler);
    httpServer.requestHandler(router);
    httpServer.listen(port);
    
    // This does nothing
    handler.start();
    
    WebClient webClient = WebClient.create(vertx);
    
    JwtValidator validator = JwtValidator.createDynamic(webClient
            , IssuerAcceptabilityHandler.create(Arrays.asList(handler.getBaseUrl()), null, null)
            , Duration.ofMinutes(1));
    
    // RestAssured base URL
    RestAssured.baseURI = "http://localhost";
    RestAssured.port = port;
    
    String token = RestAssured
            .given()
            .body("{\"myclaim\":\"myvalue\", \"aud\":\"test\", \"sub\":\"irrelevant\"}")
            .put("/authy/token")
            .then()
            .statusCode(200)
            .extract().body().asString();
    
    logger.debug("Token: {}", token);
    
    validator.validateToken(handler.getBaseUrl(), token, Arrays.asList("test"), false)
            .andThen(ar -> {
              if (ar.succeeded()) {
                logger.debug("JWT: {}", ar.result());
                try {
                  // This does nothing
                  handler.close();
                } catch (Throwable ex) {
                  testContext.failNow(ex);
                }
                testContext.completeNow();
              } else {
                testContext.failNow(ar.cause());
              }
            });
    
    
  }

  // Helpers

  private Cache<String, AlgorithmAndKeyPair> emptyCache() {
    return CacheBuilder.newBuilder()
        .expireAfterWrite(Duration.ofMinutes(10))
        .concurrencyLevel(1)
        .build();
  }

  private Map.Entry<String, AlgorithmAndKeyPair> rsaKey(String kid) throws NoSuchAlgorithmException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    AlgorithmAndKeyPair akp = new AlgorithmAndKeyPair(JsonWebAlgorithm.RS256, kp);
    return Map.entry(kid, akp);
  }
}