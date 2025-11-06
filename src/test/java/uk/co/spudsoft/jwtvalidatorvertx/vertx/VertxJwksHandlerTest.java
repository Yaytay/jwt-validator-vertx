package uk.co.spudsoft.jwtvalidatorvertx.vertx;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.restassured.RestAssured;
import io.vertx.ext.web.Router;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;

/**
 * Integration-style unit tests for VertxJwksHandler using a real Vert.x HttpServer and RestAssured.
 */
public class VertxJwksHandlerTest {

  private VertxJwksHandler handler;
  private int port;
  private String basePath;

  
  @BeforeEach
  void setUp() throws IOException {
        
    
    // Choose a random available port
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    basePath = "/auth";

    handler = VertxJwksHandler.create("localhost", port, basePath);
    handler.start();

    // RestAssured base URL
    RestAssured.baseURI = "http://localhost";
    RestAssured.port = port;
  }

  @AfterEach
  void tearDown() throws Exception {
    handler.close();
  }
  
  @Test
  void testCheckPath() {
    assertEquals("/bob", VertxJwksHandler.checkPath("/bob"));
    assertEquals("/bob", VertxJwksHandler.checkPath("bob"));
    assertEquals("/bob", VertxJwksHandler.checkPath("bob/"));
  }

  @Test
  void testOpenIdConfigurationReturnsJwksUri() {
    RestAssured
        .given()
        .when()
        .get(basePath + "/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("jwks_uri", Matchers.equalTo("http://localhost:" + port + "http://localhost:" + port + basePath + "/jwks"));
  }

  @Test
  void testJwksReturnsEmptyKeysWhenNoKeysPresent() {
    handler.setKeyCache(emptyCache());

    RestAssured
        .given()
        .when()
        .get(basePath + "/jwks")
        .then()
        .statusCode(200)
        .header("cache-control", Matchers.containsString("max-age"))
        .body("keys", Matchers.hasSize(0));
  }

  @Test
  void testJwksReturnsProvidedRsaKey() throws Exception {
    Cache<String, AlgorithmAndKeyPair> cache = emptyCache();
    Map.Entry<String, AlgorithmAndKeyPair> entry = rsaKey("kid-rsa-1");
    cache.put(entry.getKey(), entry.getValue());
    handler.setKeyCache(cache);

    RestAssured
        .given()
        .when()
        .get(basePath + "/jwks")
        .then()
        .statusCode(200)
        .header("cache-control", Matchers.equalTo("max-age=100"))
        .body("keys", Matchers.hasSize(1))
        .body("keys[0].kid", Matchers.equalTo("kid-rsa-1"))
        .body("keys[0].kty", Matchers.equalTo("RSA"))
        .body("keys[0].alg", Matchers.equalTo(entry.getValue().getAlgorithm().getName()));
  }

  @Test
  void testNonMatchingPathFallsThrough() {
    RestAssured
        .given()
        .when()
        .get("/not-matched")
        .then()
        .statusCode(Matchers.anyOf(Matchers.is(404), Matchers.is(200)));
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