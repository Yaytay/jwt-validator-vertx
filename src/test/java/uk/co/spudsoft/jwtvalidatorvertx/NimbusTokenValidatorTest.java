package uk.co.spudsoft.jwtvalidatorvertx;

import com.google.common.collect.ImmutableMap;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.Checkpoint;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import uk.co.spudsoft.jwtvalidatorvertx.nimbus.NimbusJwksHandler;
import uk.co.spudsoft.jwtvalidatorvertx.nimbus.NimbusTokenBuilder;

/**
 * Required tests: 
 * <UL>
 * <LI>Invalid structure (not three dots) 
 * <LI>Invalid structure (first part not base64) 
 * <LI>Invalid structure (second part not base64) 
 * <LI>Invalid structure (third part not base64) 
 * <LI>Invalid structure (first part not JSON) 
 * <LI>Invalid structure (second part not JSON) 
 * <LI>Algorithm none 
 * <LI>Algorithm not in acceptable list (RS256, RS384, RS512) but token otherwise valid 
 * <LI>Signature invalid 
 * <LI>Key not in jwks output 
 * <LI>Token exp value in the past - measure acceptable leeway over &lt; 1 hour 
 * <LI>Token nbf claim in the future - measure acceptable leeway over &lt; 1 hour 
 * <LI>Token bad iss accepted - not matching preconfigured values 
 * <LI>Token bad aud accepted 
 * <LI>Token aud not accepted when single value despite being the aud for the service 
 * <LI>Token aud not accepted when single element array despite being the aud for the service 
 * <LI>Token aud not accepted when first element of array despite being the aud for the service 
 * <LI>Token aud not accepted when last element of array despite being the aud for the service 
 * <LI>Token sub not present
 * </UL>
 *
 * @author njt
 */
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ExtendWith(VertxExtension.class)
public class NimbusTokenValidatorTest {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(NimbusTokenValidatorTest.class);

  private final Vertx vertx = Vertx.vertx();

  private NimbusJwksHandler jwks;

  private static final Map<String, Object> BORING_CLAIMS = ImmutableMap.<String, Object>builder()
          .put("email", "bob@")
          .put("given_name", "tester")
          .build();

  @BeforeAll
  public void init() throws IOException {
    jwks = new NimbusJwksHandler();
    logger.debug("Starting JWKS endpoint");
    jwks.start();
  }

  @AfterAll
  public void shutdown() throws IOException {
    logger.debug("Stopping JWKS endpoint");
    jwks.close();
  }

  private final JwtValidatorVertx defaultValidator;

  public NimbusTokenValidatorTest(Vertx vertx) {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    defaultValidator = JwtValidatorVertx.create(vertx, iah, Duration.of(1, ChronoUnit.MINUTES));
  }

  @Test
  @Order(1)
  public void testValid(VertxTestContext testContext) throws Throwable {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(
            builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", Arrays.asList("aud"),
                    nowSeconds, nowSeconds + 100, BORING_CLAIMS),
             Arrays.asList("aud"),
             false
    ).compose(signedJwt -> {
      logger.debug("Token valid from: {}", signedJwt.getNotBeforeLocalDateTime());
      logger.debug("Token tags: {}", signedJwt.getClaim("tags"));
      testContext.verify(() -> {
        assertNotNull(signedJwt);
      });
      return Future.succeededFuture();
    }).onComplete(testContext.succeedingThenComplete());
  }

  @Test
  @Order(2)
  public void testInvalidStructureNotThreeParts(VertxTestContext testContext) {
    Checkpoint checkpoint = testContext.checkpoint(4);
    defaultValidator.validateToken("a.b", Arrays.asList("aud"), false)
            .onFailure(ex -> checkpoint.flag())
            .onSuccess(s -> testContext.failNow("Should have thrown"))
            ;
    defaultValidator.validateToken("a.b.c.d", Arrays.asList("aud"), false)
            .onFailure(ex -> checkpoint.flag())
            .onSuccess(s -> testContext.failNow("Should have thrown"))
            ;
    defaultValidator.validateToken("a.b.c.d.e", Arrays.asList("aud"), false)
            .onFailure(ex -> checkpoint.flag())
            .onSuccess(s -> testContext.failNow("Should have thrown"))
            ;
    defaultValidator.validateToken("a.b.c.d.e.f", Arrays.asList("aud"), false)
            .onFailure(ex -> checkpoint.flag())
            .onSuccess(s -> testContext.failNow("Should have thrown"))
            ;
  }

  @Test
  @Order(3)
  public void testInvalidStructureFirstPartNotBase64(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder() {
      @Override
      protected String base64Header(JsonObject header) {
        String base64 = super.base64Header(header);
        return base64.substring(0, base64.length() - 1);
      }
    };
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(4)
  public void testInvalidStructureSecondPartNotBase64(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder() {
      @Override
      protected String base64Claims(JsonObject claims) {
        String base64 = super.base64Claims(claims);
        base64 = base64.replaceAll("=", "");
        return base64.substring(0, base64.length() - 1);
      }
    };
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(5)
  public void testInvalidStructureThirdPartNotBase64(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder() {
      @Override
      protected String base64Signature(byte[] signature) {
        String base64 = super.base64Signature(signature);
        base64 = base64.replaceAll("=", "");
        return base64.substring(0, base64.length() - 1);
      }
    };
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(6)
  public void testInvalidStructureFirstPartNotJson(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder() {
      @Override
      protected String base64Header(JsonObject header) {
        return BASE64.encodeToString(header.toString().replaceAll("\"", "").getBytes(StandardCharsets.UTF_8));
      }
    };
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(7)
  public void testInvalidStructureSecondPartNotJson(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder() {
      @Override
      protected String base64Claims(JsonObject claims) {
        return BASE64.encodeToString(claims.toString().replaceAll("\"", "").getBytes(StandardCharsets.UTF_8));
      }
    };
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(8)
  public void testAlgorithmNone(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.none, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(9)
  public void testAlgorithmNotPermitted(VertxTestContext testContext) throws Exception {

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.ES512, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(10)
  public void testInvalidSignature(VertxTestContext testContext) throws Exception {

    TokenBuilder builder = new NimbusTokenBuilder().setInvalidSignature(true);
    jwks.setTokenBuilder((NimbusTokenBuilder) builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(11)
  public void testKeyNotInJwksOutput(VertxTestContext testContext) throws Exception {

    TokenBuilder builder = new NimbusTokenBuilder().setInvalidKid(true);
    jwks.setTokenBuilder((NimbusTokenBuilder) builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(13)
  public void testNoExpPermitted(VertxTestContext testContext) throws Exception {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setRequireExp(false);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete())
            ;
  }

  @Test
  @Order(14)
  public void testNoExpRejected(VertxTestContext testContext) throws Exception {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setRequireExp(true);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds, null, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete())
            ;
  }

  @Test
  @Order(12)
  public void testExpInThePast() throws Throwable {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setTimeLeewaySeconds(6);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    int acceptable = -1;
    for (int i = 0; i < 20; i += 1) {
      logger.debug("Iteration {}", i);
      long nowSeconds = System.currentTimeMillis() / 1000;
      Future<JWT> future = validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
                Arrays.asList("aud"), nowSeconds, nowSeconds - i, BORING_CLAIMS), Arrays.asList("aud"), false);
      await().atMost(2, TimeUnit.SECONDS).until(() -> future.isComplete());

      if (future.succeeded()) {
        acceptable = i;
      }
    }
    logger.info("Maximumum detected leeway in exp: {}s", acceptable);
    assertThat(acceptable, greaterThanOrEqualTo(5));
    assertThat(acceptable, lessThanOrEqualTo(7));
  }

  @Test
  @Order(13)
  public void testNoNbfPermitted(VertxTestContext testContext) throws Throwable {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setRequireNbf(false);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
            Arrays.asList("aud"), null, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete());
    
  }

  @Test
  @Order(14)
  public void testNoNbfRejected(VertxTestContext testContext) throws Throwable {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setRequireNbf(true);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
            Arrays.asList("aud"), null, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete());
  }

  @Test
  @Order(13)
  public void testNbfInTheFuture() throws Throwable {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));
    validator.setTimeLeewaySeconds(6);

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();

    int acceptable = 0;
    for (int i = 0; i < 20; i += 1) {
      long nowSeconds = System.currentTimeMillis() / 1000;
      Future<JWT> future = validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
              Arrays.asList("aud"), nowSeconds + i, nowSeconds, BORING_CLAIMS), Arrays.asList("aud"), false);
      await().atMost(2, TimeUnit.SECONDS).until(() -> future.isComplete());
      
      if (future.succeeded()) {
        acceptable = i;
      }
    }
    logger.info("Maximumum detected leeway in nbf: {}s", acceptable);
    assertThat(acceptable, greaterThanOrEqualTo(5));
    assertThat(acceptable, lessThanOrEqualTo(7));
  }

  @Test
  @Order(14)
  public void testBadIssAccepted(VertxTestContext testContext) throws Throwable {
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList(jwks.getBaseUrl().replace("bob", "carol")), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.ofMinutes(1));

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();

    long nowSeconds = System.currentTimeMillis() / 1000;
    validator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
            Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete());
  }

  @Test
  @Order(15)
  public void testBadAudAccepted(VertxTestContext testContext) throws Exception {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();

    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub",
            Arrays.asList("bad"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete());
  }

  @Test
  @Order(16)
  public void testAudAcceptedAsSingleElementArray(VertxTestContext testContext) throws Throwable {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    JsonArray aud = new JsonArray();
    aud.add("aud");
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(
            builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", null, nowSeconds, nowSeconds + 100,
                    claimsWithAud), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete());
  }

  @Test
  @Order(17)
  public void testAudAcceptedAsSingleValue(VertxTestContext testContext) throws Throwable {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", "aud")
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(
            builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", null, nowSeconds, nowSeconds + 100,
                    claimsWithAud), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete());
  }

  @Test
  @Order(18)
  public void testAudAcceptedAsFirstElementOfArray(VertxTestContext testContext) throws Throwable {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    JsonArray aud = new JsonArray();
    aud.add("aud");
    aud.add("bob");
    aud.add("carol");
    aud.add("ted");
    aud.add("ringo");
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(
            builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", null, nowSeconds, nowSeconds + 100,
                    claimsWithAud), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete());
  }

  @Test
  @Order(19)
  public void testAudAcceptedAsLastElementOfArray(VertxTestContext testContext) throws Throwable {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    JsonArray aud = new JsonArray();
    aud.add("bob");
    aud.add("carol");
    aud.add("ted");
    aud.add("ringo");
    aud.add("aud");
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(
            builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", null, nowSeconds, nowSeconds + 100,
                    claimsWithAud), Arrays.asList("aud"), false)
            .onComplete(testContext.succeedingThenComplete());
  }

  @Test
  @Order(20)
  public void testNoSubAccepted(VertxTestContext testContext) throws Throwable {

    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    defaultValidator.validateToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), null,
              Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS), Arrays.asList("aud"), false)
            .onComplete(testContext.failingThenComplete());
  }

}
