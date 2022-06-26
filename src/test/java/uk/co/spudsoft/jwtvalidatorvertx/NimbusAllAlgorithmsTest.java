package uk.co.spudsoft.jwtvalidatorvertx;

import com.google.common.collect.ImmutableMap;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.junit5.Timeout;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import static java.util.concurrent.TimeUnit.MINUTES;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
@Timeout(timeUnit = MINUTES, value = 60)
public class NimbusAllAlgorithmsTest {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(NimbusAllAlgorithmsTest.class);

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

  @Test
  public void testValidES256(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.ES256, 86);
  }
  
  @Test
  public void testValidES384(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.ES384, 128);
  }
  
  @Test
  public void testValidES512(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.ES512, 176);
  }
  
  @Test
  public void testValidEdDSA(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.EdDSA, 86);
  }
  
  @Test
  public void testValidPS256(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.PS256, 342);
  }
  
  @Test
  public void testValidPS384(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.PS384, 342);
  }
  
  @Test
  public void testValidPS512(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.PS512, 342);
  }
  
  @Test
  public void testValidRS256(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.RS256, 342);
  }
  
  @Test
  public void testValidRS384(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.RS384, 342);
  }
  
  @Test
  public void testValidRS512(VertxTestContext testContext) {
    testValid(testContext, JsonWebAlgorithm.RS512, 342);
  }
  
  /**
   * Test a valid token using a specific algorithm.
   * Note that this is the method that is copied to the README.md file, which is why it's overly commented.
   * @param testContext The VertxTestContext to complete asynchronously.
   * @param jwa The algorithm to use.
   * @param sigLength The expected length of the signature (to be tested).
   */
  public void testValid(VertxTestContext testContext, JsonWebAlgorithm jwa, int sigLength) {
    NimbusTokenBuilder builder = new NimbusTokenBuilder();
    jwks.setTokenBuilder(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    String token;
    try {
      token = builder.buildToken(jwa, kid, jwks.getBaseUrl(), "sub", Arrays.asList("aud"), nowSeconds, nowSeconds + 100, BORING_CLAIMS);
    } catch(Throwable ex) {
      logger.error("Unable to generate {} token: ", jwa, ex);
      testContext.failNow(ex);
      return;
    }

    JwtValidatorVertx validator = JwtValidatorVertx.create(
            // The Vertx instance that will be used for make web requests
            vertx, 
            // Array of acceptable issuers (as regular expressions).
            Arrays.asList("http://localhost.*"), 
            // Time to cache JWK keys for if they do have a cache-control(max-age) header
            Duration.of(1, ChronoUnit.MINUTES)
    );
    // By default the JwtValidatorVertx will accept RS256, RS384 and RS512, any others that must be handled must be specified.
    validator.addPermittedAlgorithm(jwa);

    validator.validateToken(token, Arrays.asList("aud"), false)
            .compose(signedJwt -> {
              // Standard claims can be extracted with named methods
              logger.debug("Token valid from: {}", signedJwt.getNotBeforeLocalDateTime());
              // Non-standard claims can be extracted with the claim method
              logger.debug("Token tags: {}", signedJwt.getClaim("tags"));
              assertEquals(sigLength, signedJwt.getSignature().length()
                      , "Signatue for " + jwa.getName() + " is " + signedJwt.getSignature().length() + " characters, expected " + sigLength);
              testContext.verify(() -> {
                assertNotNull(signedJwt, "Failed to validate " + jwa.getName() + " token (null returned).");
              });
              return Future.succeededFuture();
            })
            .onComplete(testContext.succeedingThenComplete());
    
  }

}
