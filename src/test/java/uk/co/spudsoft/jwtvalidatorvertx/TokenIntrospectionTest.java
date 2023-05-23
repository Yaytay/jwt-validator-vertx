package uk.co.spudsoft.jwtvalidatorvertx;

import uk.co.spudsoft.jwtvalidatorvertx.jdk.JdkJwksHandler;
import uk.co.spudsoft.jwtvalidatorvertx.jdk.JdkTokenBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableMap;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * TokenIntrospectionTest class.
 *
 * @author Paulius Matulionis
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(VertxExtension.class)
@Disabled
public class TokenIntrospectionTest {

  private static final Logger logger = LoggerFactory.getLogger(TokenIntrospectionTest.class);

  private final Vertx vertx = Vertx.vertx();
  private final ObjectMapper objectMapper = new ObjectMapper();

  private JdkJwksHandler jwks;

  @BeforeAll
  public void init() throws IOException {
    jwks = new JdkJwksHandler();
    logger.debug("Starting JWKS endpoint");
    jwks.start();
  }

  @AfterAll
  public void shutdown() throws IOException {
    logger.debug("Stopping JWKS endpoint");
    jwks.close();
  }

  @Test
  public void testIntrospectToken(Vertx vertx, VertxTestContext testContext) throws Throwable {
    JdkTokenBuilder builder = new JdkTokenBuilder();
    jwks.setTokenBuilder(builder);

    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(Arrays.asList("http://localhost.*"), null, Duration.ofMillis(1000));
    JwtValidatorVertx validator = JwtValidatorVertx.create(vertx, iah, Duration.of(1, ChronoUnit.MINUTES));
    
    ArrayNode aud = objectMapper.createArrayNode();
    aud.add("bob");
    aud.add("carol");
    aud.add("aud");
    aud.add("ted");
    aud.add("ringo");

    final ObjectNode moviesAndYears = objectMapper.createObjectNode()
            .put("1917", 2019)
            .put("The Matrix", 1999)
            .put("Blade Runner", 1982)
            .put("Blade Runner 2049", 2017);

    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .put("is_admin", false)
            .put("age", 100)
            .put("some_decimal", 0.5)
            .put("movies_and_years", moviesAndYears)
            .put("user_id", Map.of("example.com", "tester"))
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;

    String token = builder.buildToken(JsonWebAlgorithm.RS256, kid, jwks.getBaseUrl(), "sub", null, nowSeconds, nowSeconds + 100, claimsWithAud);

    validator.validateToken(token, Arrays.asList("aud"), false)
            .compose(jwt -> {
              testContext.verify(() -> {
                assertNotNull(jwt);

                assertThat(jwt.getPayloadSize(), greaterThan(0));
                
                List<String> audFromPayload = jwt.getAudience();
                for (int i = 0; i < aud.size(); i++) {
                  assertEquals(aud.get(i).textValue(), audFromPayload.get(i));
                }

                assertEquals("bob@", jwt.getClaim("email"));
                assertEquals("tester", jwt.getClaim("given_name"));
                assertEquals(false, jwt.getClaim("is_admin"));
                assertEquals(100, ((Number) jwt.getClaim("age")).intValue());
                assertEquals(0.5, jwt.getClaim("some_decimal"));

                final Map<?,?> moviesAndYearsFromPayload = (Map) jwt.getClaim("movies_and_years");
                assertEquals(2019, ((Number) moviesAndYearsFromPayload.get("1917")).intValue());
                assertEquals(1999, ((Number) moviesAndYearsFromPayload.get("The Matrix")).intValue());
                assertEquals(1982, ((Number) moviesAndYearsFromPayload.get("Blade Runner")).intValue());
                assertEquals(2017, ((Number) moviesAndYearsFromPayload.get("Blade Runner 2049")).intValue());

                final Map<?,?> userIdMap = (Map) jwt.getClaim("user_id");
                assertEquals("tester", userIdMap.get("example.com"));                
              });
//              return validator.introspectToken(token, null, null);
//            })
//            .compose(claims -> {
//              testContext.verify(() -> {
//                logger.debug("Claims: {}.", claims);
//                assertEquals("bobby value", claims.getStringClaim("bobby"));
//              });
              return Future.succeededFuture();
            })
            .onComplete(testContext.succeedingThenComplete())
            ;
  }

}
