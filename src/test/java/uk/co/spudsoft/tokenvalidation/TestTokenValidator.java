/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.tokenvalidation;

import uk.co.spudsoft.tokenvalidation.jdk.JdkJwksHandler;
import uk.co.spudsoft.tokenvalidation.jdk.JdkTokenBuilder;
import io.vertx.core.Vertx;
import java.io.IOException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author njt
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestTokenValidator extends AbstractTokenValidationTester {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(TestTokenValidator.class);

  private final Vertx vertx = Vertx.vertx();
  private TokenValidator tokenValidator;

  private JdkJwksHandler jwks;

  @Override
  protected TokenBuilder createTokenBuilder() {
    return new JdkTokenBuilder();
  }

  @Test
  public void test() {
    performTests();
    List<TestResult> results = getResults();
    logger.debug("Token test results:");
    for (TestResult result : results) {
      logger.debug("{}\t{}\t{}", result.testName, result.pass, result.message);
    }
  }

  @BeforeAll
  public void init() throws IOException {
    jwks = new JdkJwksHandler();
    logger.debug("Starting JWKS endpoint");
    jwks.start();
    tokenValidator = TokenValidator.create(vertx, Arrays.asList(jwks.getBaseUrl()), Duration.of(1, ChronoUnit.MINUTES));
    tokenValidator.setRequireExp(true);
    tokenValidator.setRequireNbf(true);
    tokenValidator.setTimeLeewaySeconds(3);
  }

  @AfterAll
  public void shutdown() throws IOException {
    logger.debug("Stopping JWKS endpoint");
    jwks.close();
  }

  @Override
  protected void useToken(String token) {
    tokenValidator.validateToken(token, null, false);
  }

  @Override
  protected void prepTest(TokenBuilder builder) {
    jwks.setTokenBuilder((JdkTokenBuilder) builder);
  }

  @Override
  protected String getAud() {
    return "aud";
  }

  @Override
  protected String getIssuer() {
    return jwks.getBaseUrl();
  }

  @Override
  protected String getKeyId() {
    return UUID.randomUUID().toString();
  }

  @Override
  protected boolean requiresExp() {
    return true;
  }

  @Override
  protected boolean requiresNbf() {
    return true;
  }

}
