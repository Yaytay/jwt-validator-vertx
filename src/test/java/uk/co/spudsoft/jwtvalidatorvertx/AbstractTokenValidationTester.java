package uk.co.spudsoft.jwtvalidatorvertx;

import com.google.common.collect.ImmutableMap;
import io.vertx.core.json.JsonArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * @author njt
 */
public abstract class AbstractTokenValidationTester {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(AbstractTokenValidationTester.class);

  private static final Map<String, Object> BORING_CLAIMS = ImmutableMap.<String, Object>builder()
          .put("email", "bob@")
          .put("given_name", "tester")
          .build();
  
  protected abstract TokenBuilder createTokenBuilder();

  protected abstract void useToken(String token);

  protected abstract void prepTest(TokenBuilder builder);

  protected abstract String getAud();

  protected abstract String getIssuer();

  protected abstract String getKeyId();

  protected abstract boolean requiresExp();

  protected abstract boolean requiresNbf();

  protected class TestFailure extends Exception {

    private static final long serialVersionUID = 1L;
    
    public TestFailure(String message) {
      super(message);
    }

  }

  protected interface TestFunction {

    String test() throws Exception;
  }

  public class TestResult {

    public final String testName;
    public final String message;
    public final boolean pass;

    public TestResult(String testName, String message, boolean pass) {
      this.testName = testName;
      this.message = message;
      this.pass = pass;
    }
  }

  private List<TestResult> results = new ArrayList<>();

  public List<TestResult> getResults() {
    return results;
  }

  protected void performTest(String testName, TestFunction function) {
    String message;
    boolean succeeded = false;
    try {
      message = function.test();
      succeeded = true;
    } catch (TestFailure ex) {
      message = ex.getMessage();
    } catch (Throwable ex) {
      message = ex.getClass().getName() + ": " + ex.getMessage();
    }
    results.add(new TestResult(testName, message, succeeded));
  }

  public void performTests() {
    performTest("Valid token with RS256 signature", this::testValidRs256);
    performTest("Valid token with RS384 signature", this::testValidRs384);
    performTest("Valid token with RS512 signature", this::testValidRs512);
    performTest("Token structure invalid - not three parts", this::testInvalidStructureNotThreeParts);
    performTest("Token structure invalid - first part not base 64", this::testInvalidStructureFirstPartNotBase64);
    performTest("Token structure invalid - second part not base 64", this::testInvalidStructureSecondPartNotBase64);
    performTest("Token structure invalid - third part not base 64", this::testInvalidStructureThirdPartNotBase64);
    performTest("Token structure invalid - first part not JSON", this::testInvalidStructureFirstPartNotJson);
    performTest("Token structure invalid - second part not JSON", this::testInvalidStructureSecondPartNotJson);
    performTest("Token with none algorithm", this::testAlgorithmNone);
    performTest("Token with ES512 algorithm", this::testAlgorithmES512);
    performTest("Token with HS512 algorithm", this::testAlgorithmHS512);
    performTest("Token with invalid signature", this::testInvalidSignature);
    performTest("Key not found in JWKS output", this::testKeyNotInJwksOutput);
    performTest("Token with no exp claim", this::testNoExpPermitted);
    performTest("Token with exp claim in the past", this::testExpInThePast);
    performTest("Token with no nbf claim", this::testNoNbfPermitted);
    performTest("Token with nbf claim in the future", this::testNbfInTheFuture);
    performTest("Token with bad iss", this::testBadIssAccepted);
    performTest("Token with bad aud", this::testBadAudAccepted);
    performTest("Valid token with aud in single element array", this::testAudNotAcceptedAsSingleElementArray);
    performTest("Valid token with aud as string", this::testAudNotAcceptedAsSingleValue);
    performTest("Valid token with aud as first element of array", this::testAudNotAcceptedAsFirstElementOfArray);
    performTest("Valid token with aud as last element of array", this::testAudNotAcceptedAsLastElementOfArray);
    performTest("Token with no sub", this::testNoSubAccepted);
  }

  public String testValidRs256() throws Exception {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
            nowSeconds + 100, BORING_CLAIMS));
    return "Passed";
  }

  public String testValidRs384() throws Exception {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    useToken(builder.buildToken(JsonWebAlgorithm.RS384, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
            nowSeconds + 100, BORING_CLAIMS));
    return "Passed";
  }

  public String testValidRs512() throws Exception {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    useToken(builder.buildToken(JsonWebAlgorithm.RS512, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
            nowSeconds + 100, BORING_CLAIMS));
    return "Passed";
  }

  public String testInvalidStructureNotThreeParts() throws TestFailure {
    try {
      useToken("a.b");
      throw new TestFailure("Fail, accepted \"a.b\")");
    } catch (IllegalArgumentException ex) {
    }
    try {
      useToken("a.b.c.d");
      throw new TestFailure("Fail, accepted \"a.b.c.d\")");
    } catch (IllegalArgumentException ex) {
    }
    try {
      useToken("a.b.c.d.e");
      throw new TestFailure("Fail, accepted \"a.b.c.d.e\")");
    } catch (IllegalArgumentException ex) {
    }
    try {
      useToken("a.b.c.d.e.f");
      throw new TestFailure("Fail, accepted \"a.b.c.d.e.f\")");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidStructureFirstPartNotBase64() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setBreakHeader(true);
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with non-base64 header");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidStructureSecondPartNotBase64() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setBreakPayload(true);
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with non-base64 claims");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidStructureThirdPartNotBase64() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setBreakSignature(true);
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with non-base64 structure");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidStructureFirstPartNotJson() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setHeaderNotJson(true);
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with non-JSON header");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidStructureSecondPartNotJson() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setPayloadNotJson(true);
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, getKeyId(), getIssuer(), "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with non-JSON claims");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testAlgorithmNone() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.none, null, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with no algorithm");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testAlgorithmES512() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.ES512, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with no ES512 algorithm");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testAlgorithmHS512() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.HS512, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with no ES512 algorithm");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testInvalidSignature() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setInvalidSignature(true);
    prepTest(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with invalid signature");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testKeyNotInJwksOutput() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder().setInvalidKid(true);
    prepTest(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with key that isn't in JWKS");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  private int inc(int val) {
    if (val < 10) {
      return 1;
    } else if (val < 100) {
      return 10;
    } else {
      return 100;
    }
  }

  public String testNoExpPermitted() throws Exception, TestFailure {
    if (requiresExp()) {
      TokenBuilder builder = createTokenBuilder();
      prepTest(builder);

      String kid = UUID.randomUUID().toString();
      long nowSeconds = System.currentTimeMillis() / 1000;
      try {
        useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
                null, BORING_CLAIMS));
        throw new TestFailure("Fail, accepted token with no exp");
      } catch (IllegalArgumentException ex) {
        return "Passed";
      }
    } else {
      return "Skipped";
    }
  }

  public String testExpInThePast() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();

    int acceptable = 0;
    for (int i = 0; i < 4000; i += inc(i)) {
      try {
        long nowSeconds = System.currentTimeMillis() / 1000;
        useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds,
                nowSeconds - i, BORING_CLAIMS));
        acceptable = i;
      } catch (IllegalArgumentException ex) {
        logger.debug(ex.getMessage());
        break;
      }
    }
    if (acceptable > 60) {
      throw new TestFailure("Fail, accepted tokens " + acceptable + " seconds past their exp time");
    } else if (acceptable == 0) {
      return "Passed";
    } else {
      return "Passed, accepted tokens " + acceptable + " seconds past their exp time";
    }
  }

  public String testNoNbfPermitted() throws Exception, TestFailure {
    if (requiresNbf()) {
      TokenBuilder builder = createTokenBuilder();
      prepTest(builder);

      String kid = UUID.randomUUID().toString();
      long nowSeconds = System.currentTimeMillis() / 1000;
      try {
        useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), null,
                nowSeconds + 100, BORING_CLAIMS));
        throw new TestFailure("Fail, accepted token with no nbf");
      } catch (IllegalArgumentException ex) {
        return "Passed";
      }
    } else {
      return "Skipped";
    }
  }

  public String testNbfInTheFuture() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();

    int acceptable = 0;
    for (int i = 0; i < 4000; i += inc(i)) {
      try {
        long nowSeconds = System.currentTimeMillis() / 1000;
        useToken(
                builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList(getAud()), nowSeconds + i,
                        nowSeconds, BORING_CLAIMS));
        acceptable = i;
      } catch (IllegalArgumentException ex) {
        logger.debug(ex.getMessage());
        break;
      }
    }
    if (acceptable > 60) {
      throw new TestFailure("Fail, accepted tokens " + acceptable + " seconds before their nbf time");
    } else if (acceptable == 0) {
      return "Passed";
    } else {
      return "Passed, accepted tokens " + acceptable + " seconds before their nbf time";
    }
  }

  public String testBadIssAccepted() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, "http://www.microsoft.com/", "sub", Arrays.asList(getAud()),
              nowSeconds, nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with invalid issuer");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testBadAudAccepted() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();

    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", Arrays.asList("bad"), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with bad audience");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

  public String testAudNotAcceptedAsSingleElementArray() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    JsonArray aud = new JsonArray();
    aud.add(getAud());
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", null, nowSeconds, nowSeconds + 100,
              claimsWithAud));
      return "Passed";
    } catch (IllegalArgumentException ex) {
      throw new TestFailure("Fail, did not accept token with aud = " + aud);
    }
  }

  public String testAudNotAcceptedAsSingleValue() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put("aud", getAud())
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", null, nowSeconds, nowSeconds + 100,
              claimsWithAud));
      return "Passed";
    } catch (IllegalArgumentException ex) {
      throw new TestFailure("Fail, did not accept token with aud = \"aud\"");
    }
  }

  public String testAudNotAcceptedAsFirstElementOfArray() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    JsonArray aud = new JsonArray();
    aud.add(getAud());
    aud.add("bob");
    aud.add("carol");
    aud.add("ted");
    aud.add("ringo");
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put(getAud(), aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", null, nowSeconds, nowSeconds + 100,
              claimsWithAud));
      return "Passed";
    } catch (IllegalArgumentException ex) {
      throw new TestFailure("Fail, did not accept token with aud = " + aud);
    }
  }

  public String testAudNotAcceptedAsLastElementOfArray() throws Exception, TestFailure {
    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    JsonArray aud = new JsonArray();
    aud.add("bob");
    aud.add("carol");
    aud.add("ted");
    aud.add("ringo");
    aud.add(getAud());
    Map<String, Object> claimsWithAud = ImmutableMap.<String, Object>builder()
            .put(getAud(), aud)
            .put("email", "bob@")
            .put("given_name", "tester")
            .build();

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), "sub", null, nowSeconds, nowSeconds + 100,
              claimsWithAud));
      return "Passed";
    } catch (IllegalArgumentException ex) {
      throw new TestFailure("Fail, did not accept token with aud = " + aud);
    }

  }

  public String testNoSubAccepted() throws Exception, TestFailure {

    TokenBuilder builder = createTokenBuilder();
    prepTest(builder);

    String kid = UUID.randomUUID().toString();
    long nowSeconds = System.currentTimeMillis() / 1000;
    try {
      useToken(builder.buildToken(JsonWebAlgorithm.RS256, kid, getIssuer(), null, Arrays.asList(getAud()), nowSeconds,
              nowSeconds + 100, BORING_CLAIMS));
      throw new TestFailure("Fail, accepted token with no sub");
    } catch (IllegalArgumentException ex) {
    }
    return "Passed";
  }

}
