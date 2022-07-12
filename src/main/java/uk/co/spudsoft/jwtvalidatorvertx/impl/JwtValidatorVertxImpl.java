package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.google.common.base.Strings;
import io.vertx.core.Future;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JWK;
import uk.co.spudsoft.jwtvalidatorvertx.JWT;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;

import java.util.EnumSet;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler;
import uk.co.spudsoft.jwtvalidatorvertx.JwtValidatorVertx;

/**
 * Token validation for vertx - implementation of {@link uk.co.spudsoft.jwtvalidatorvertx.JwtValidatorVertx}.
 * @author Jim Talbut
 */
public class JwtValidatorVertxImpl implements JwtValidatorVertx {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JwtValidatorVertxImpl.class);

  private static final Base64.Decoder B64DECODER = Base64.getUrlDecoder();
  
  private static final EnumSet<JsonWebAlgorithm> DEFAULT_PERMITTED_ALGS = EnumSet.of(
          JsonWebAlgorithm.RS256, JsonWebAlgorithm.RS384, JsonWebAlgorithm.RS512
  );
  
  private EnumSet<JsonWebAlgorithm> permittedAlgs;
  
  private boolean requireExp = true;
  private boolean requireNbf = true;
  
  private long timeLeewaySeconds = 0;
  
  private final JsonWebKeySetHandler openIdDiscoveryHandler;
  
  /**
   * Constructor.
   * @param openIdDiscoveryHandler         Handler for obtaining OpenIdDiscovery data and JWKs
   */
  public JwtValidatorVertxImpl(JsonWebKeySetHandler openIdDiscoveryHandler) {
    this.openIdDiscoveryHandler = openIdDiscoveryHandler;
    this.permittedAlgs = EnumSet.copyOf(DEFAULT_PERMITTED_ALGS);
  }

  @Override
  public EnumSet<JsonWebAlgorithm> getPermittedAlgorithms() {
    return EnumSet.copyOf(permittedAlgs);
  }

  @Override
  public JwtValidatorVertx setPermittedAlgorithms(EnumSet<JsonWebAlgorithm> algorithms) {
    this.permittedAlgs = EnumSet.copyOf(algorithms);
    return this;
  }

  @Override
  public JwtValidatorVertx addPermittedAlgorithm(JsonWebAlgorithm algorithm) {
    this.permittedAlgs.add(algorithm);
    return this;
  }
  
  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param timeLeewaySeconds the maximum amount of time that can pass between the exp and now.
   */
  @Override
  public JwtValidatorVertx setTimeLeewaySeconds(long timeLeewaySeconds) {
    this.timeLeewaySeconds = timeLeewaySeconds;
    return this;
  }

  /**
   * Set to true if the token is required to have an exp claim.
   * @param requireExp true if the token is required to have an exp claim.
   */
  @Override
  public JwtValidatorVertx setRequireExp(boolean requireExp) {
    this.requireExp = requireExp;
    return this;
  }

  /**
   * Set to true if the token is required to have an nbf claim.
   * @param requireNbf true if the token is required to have an nbf claim.
   */
  @Override
  public JwtValidatorVertx setRequireNbf(boolean requireNbf) {
    this.requireNbf = requireNbf;
    return this;
  }
  
  /**
   * Validate the token and either throw an exception or return it's constituent parts.
   * @param token             The token.
   * @param requiredAudList   List of audiences, all of which must be claimed by the token. If null the defaultRequiredAud is used.
   * @param ignoreRequiredAud Do not check for required audiences.
   * @return The token's parts.
   */
  @Override
  public Future<JWT> validateToken(
          String token
          , List<String> requiredAudList
          , boolean ignoreRequiredAud
  ) {
    
    JWT jwt;
    try {
      jwt = JWT.parseJws(token);
    } catch (Throwable ex) {
      logger.error("Parse of JWT failed: ", ex);
      return Future.failedFuture(new IllegalArgumentException("Parse of signed JWT failed", ex));
    }

    try {
      JsonWebAlgorithm jwa = validateAlgorithm(jwt.getAlgorithm());
      jwt.getKid();

      if (jwt.getPayloadSize() == 0) {
        logger.error("No payload claims found in JWT");
        return Future.failedFuture(new IllegalArgumentException("Parse of signed JWT failed"));
      }
      String issuer = jwt.getIssuer();

      openIdDiscoveryHandler.validateIssuer(issuer);

      return jwt.getJwk(openIdDiscoveryHandler)
              .compose(jwk -> {
                try {
                  verify(jwa, jwk, jwt);

                  long nowSeconds = System.currentTimeMillis() / 1000;
                  validateNbf(jwt, nowSeconds);
                  validateExp(jwt, nowSeconds);
                  validateAud(jwt, requiredAudList, ignoreRequiredAud);
                  validateSub(jwt);

                  return Future.succeededFuture(jwt);
                } catch (Throwable ex) {
                  logger.info("Validation of {} token failed: ", jwt.getAlgorithm(), ex);
                  return Future.failedFuture(new IllegalArgumentException("Validation of " + jwt.getAlgorithm() + " signed JWT failed", ex));
                }
              });
    } catch (Throwable ex) {
      logger.error("Failed to process token: ", ex);
      return Future.failedFuture(ex);
    }
  }

  private void verify(JsonWebAlgorithm jwa, JWK<?> jwk, JWT jwt) throws IllegalArgumentException {

    // empty signature is never allowed
    if (Strings.isNullOrEmpty(jwt.getSignature())) {
      throw new IllegalStateException("No signature in token.");
    }

    // if we only allow secure alg, then none is not a valid option
    if (JsonWebAlgorithm.none == jwa) {
      throw new IllegalStateException("Algorithm \"none\" not allowed");
    }

    byte[] payloadInput = B64DECODER.decode(jwt.getSignature());

    byte[] signingInput = jwt.getSignatureBase().getBytes(StandardCharsets.UTF_8);

    try {
      if (!jwk.verify(jwa, payloadInput, signingInput)) {
        throw new IllegalArgumentException("Signature verification failed");
      }
    } catch (Throwable ex) {
      logger.warn("Signature verification failed: ", ex);
      throw new IllegalArgumentException("Signature verification failed", ex);
    }
  }

  private void validateSub(JWT jwt) throws IllegalArgumentException {
    if (Strings.isNullOrEmpty(jwt.getSubject())) {
      throw new IllegalArgumentException("No subject specified in token");
    }
  }

  private void validateAud(JWT jwt, List<String> requiredAudList, boolean ignoreRequiredAud) throws IllegalArgumentException {
    if ((requiredAudList == null) || (!ignoreRequiredAud && requiredAudList.isEmpty())) {
      throw new IllegalStateException("Required audience not set");
    }
    if (jwt.getAudience() == null) {
      throw new IllegalArgumentException("Token does not include aud claim");
    }
    for (String aud : jwt.getAudience()) {
      for (String requiredAud : requiredAudList) {
        if (requiredAud.equals(aud)) {
          return;
        }
      }
    }
    if (!ignoreRequiredAud) {
      if (requiredAudList.size() == 1) {
        logger.warn("Required audience ({}) not found in token aud claim: {}", requiredAudList.get(0), jwt.getAudience());
      } else {
        logger.warn("None of the required audiences ({}) found in token aud claim: {}", requiredAudList, jwt.getAudience());
      }
      throw new IllegalArgumentException("Required audience not found in token");
    }
  }

  private void validateExp(JWT jwt, long nowSeconds) throws IllegalArgumentException {
    if (jwt.getExpiration() != null) {
      long target = nowSeconds - timeLeewaySeconds;
      if (jwt.getExpiration() < target) {
        logger.warn("Token exp = {} ({}), now = {} ({}), target = {} ({})", jwt.getExpiration(), jwt.getExpirationLocalDateTime(), nowSeconds, LocalDateTime.ofEpochSecond(nowSeconds, 0, ZoneOffset.UTC), target, LocalDateTime.ofEpochSecond(target, 0, ZoneOffset.UTC));
        throw new IllegalArgumentException("Token is not valid after " + jwt.getExpirationLocalDateTime());
      }
    } else if (requireExp) {
      throw new IllegalArgumentException("Token does not specify exp");
    }
  }

  private void validateNbf(JWT jwt, long nowSeconds) throws IllegalArgumentException {
    if (jwt.getNotBefore() != null) {
      long target = nowSeconds + timeLeewaySeconds;
      if (jwt.getNotBefore() > target) {
        throw new IllegalArgumentException("Token is not valid until " + jwt.getNotBeforeLocalDateTime());
      }
    } else if (requireNbf) {
      throw new IllegalArgumentException("Token does not specify exp");
    }
  }

  private JsonWebAlgorithm validateAlgorithm(String algorithm) {
    if (algorithm == null) {
      logger.warn("No signature algorithm in token.");
      throw new IllegalArgumentException("Parse of signed JWT failed");
    }
    JsonWebAlgorithm jwa;
    try {
      jwa = JsonWebAlgorithm.valueOf(algorithm);
    } catch (Throwable ex) {
      logger.warn("Failed to parse algorithm \"{}\"", algorithm);
      throw new IllegalArgumentException("Parse of signed JWT failed");
    }
    if (!permittedAlgs.contains(jwa)) {
      logger.warn("Failed to find algorithm \"{}\" in {}", algorithm, permittedAlgs);
      throw new IllegalArgumentException("Parse of signed JWT failed");
    }
    return jwa;
  }

}
