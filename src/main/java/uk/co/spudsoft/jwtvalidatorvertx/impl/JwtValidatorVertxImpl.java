package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import io.vertx.core.Future;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWS;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import static java.util.Objects.requireNonNull;
import java.util.Set;
import uk.co.spudsoft.jwtvalidatorvertx.IssuerAcceptabilityHandler;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler;
import uk.co.spudsoft.jwtvalidatorvertx.Jwt;
import uk.co.spudsoft.jwtvalidatorvertx.JwtValidator;

/**
 * Token validation for vertx - implementation of {@link uk.co.spudsoft.jwtvalidatorvertx.JwtValidator}.
 * @author Jim Talbut
 */
public class JwtValidatorVertxImpl implements JwtValidator {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JwtValidatorVertxImpl.class);

  private static final Base64.Decoder B64DECODER = Base64.getUrlDecoder();
  
  private static final Set<String> DEFAULT_PERMITTED_ALGS = ImmutableSet.of(
          JWS.EdDSA

          , JWS.ES256
          , JWS.ES384
          , JWS.ES512

          , JWS.PS256
          , JWS.PS384
          , JWS.PS512

          , JWS.ES256K

          , JWS.RS256
          , JWS.RS384
          , JWS.RS512
  );
  
  private Set<String> permittedAlgs;
  
  private boolean requireExp = true;
  private boolean requireNbf = true;
  
  private long timeLeewayMilliseconds = 0;
  private long minimumKeyCacheLifetime = 0;
  
  private final JsonWebKeySetHandler jsonWebKeySetHandler;
  private final IssuerAcceptabilityHandler issuerAcceptabilityHandler;
  
  /**
   * Constructor.
   * @param jsonWebKeySetHandler         Handler for obtaining JWKs
   * @param issuerAcceptabilityHandler   Handler for validating issuers found in the JWT.
   */
  public JwtValidatorVertxImpl(JsonWebKeySetHandler jsonWebKeySetHandler, IssuerAcceptabilityHandler issuerAcceptabilityHandler) {
    this.jsonWebKeySetHandler = jsonWebKeySetHandler;
    this.issuerAcceptabilityHandler = issuerAcceptabilityHandler;
    this.permittedAlgs = new HashSet<>(DEFAULT_PERMITTED_ALGS);
  }

  @Override
  public Set<String> getPermittedAlgorithms() {
    return ImmutableSet.copyOf(permittedAlgs);
  }

  @Override
  public JwtValidator setPermittedAlgorithms(Set<String> algorithms) throws NoSuchAlgorithmException {
    Set<String> copy = new HashSet<>();
    for (String alg : algorithms) {
      if (!DEFAULT_PERMITTED_ALGS.contains(alg)) {
        throw new NoSuchAlgorithmException();
      } else {
        copy.add(alg);
      }
    }
    this.permittedAlgs = copy;
    return this;
  }

  @Override
  public JwtValidator addPermittedAlgorithm(String algorithm) throws NoSuchAlgorithmException {
    if (!DEFAULT_PERMITTED_ALGS.contains(algorithm)) {
      throw new NoSuchAlgorithmException();
    } else {
      permittedAlgs.add(algorithm);
    }
    return this;
  }
  
  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param timeLeeway the maximum amount of time that can pass between the exp and now.
   */
  @Override
  public JwtValidator setTimeLeeway(Duration timeLeeway) {
    this.timeLeewayMilliseconds = timeLeeway.toMillis();
    return this;
  }

  /**
   * Set the minimum amount of time that JWKs (and OpenID Discovery data) will be cached for.
   * @param minKeyCacheLifetime the minimum amount of time that JWKs (and OpenID Discovery data) will be cached for.
   */
  @Override
  public JwtValidator setMinimumKeyCacheLifetime(Duration minKeyCacheLifetime) {
    this.minimumKeyCacheLifetime = minKeyCacheLifetime.toMillis();
    return this;
  }

  /**
   * Set to true if the token is required to have an exp claim.
   * @param requireExp true if the token is required to have an exp claim.
   */
  @Override
  public JwtValidator setRequireExp(boolean requireExp) {
    this.requireExp = requireExp;
    return this;
  }

  /**
   * Set to true if the token is required to have an nbf claim.
   * @param requireNbf true if the token is required to have an nbf claim.
   */
  @Override
  public JwtValidator setRequireNbf(boolean requireNbf) {
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
  public Future<Jwt> validateToken(
          String issuer
          , String token
          , List<String> requiredAudList
          , boolean ignoreRequiredAud
  ) {
    
    Jwt jwt;
    try {
      jwt = Jwt.parseJws(token);
    } catch (Throwable ex) {
      if (logger.isTraceEnabled()) {
        logger.error("Parse of JWT ({}) failed: ", token, ex);
      } else {
        logger.error("Parse of JWT failed: ", ex);
      }
      return Future.failedFuture(new IllegalArgumentException("Parse of signed JWT failed", ex));
    }

    try {
      validateAlgorithm(jwt.getAlgorithm());
      String kid = jwt.getKid();

      if (jwt.getPayloadSize() == 0) {
        logger.error("No payload claims found in JWT");
        return Future.failedFuture(new IllegalArgumentException("Parse of signed JWT failed"));
      }

      return jsonWebKeySetHandler.findJwk(issuer, kid)
              .onFailure(ex -> {
                logger.warn("Failed to find JWK for {} ({}): ", kid, issuer, ex);
              })
              .compose(jwk -> {
                try {
                  verify(jwk, jwt);

                  long now = System.currentTimeMillis();
                  validateIssuer(jwt, issuer);
                  validateNbf(jwt, now);
                  validateExp(jwt, now);
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

  private void validateIssuer(Jwt jwt, String externalIssuer) {
    String tokenIssuer = jwt.getIssuer();

    // empty issuer is never allowed
    if (Strings.isNullOrEmpty(tokenIssuer)) {
      throw new IllegalStateException("No issuer in token.");
    }
    
    if (!issuerAcceptabilityHandler.isAcceptable(tokenIssuer)) {
      throw new IllegalStateException("Issuer from token (" + tokenIssuer + ") is not acceptable.");
    }
    
    if (externalIssuer != null) {
      if (!externalIssuer.equals(tokenIssuer)) {
        throw new IllegalStateException("Issuer from token (" + tokenIssuer + ") does not match expected issuer (" + externalIssuer + ").");
      }
    }
  }
  
  private void verify(JWK jwk, Jwt jwt) throws IllegalArgumentException {

    // empty signature is never allowed
    if (Strings.isNullOrEmpty(jwt.getSignature())) {
      throw new IllegalStateException("No signature in token.");
    }

    requireNonNull(jwk, "JWK not set");
    
    // if we only allow secure alg, then none is not a valid option
    if ("none".equals(jwk.getAlgorithm())) {
      throw new IllegalStateException("Algorithm \"none\" not allowed");
    }

    byte[] payloadInput = B64DECODER.decode(jwt.getSignature());

    byte[] signingInput = jwt.getSignatureBase().getBytes(StandardCharsets.UTF_8);

    try {
      JWS jws = new JWS(jwk);
      if (!jws.verify(payloadInput, signingInput)) {
        throw new IllegalArgumentException("Signature verification failed");
      }
    } catch (Throwable ex) {
      logger.warn("Signature verification failed: ", ex);
      throw new IllegalArgumentException("Signature verification failed", ex);
    }
  }

  private void validateSub(Jwt jwt) throws IllegalArgumentException {
    if (Strings.isNullOrEmpty(jwt.getSubject())) {
      throw new IllegalArgumentException("No subject specified in token");
    }
  }

  private void validateAud(Jwt jwt, List<String> requiredAudList, boolean ignoreRequiredAud) throws IllegalArgumentException {
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

  private void validateExp(Jwt jwt, long now) throws IllegalArgumentException {
    if (jwt.getExpiration() != null) {
      long targetMs = now - timeLeewayMilliseconds;
      if (1000 * jwt.getExpiration() < targetMs) {
        logger.warn("Token exp = {} ({}), now = {} ({}), target = {} ({})", jwt.getExpiration(), jwt.getExpirationLocalDateTime(), now, LocalDateTime.ofInstant(Instant.ofEpochMilli(now), ZoneOffset.UTC), targetMs, LocalDateTime.ofInstant(Instant.ofEpochMilli(targetMs), ZoneOffset.UTC));
        throw new IllegalArgumentException("Token is not valid after " + jwt.getExpirationLocalDateTime());
      }
    } else if (requireExp) {
      throw new IllegalArgumentException("Token does not specify exp");
    }
  }

  private void validateNbf(Jwt jwt, long now) throws IllegalArgumentException {
    if (jwt.getNotBefore() != null) {
      long targetMs = now + timeLeewayMilliseconds;
      if (1000 * jwt.getNotBefore() > targetMs) {
        logger.warn("Token nbf = {} ({}), now = {} ({}), target = {} ({})", jwt.getNotBefore(), jwt.getNotBeforeLocalDateTime(), now, LocalDateTime.ofInstant(Instant.ofEpochMilli(now), ZoneOffset.UTC), targetMs, LocalDateTime.ofInstant(Instant.ofEpochMilli(targetMs), ZoneOffset.UTC));
        throw new IllegalArgumentException("Token is not valid until " + jwt.getNotBeforeLocalDateTime());
      }
    } else if (requireNbf) {
      throw new IllegalArgumentException("Token does not specify exp");
    }
  }

  private void validateAlgorithm(String algorithm) throws IllegalArgumentException {
    if (algorithm == null) {
      logger.warn("No signature algorithm in token.");
      throw new IllegalArgumentException("Parse of signed JWT failed");
    }
    if (!permittedAlgs.contains(algorithm)) {
      logger.warn("Failed to find algorithm \"{}\" in {}", algorithm, permittedAlgs);
      throw new IllegalArgumentException("Parse of signed JWT failed");
    }
  }

}
