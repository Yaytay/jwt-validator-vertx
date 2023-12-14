/*
 * Copyright (C) 2022 jtalbut
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
package uk.co.spudsoft.jwtvalidatorvertx;

import io.vertx.core.Future;
import io.vertx.ext.web.client.WebClient;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;
import uk.co.spudsoft.jwtvalidatorvertx.impl.JwtValidatorVertxImpl;

/**
 * Validate JWTs.
 * 
 * There are two approaches that can be used for finding the keys necessary to validate the signature:
 * <UL>
 * <LI> The caller passes in the issuer, the validator performs OpenID Discovery to find the JWKS URL and then finds the keys from there.
 * <LI> The configuration of the validator specifies a number of JWKS URLs.
 * </UL>
 * <p>
 * The former configuration is appropriate when used in a SAAS application with many issuers, each of which has it's own JWKS.
 * If the validator is not being used in a SAAS application, or the issuers in a SAAS application share keys, then the second
 * approach is a lot more memory efficient.
 * <p>
 * An instance of JwtValidator can only support one of these two models, determined by the JwsonWebKeySetHandler that it uses (and you probably only want one JwtValidator in your service).
 * <p>
 * When a dynamic configuration is used the issuer acceptability must pass three steps:
 * <UL>
 * <LI>The issuer passed in to the JwtValidator must be non-null and acceptable.
 * <LI>The issuer found in the token must be non-null and acceptable.
 * <LI>The issuer passed in and the issuer in the token must be the same.
 * </UL>
 * <p>
 * With a static configuration the passed in issuer is optional, and thus the first and last steps may be skipped.
 * If an issuer is passed in to a static configuration all three steps will take place.
 * <p>
 * There are circumstances in which a client will want to use a static JwtValidator, but also to use the a {@link OpenIdDiscoveryHandler}.
 * This is OK, but the caching of JWKSs will not be shared between the two sides because there is a fundamental difference in requirements between the two.
 * When the OpenIdDiscoveryHandler is used to find JWKs the key IDs are specific to the issuer, but the static configuration requires all key IDs to be globally unique.
 * <p>
 * The WebClient passed in to create the JwtValidator does not have to be dedicated to it.
 * 
 * @author jtalbut
 */
public interface JwtValidator {
  
  /**
   * Create a JwtValidatorVertx that will use an OpenIdDiscoveryHandler to find JWKs from any acceptable issuer.
   * 
   * @param webClient The Vertx WebClient instance that will be used for asynchronous communication with JWKS endpoints.
   * @param issuerAcceptabilityHandler The object used to determine the acceptability of issuers.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * @return A newly created JwtValidatorVertx.
   */
  static JwtValidator createDynamic(WebClient webClient, IssuerAcceptabilityHandler issuerAcceptabilityHandler, Duration defaultJwkCacheDuration) {
    JsonWebKeySetHandler openIdDiscoveryHandler = JsonWebKeySetOpenIdDiscoveryHandler.create(webClient, issuerAcceptabilityHandler, defaultJwkCacheDuration);
    return create(openIdDiscoveryHandler, issuerAcceptabilityHandler);
  }
  
  /**
   * Create a JwtValidatorVertx that will use a fixed set of URLs for downloading JWKs.
   * 
   * @param webClient The Vertx WebClient instance that will be used for asynchronous communication with JWKS endpoints.
   * @param jwksEndpoints The object used to determine the acceptability of issuers.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * @param issuerAcceptabilityHandler The object used to determine the acceptability of issuers.
   * @return A newly created JwtValidatorVertx.
   */
  static JwtValidator createStatic(WebClient webClient, Collection<String> jwksEndpoints, Duration defaultJwkCacheDuration, IssuerAcceptabilityHandler issuerAcceptabilityHandler) {
    JsonWebKeySetHandler staticHandler = JsonWebKeySetKnownJwksHandler.create(webClient, jwksEndpoints, defaultJwkCacheDuration);
    return create(staticHandler, issuerAcceptabilityHandler);
  }

  /**
   * Create a JwtValidatorVertx.
   * 
   * @param jsonWebKeySetHandler The JsonWebKeySet handler used for OpenID discovery and JWK Set discovery.
   * @param issuerAcceptabilityHandler The object used to determine the acceptability of issuers.
   * @return A newly created JwtValidatorVertx.
   */
  static JwtValidator create(JsonWebKeySetHandler jsonWebKeySetHandler, IssuerAcceptabilityHandler issuerAcceptabilityHandler) {
    return new JwtValidatorVertxImpl(jsonWebKeySetHandler, issuerAcceptabilityHandler);
  }

  /**
   * Get a copy of the current set of permitted algorithms.
   * @return a copy of the current set of permitted algorithms.
   */
  Set<String> getPermittedAlgorithms();
  
  /**
   * Replace the current set of permitted algorithms with a new set.
   * @param algorithms The new set of permitted algorithms.
   * @return this for fluent configuration.
   * @throws NoSuchAlgorithmException if any of the algorithms passed in are not recognised.
   */
  JwtValidator setPermittedAlgorithms(Set<String> algorithms) throws NoSuchAlgorithmException;
  
  /**
   * Add a single algorithm to the current set of permitted algorithms.
   * @param algorithm The algorithm to add to the current set of permitted algorithms.
   * @return this for fluent configuration.
   * @throws NoSuchAlgorithmException if the algorithm passed is not recognised.
   */
  JwtValidator addPermittedAlgorithm(String algorithm) throws NoSuchAlgorithmException;
  
  
  
  /**
   * Set to true if the token is required to have an exp claim.
   * @param requireExp true if the token is required to have an exp claim.
   * @return this for fluent configuration.
   */
  JwtValidator setRequireExp(boolean requireExp);

  /**
   * Set to true if the token is required to have an nbf claim.
   * @param requireNbf true if the token is required to have an nbf claim.
   * @return this for fluent configuration.
   */
  JwtValidator setRequireNbf(boolean requireNbf);

  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param timeLeeway the maximum amount of time that can pass between the exp and now.
   * @return this for fluent configuration.
   */
  JwtValidator setTimeLeeway(Duration timeLeeway);

  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param minKeyCacheLifetime the minimum amount of time for which keys will be cached.
   * @return this for fluent configuration.
   */
  JwtValidator setMinimumKeyCacheLifetime(Duration minKeyCacheLifetime);

  /**
   * Validate the token and either return a failed Future or return a Future containing the JWT's constituent parts.
   * 
   * There are two ways in which keys can be located for token verification:
   * <ul>
   * <li>If the issuer is not null it will be used to perform OpenID Discovery to locate the JWKS and thus to download the key.
   * <li>If the issuer is null all of the configured JWKS endpoints will be queried to search for the key.
   * </ul>
   * In both cases the key will be cached according to the Cache-Control max-age parameter, or for at least the configured minKeyCacheLifetime.
   * In the case of a cache miss the JWKS endpoints (either configured or discovered) will always be requeried, so there isn't much harm in using a long key cache lifetime.
   * 
   * @param issuer            The token issuer.
   * @param token             The token.
   * @param requiredAudList   List of audiences, all of which must be claimed by the token. 
   * @param ignoreRequiredAud Do not check for required audiences.
   * @return The token's parts.
   */
  Future<Jwt> validateToken(@Nullable String issuer, String token, List<String> requiredAudList, boolean ignoreRequiredAud);

}
