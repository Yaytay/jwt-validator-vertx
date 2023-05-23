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
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import uk.co.spudsoft.jwtvalidatorvertx.impl.JwtValidatorVertxImpl;

/**
 * Validate JWTs, obtaining keys via OpenID Discovery is necessary.
 * @author jtalbut
 */
public interface JwtValidatorVertx {
  
  /**
   * Create a JwtValidatorVertx.
   * 
   * @param vertx The Vertx instance that will be used for asynchronous communication with JWKS endpoints.
   * @param issuerAcceptabilityHandler The object used to determine the acceptability of issuers.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * @return A newly created JwtValidatorVertx.
   */
  static JwtValidatorVertx create(Vertx vertx, IssuerAcceptabilityHandler issuerAcceptabilityHandler, Duration defaultJwkCacheDuration) {
    JsonWebKeySetHandler openIdDiscoveryHandler = JsonWebKeySetOpenIdDiscoveryHandler.create(WebClient.create(vertx), issuerAcceptabilityHandler, defaultJwkCacheDuration);
    return create(openIdDiscoveryHandler);
  }

  /**
   * Create a JwtValidatorVertx.
   * 
   * @param jsonWebKeySetHandler The JsonWebKeySet handler used for OpenID discovery and JWK Set discovery.
   * @return A newly created JwtValidatorVertx.
   */
  static JwtValidatorVertx create(JsonWebKeySetHandler jsonWebKeySetHandler) {
    return new JwtValidatorVertxImpl(jsonWebKeySetHandler);
  }

  /**
   * Get a copy of the current set of permitted algorithms.
   * @return a copy of the current set of permitted algorithms.
   */
  EnumSet<JsonWebAlgorithm> getPermittedAlgorithms();
  
  /**
   * Replace the current set of permitted algorithms with a new set.
   * @param algorithms The new set of permitted algorithms.
   * @return this for fluent configuration.
   */
  JwtValidatorVertx setPermittedAlgorithms(EnumSet<JsonWebAlgorithm> algorithms);
  
  /**
   * Add a single algorithm to the current set of permitted algorithms.
   * @param algorithm The algorithm to add to the current set of permitted algorithms.
   * @return this for fluent configuration.
   */
  JwtValidatorVertx addPermittedAlgorithm(JsonWebAlgorithm algorithm);
  
  /**
   * Set to true if the token is required to have an exp claim.
   * @param requireExp true if the token is required to have an exp claim.
   * @return this for fluent configuration.
   */
  JwtValidatorVertx setRequireExp(boolean requireExp);

  /**
   * Set to true if the token is required to have an nbf claim.
   * @param requireNbf true if the token is required to have an nbf claim.
   * @return this for fluent configuration.
   */
  JwtValidatorVertx setRequireNbf(boolean requireNbf);

  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param timeLeewaySeconds the maximum amount of time that can pass between the exp and now.
   * @return this for fluent configuration.
   */
  JwtValidatorVertx setTimeLeewaySeconds(long timeLeewaySeconds);

  /**
   * Validate the token and either throw an exception or return it's constituent parts.
   * @param token             The token.
   * @param requiredAudList   List of audiences, all of which must be claimed by the token. 
   * @param ignoreRequiredAud Do not check for required audiences.
   * @return The token's parts.
   */
  Future<JWT> validateToken(String token, List<String> requiredAudList, boolean ignoreRequiredAud);

}
