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

import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.Collection;
import uk.co.spudsoft.jwtvalidatorvertx.impl.JWKSStaticSetHandlerImpl;

/**
 * Manage JWKs manually.
 * 
 * It is not usually necessary to use this interface for anything other than the Factory methods.
 * 
 * @author jtalbut
 */
public interface JsonWebKeySetKnownJwksHandler extends JsonWebKeySetHandler {
  
  /**
   * Construct an instance of the implementation class.
   * 
   * With a static map of JWKs the security of the system is not compromised by allowing any issuer, though you should question why this is necessary (so still avoid overly permissive acceptable issuer regexes).
   * 
   * Each JWKs endpoint must use KIDs that are globally unique.
   * 
   * When a KID is requested and cannot be found ALL the configured JWKS URLs will be queried and the single cache will be updated.
   * Entries in the cache will be retained for a duration based on either the Cache-Control max-age header of the response or, 
   * if that is not present, the defaultJwkCacheDuration.
   * Given that only positive responses are cached it is reasonable for the defaultJwkCacheDuration to be 24 hours (or more).
   * 
   * @param webClient Vertx WebClient instance, that will be used for querying the JWKS URLs.
   * @param jwksUrls Static set of URLs that will be used for obtaining JWKs.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * @return a newly created instance of the implementation class.
   * 
   * The JWKS URLs must be accessed via https for the environment to offer any security.
   * This is not enforced at the code level.
   * 
   */
  static JsonWebKeySetKnownJwksHandler create(WebClient webClient, Collection<String> jwksUrls, Duration defaultJwkCacheDuration) {
    return new JWKSStaticSetHandlerImpl(webClient, jwksUrls, defaultJwkCacheDuration);
  }
  
}
