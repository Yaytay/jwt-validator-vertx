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
import io.vertx.ext.auth.impl.jose.JWK;
import javax.annotation.Nullable;

/**
 * Perform OpenID Connect discovery as per <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
 * @author jtalbut
 */
public interface JsonWebKeySetHandler {
  
  /**
   * Perform whatever initialization is required to get this handler working.
   * <P>
   * This is primarily intended to provide the opportunity for handlers to preload JWKs.
   * It shouldn't matter whether or not the preload has completed, hence this method returns void 
   * and it is expected that processing continues in the background.
   */
  void optimize();
 
  /**
   * Find a JWK for the given issuer and kid.
   * 
   * A specific implementation of JsonWebKeySetHandler will either require the issuer to be null, or not null.
   * The issuer should never be extracted from the payload of a JWT for the purpose of finding the JWK.
   * 
   * If the client has a mechanism for knowing the issuer of the token it can work with a greater number of issuers,
   * if the client is not able to determine the issuer for a token (before validation) then it must maintain a cache of the keys
   * for all known JWK sets.
   * 
   * @param issuer the issuer of the JWT (and JWK).
   * @param kid The key ID being sought.
   * @return A Future that will be completed with a JWK.
   */
  Future<JWK> findJwk(@Nullable String issuer, String kid);
  
}
