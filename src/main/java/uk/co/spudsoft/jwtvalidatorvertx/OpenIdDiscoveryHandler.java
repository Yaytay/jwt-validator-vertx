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

/**
 * Interface for obtaining the OpenID Discovery Data for an issuer.
 * @author jtalbut
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
 */
public interface OpenIdDiscoveryHandler {
  
  /**
   * Obtain the discovery data for an issuer as per <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
   * 
   * If discovery data has not already been cached this will result in a call to 
   * <pre>
   * issuer + (issuer.endsWith("/") ? "" : "/") + ".well-known/openid-configuration"
   * </pre>
   * 
   * The resulting Discovery Data will be cached against the issuer.
   * 
   * @param issuer The issuer to obtain the discovery data for.
   * @return A Future that will be completed with the Discovery Data.
   */
  Future<DiscoveryData> performOpenIdDiscovery(String issuer);
    
}
