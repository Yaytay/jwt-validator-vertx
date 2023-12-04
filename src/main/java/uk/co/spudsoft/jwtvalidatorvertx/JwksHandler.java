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

import com.google.common.cache.Cache;
import java.io.Closeable;

/**
 * Class for easily providing a JWKS endpoint.
 * <p>
 * The TokenBuilder was created (along with the {@link JwksHandler} to provide a simple way to test the JWT Validator.
 * <p>
 * The two can also be used to provide a simple OpenID Discovery server (which is why they are not in the test classes).
 * An OpenID server created using TokenBuilder and {@link JwksHandler} is not fully featured, but will suffice in some circumstances.
 *
 * @author jtalbut
 */
public interface JwksHandler extends Closeable {

  /**
   * Return the base URL that the JwksHandler is listening on.
   * This value may be used directly as the issuer claim in a token.
   * @return the base URL that the JwksHandler is listening on. 
   */
  String getBaseUrl();

  /**
   * Set the key cache that the JwksHandler should use.
   * In production use this method should be called once, in a test environment it may be called repeatedly.
   * A JwksHandler must only access the keyCache (or anything derived from it) whilst serving an HTTP request.
   * Between requests the JwkHandler may only hold a reference to the keyCache.
   * @param keyCache the key cache that the JwksHandler should use.
   */
  void setKeyCache(Cache<String, AlgorithmAndKeyPair> keyCache);
  
  /**
   * Start listening.
   */
  void start();
  
}
