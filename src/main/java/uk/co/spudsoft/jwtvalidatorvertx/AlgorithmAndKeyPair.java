/*
 * Copyright (C) 2023 jtalbut
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
import com.google.common.cache.CacheBuilder;
import java.security.KeyPair;
import java.time.Duration;

/**
 * Associated the algorithm with a {@link java.security.KeyPair}. The keys for some algorithms (like RSA) can be used for
 * different types of JWS algorithms (i.e. RS512 and RS256 use the same size RSA keys). In order for the token builder to work
 * with the {@link uk.co.spudsoft.jwtvalidatorvertx.JwksHandler}
 */
public class AlgorithmAndKeyPair {

  private final JsonWebAlgorithm algorithm;
  private final KeyPair keyPair;

  /**
   * Create a guava cache with a configured key lifetime.
   * @param keyLifetime The value to use for the expireAfterWrite setting.
   * @return a guava cache with a configured key lifetime.
   */
  public static Cache<String, AlgorithmAndKeyPair> createCache(Duration keyLifetime) {
    return CacheBuilder.newBuilder()
            .expireAfterWrite(keyLifetime)
            .build();
  }
    
  /**
   * Constructor.
   *
   * @param algorithm The algorithm to use with this key.
   * @param keyPair The key pair.
   */
  public AlgorithmAndKeyPair(JsonWebAlgorithm algorithm, KeyPair keyPair) {
    this.algorithm = algorithm;
    this.keyPair = keyPair;
  }

  /**
   * Get the algorithm to use with this key.
   * @return the algorithm to use with this key.
   */
  public JsonWebAlgorithm getAlgorithm() {
    return algorithm;
  }

  /**
   * Get the KeyPair.
   * @return the KeyPair.
   */
  public KeyPair getKeyPair() {
    return keyPair;
  }
}
