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

import io.vertx.core.json.JsonObject;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.impl.ECJwkBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.impl.EdECJwkBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.impl.RSAJwkBuilder;

/**
 * The JwkBuilder class is an SPI for containing the algorithm-specific conversions from Token to JWK or from JSON to JWK.
 * 
 * @author jtalbut
 */
public abstract class JwkBuilder {
  
  private static final Logger logger = LoggerFactory.getLogger(JwkBuilder.class);
  
  private static final List<JwkBuilder> BUILDERS = Arrays.<JwkBuilder>asList(
          new RSAJwkBuilder()
          , new EdECJwkBuilder()
          , new ECJwkBuilder()
  );

  /**
   * Get the appropriate builder for the given public key.
   * @param publicKey The public key whose builder is being sought.
   * @return A JwkBuilder able to work with the given public key.
   * @throws IllegalArgumentException if now builder can be found for the provided key.
   */
  public static JwkBuilder get(PublicKey publicKey) {
    for (JwkBuilder builder : BUILDERS) {
      if (builder.canHandleKey(publicKey)) {
        return builder;
      }
    }
    throw new IllegalArgumentException("Key cannot be handled");
  }
  
  /**
   * Protected constructor used by subclasses.
   */
  protected JwkBuilder() {
  }
  
  /**
   * Instance of a {@link java.util.Base64.Encoder} for encoding values used in JWK JSON.
   * Used when creating JSON for implementations of {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder#toJson(java.lang.String, java.lang.String, java.security.PublicKey)}.
   */
  protected static final Base64.Encoder B64ENCODER = Base64.getUrlEncoder().withoutPadding();

  /**
   * Return true if the builder can create a JWK by generating JSON for the given PublicKey.
   * @param key The key that that this builder is being asked about.
   * @return true if the builder can create a JWK by generating JSON for the given PublicKey.
   */
  public abstract boolean canHandleKey(PublicKey key);
  
  /**
   * Convert the given public key into a valid JWK JSON representation.
   * @param kid The ID for the key.
   * @param algorithm The algorithm to be used with the key.
   * @param publicKey The public key.
   * @return The JWK representation of the key,
   * @throws InvalidParameterSpecException if the security subsystem does so.
   * @throws NoSuchAlgorithmException if the security subsystem does so.
   */
  public abstract JsonObject toJson(String kid, String algorithm, PublicKey publicKey) throws InvalidParameterSpecException, NoSuchAlgorithmException;
  
}
