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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JwkBuilder class is an SPI for containing the algorithm-specific conversions from Token to JWK or from JSON to JWK.
 * 
 * @author jtalbut
 * @param <T> The specific class on PublicKey that is created.
 */
public abstract class JwkBuilder<T extends PublicKey> {
  
  private static final Logger logger = LoggerFactory.getLogger(JwkBuilder.class);

  /**
   * Instance of a {@link java.util.Base64.Encoder} for encoding values used in JWK JSON.
   * Used when creating JSON for implementations of {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder#create(long, java.lang.String, java.security.PublicKey)}.
   */
  protected static final Base64.Encoder B64ENCODER = Base64.getUrlEncoder().withoutPadding();

  /**
   * Instance of a {@link java.util.Base64.Decoder} for decoding values found in JWK JSON.
   * Used when reading JSON for implementations of {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder#create(long, io.vertx.core.json.JsonObject) }.
   */
  protected static final Base64.Decoder B64DECODER = Base64.getUrlDecoder();
  
  
  /**
   * Confirm that any alg field specified in the JsonObject matches the family passed in.
   * 
   * There is no requirement for JWKs to specify an algorithm (most don't, in my experience), but if one is specified then it must be correct.
   * 
   * @param jo The JWK as a JsonObject that may, or may not, contain an alg field.
   * @param requiredFamily The family name (taken from {@link JsonWebAlgorithm#familyName}) that must match that for the algorithm
   * @throws IllegalArgumentException is the required family is not the family for the algorithm passed in.
   */
  protected void validateAlg(JsonObject jo, String requiredFamily) {
    // From RFC 7515 alg is optional and I haven't ever seen it in the wild.
    // If it is provided we just validate that it is compatible with the kty.
    String algString = jo.getString("alg");
    if (algString != null) {
      JsonWebAlgorithm alg = JsonWebAlgorithm.valueOf(algString);
      if (!requiredFamily.equals(alg.getFamilyName())) {
        String kty = jo.getString("kty");
        logger.warn("Algorithm ({}) does not match key type ({})", algString, kty);
        throw new IllegalArgumentException("Algorithm (" + algString + ") does not match key type (" + kty + ")");
      }
    }
  }
  
  /**
   * Create a JWK from a JSON.
   * 
   * This is expected to result in a call to the JWK constructor that takes in both the JSON and the PublicKey.
   * 
   * @param expiryMs The expiry time for the JWK.
   * This value is only relevant if the JWK is cached, it is not part of the JWK itself.
   * @param json The JSON representation of the JWK, as specified by RFC7517 (or one of its successors).
   * @return a newly created JWK object containing both JSON and JDK PublicKey.
   * @throws NoSuchAlgorithmException if the underlying JDK crypto subsystem cannot process this algorithm family.
   * @throws InvalidKeySpecException if the data in the JSON does not represent a valid key.
   * @throws InvalidParameterSpecException if the data in the JSON does not represent a valid key.
   * @throws IllegalArgumentException if the JSON is not in a valid form for this algorithm family.
   */
  public abstract JWK<T> create(long expiryMs, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException, IllegalArgumentException;
  
  /**
   * Create a JWK from a PublicKey.
   * 
   * This is expected to result in a call to the JWK constructor that takes in both the JSON and the PublicKey.
   * 
   * @param expiryMs The expiry time for the JWK.
   * This value is only relevant if the JWK is cached, it is not part of the JWK itself.
   * @param kid The ID to use in the JWK.
   * @param key The key to convert to JSON.
   * @return a newly created JWK object containing both JSON and JDK PublicKey.
   * @throws InvalidParameterSpecException if the data in the key does not represent a valid key (this should indicate a bug in this library).
   * @throws NoSuchAlgorithmException if the underlying JDK crypto subsystem cannot process this algorithm family.
   */
  public abstract JWK<T> create(long expiryMs, String kid, T key) throws InvalidParameterSpecException, NoSuchAlgorithmException;
  
}
