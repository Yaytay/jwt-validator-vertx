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
package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.google.common.collect.ImmutableSet;
import io.vertx.core.json.JsonObject;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
  * JWKBuilder that parses and serializes RSA public keys.
 *
 * @author jtalbut
 */
public class RSAJwkBuilder extends JwkBuilder {

  private static final Logger logger = LoggerFactory.getLogger(RSAJwkBuilder.class);
  
  private static final String KTY = "RSA";

  private static final Set<String> VALID_ALGS = ImmutableSet.<String>builder()
          .add("RS256")
          .add("RS384")
          .add("RS512")
          .build();
  
  /**
   * Constructor.
   * 
   * Typically it is not necessary to construct an explicit instance of this class, the methods in the {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder} class should suffice.
   * 
   */
  public RSAJwkBuilder() {
  }
  
  @Override
  public boolean canHandleKey(PublicKey key) {
    return key instanceof RSAPublicKey;
  }
  
  @Override
  public JsonObject toJson(String kid, String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException {
    RSAPublicKey key = (RSAPublicKey) publicKey;
    
    JsonObject json = new JsonObject();
    if (VALID_ALGS.contains(algorithm)) {
      json.put("alg", algorithm);
    } else {
      logger.warn("The algorithm {} is not in {}", algorithm, VALID_ALGS);
      throw new NoSuchAlgorithmException(algorithm);
    }
    json.put("kid", kid);
    json.put("kty", KTY);
    json.put("e", B64ENCODER.encodeToString(key.getPublicExponent().toByteArray()));
    json.put("n", B64ENCODER.encodeToString(key.getModulus().toByteArray()));
    return json;
  }

  
}
