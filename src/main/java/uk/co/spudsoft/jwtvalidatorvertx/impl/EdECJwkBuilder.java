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
import com.google.common.primitives.Bytes;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
  * JWKBuilder that parses and serializes Edwards-Curve elliptic curve (EC) public keys.
 * 
 * @author jtalbut
 */
public class EdECJwkBuilder extends JwkBuilder {
  
  private static final Logger logger = LoggerFactory.getLogger(EdECJwkBuilder.class);
  
  private static final Set<String> VALID_ALGS = ImmutableSet.<String>builder()
          .add("EdDSA")
          .build();
  
  private static final String KTY = "OKP";

  /**
   * Constructor.
   * 
   * Typically it is not necessary to construct an explicit instance of this class, the methods in the {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder} class should suffice.
   * 
   */
  public EdECJwkBuilder() {
  }
  
  @Override
  public boolean canHandleKey(PublicKey key) {
    return key instanceof EdECPublicKey;
  }  
  
  @Override
  public JsonObject toJson(String kid, String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException {
    EdECPublicKey key = (EdECPublicKey) publicKey;
            
    JsonObject json = new JsonObject();
    if (VALID_ALGS.contains(algorithm)) {
      json.put("alg", algorithm);
    } else {
      logger.warn("The algorithm {} is not in {}", algorithm, VALID_ALGS);
      throw new NoSuchAlgorithmException(algorithm);
    }
    
    json.put("kid", kid);
    json.put("kty", KTY);
    json.put("crv", key.getParams().getName());
    
    BigInteger y = key.getPoint().getY();
    byte[] arr = y.toByteArray();
    Bytes.reverse(arr, 0, arr.length);
//    if (key.getPoint().isXOdd()) {
//      arr[arr.length - 1] |= 0x8;
//    }
    json.put("x", B64ENCODER.encodeToString(arr));
    return json;
  }
  
}
