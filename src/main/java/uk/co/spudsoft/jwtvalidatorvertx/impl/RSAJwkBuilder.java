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

import com.google.common.base.Strings;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import uk.co.spudsoft.jwtvalidatorvertx.JWK;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
 *
 * @author jtalbut
 */
public class RSAJwkBuilder extends JwkBuilder<RSAPublicKey> {

  private static class RSAJwk extends JWK<RSAPublicKey> {

    RSAJwk(long expiryMs, JsonObject json, RSAPublicKey key) {
      super(expiryMs, json, key);
    }
    
  }
  
  
  @Override
  public JWK<RSAPublicKey> create(long expiryMs, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException {
    
    validateAlg(json, "RSA");
    String nStr = json.getString("n");
    String eStr = json.getString("e");
    if (Strings.isNullOrEmpty(nStr)) {
      throw new IllegalArgumentException("modulus has no value");
    } else if (Strings.isNullOrEmpty(eStr)) {
      throw new IllegalArgumentException("exponent has no value");      
    } else {
      final BigInteger n = new BigInteger(1, B64DECODER.decode(nStr));
      final BigInteger e = new BigInteger(1, B64DECODER.decode(eStr));
      RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
      return new RSAJwk(expiryMs, json, key);
    }
  }

  @Override
  public JWK<RSAPublicKey> create(long expiryMs, String kid, RSAPublicKey key) {
    JsonObject json = new JsonObject();
    json.put("kid", kid);
    json.put("kty", "RSA");
    // This is just to test the alg handling in JWK constructor, we don't know (or care) whether it's RSA256, 384 or 512.
    json.put("alg", "RS256");
    json.put("e", B64ENCODER.encodeToString(key.getPublicExponent().toByteArray()));
    json.put("n", B64ENCODER.encodeToString(key.getModulus().toByteArray()));
    return new RSAJwk(expiryMs, json, key);
  }
  
}
