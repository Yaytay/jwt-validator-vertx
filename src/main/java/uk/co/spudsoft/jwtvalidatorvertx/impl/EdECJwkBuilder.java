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
import com.google.common.primitives.Bytes;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import uk.co.spudsoft.jwtvalidatorvertx.JWK;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
 *
 * @author jtalbut
 */
public class EdECJwkBuilder extends JwkBuilder<EdECPublicKey> {
  
  private static class EdECJwk extends JWK<EdECPublicKey> {

    EdECJwk(long expiryMs, JsonObject json, EdECPublicKey key) {
      super(expiryMs, json, key);
    }
    
  }  
  
  private static EdECPoint byteArrayToEdPoint(byte[] arr) {
    byte msb = arr[arr.length - 1];
    boolean xOdd = (msb & 0x80) != 0;
    arr[arr.length - 1] &= (byte) 0x7F;
    Bytes.reverse(arr, 0, arr.length);
    BigInteger y = new BigInteger(1, arr);
    return new EdECPoint(xOdd, y);
  }
  
  @Override
  public JWK<EdECPublicKey> create(long expiryMs, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException {
    
    validateAlg(json, "EdDSA");
    String xStr = json.getString("x");
    String curve = json.getString("crv");

    if (Strings.isNullOrEmpty(xStr)) {
      throw new IllegalArgumentException("key has no value");
    } else if (Strings.isNullOrEmpty(curve)) {
      throw new IllegalArgumentException("curve has no value");      
    } else {
      KeyFactory kf = KeyFactory.getInstance("EdDSA");
      NamedParameterSpec paramSpec = new NamedParameterSpec(curve);
      EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, byteArrayToEdPoint(B64DECODER.decode(xStr)));
      EdECPublicKey key = (EdECPublicKey) kf.generatePublic(pubSpec);
      return new EdECJwk(expiryMs, json, key);
    }
  }

  @Override
  public JWK<EdECPublicKey> create(long expiryMs, String kid, EdECPublicKey key) {
    JsonObject json = new JsonObject();
    json.put("kid", kid);
    json.put("kty", "OKP");
    json.put("crv", key.getParams().getName());
    
    BigInteger y = key.getPoint().getY();
    byte[] arr = y.toByteArray();
    Bytes.reverse(arr, 0, arr.length);
    if (key.getPoint().isXOdd()) {
      arr[arr.length - 1] |= 0x8;
    }
    json.put("x", B64ENCODER.encodeToString(arr));
    return new EdECJwk(expiryMs, json, key);
  }
  
  
}
