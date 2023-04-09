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
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidParameterSpecException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JWK;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
 * JWKBuilder that parses and serializes elliptic curve (EC) public keys.
 * 
 * @author jtalbut
 */
public class ECJwkBuilder extends JwkBuilder<ECPublicKey> {
  
  private static final Logger logger = LoggerFactory.getLogger(ECJwkBuilder.class);
  private static final String KTY = "EC";

  private static class ECJwk extends JWK<ECPublicKey> {

    ECJwk(long expiryMs, JsonObject json, ECPublicKey key) {
      super(expiryMs, json, key);
    }
    
  }

  /**
   * Constructor.
   * 
   * Typically it is not necessary to construct an explicit instance of this class, the ones in the {@link uk.co.spudsoft.jwtvalidatorvertx.JWK} class should suffice.
   * 
   */
  public ECJwkBuilder() {
  }
  
  @Override
  public boolean canCreateFromKty(String kty) {
    return KTY.equals(kty);
  }

  @Override
  public boolean canCreateFromKey(PublicKey key) {
    return key instanceof ECPublicKey;
  }
  
  private static String getJdkEcCurveName(String curve) {
    if (Strings.isNullOrEmpty(curve)) {
      throw new IllegalArgumentException("JWK does not contain valid EC public key (curve not specified)");
    }
    switch (curve) {
      case "P-256":
        return "secp256r1";
      case "P-384":
        return "secp384r1";
      case "P-521":
        return "secp521r1";
      default:
        return curve;
    }
  }  
  
  @Override
  public JWK<ECPublicKey> create(long expiryMs, JsonObject json) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        
    validateAlg(json, KTY);
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");

    String curve = getJdkEcCurveName(json.getString("crv"));
    parameters.init(new ECGenParameterSpec(curve));

    String xStr = json.getString("x");
    String yStr = json.getString("y");
    if (Strings.isNullOrEmpty(xStr)) {
      throw new IllegalArgumentException("x has no value");
    } else if (Strings.isNullOrEmpty(yStr)) {
      throw new IllegalArgumentException("y has no value");      
    } else {
      final BigInteger x = new BigInteger(1, B64DECODER.decode(xStr));
      final BigInteger y = new BigInteger(1, B64DECODER.decode(yStr));

      ECPublicKey key = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)));
      return new ECJwk(expiryMs, json, key);
    }
  }

  
  private static String oidToCurve(String oid) {
    switch (oid) {
      case "1.2.840.10045.3.1.7":
        return "secp256r1";
      case "1.3.132.0.34":
        return "secp384r1";
      case "1.3.132.0.35":
        return "secp521r1";
      default:
        logger.warn("Unrecognised OID passed in: {}", oid);
        throw new IllegalArgumentException("Unknown OID");
    }
  }
  
  /**
   * Convert the coordinate to a byte array, ensuring that the result is at least fieldSize bits long.
   * @param fieldSize The minimum number of bits in the resulting array.
   * @param coordinate The BigInteger to convert.
   * @return a byte array of at least fieldSize bits containing coordinate.
   */
  private static byte[] coordinateToByteArray(int fieldSize, BigInteger coordinate) {
    byte[] coordinateByteArray = coordinate.toByteArray();
    int fullSize = (int) Math.ceil(fieldSize / 8d);

    if (fullSize > coordinateByteArray.length) {
      final byte[] fullSizeCoordinateByteArray = new byte[fullSize];
      System.arraycopy(coordinateByteArray, 0, fullSizeCoordinateByteArray, fullSize - coordinateByteArray.length, coordinateByteArray.length);
      return fullSizeCoordinateByteArray;
    } else {
      return coordinateByteArray;
    }
  }
  
  @Override
  public JWK<ECPublicKey> create(long expiryMs, String kid, PublicKey publicKey) throws InvalidParameterSpecException, NoSuchAlgorithmException {
    ECPublicKey key = (ECPublicKey) publicKey;
    
    JsonObject json = new JsonObject();
    json.put("kid", kid);
    json.put("kty", KTY);
    
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(key.getParams());
    String oid = params.getParameterSpec(ECGenParameterSpec.class).getName();
    String curve = oidToCurve(oid);
    json.put("crv", curve);
    
    int fieldSize = key.getParams().getCurve().getField().getFieldSize();
    json.put("x", B64ENCODER.encodeToString(coordinateToByteArray(fieldSize, key.getW().getAffineX())));
    json.put("y", B64ENCODER.encodeToString(coordinateToByteArray(fieldSize, key.getW().getAffineY())));

    return new ECJwk(expiryMs, json, key);
  }
  
}
