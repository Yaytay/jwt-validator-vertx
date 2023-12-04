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
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
 * JWKBuilder that parses and serializes elliptic curve (EC) public keys.
 * 
 * @author jtalbut
 */
public class ECJwkBuilder extends JwkBuilder {
  
  private static final Logger logger = LoggerFactory.getLogger(ECJwkBuilder.class);
  private static final String KTY = "EC";

  private static final Set<String> VALID_ALGS = ImmutableSet.<String>builder()
          .add("ES256")
          .add("ES384")
          .add("ES512")
          .build();
  
  /**
   * Constructor.
   * 
   * Typically it is not necessary to construct an explicit instance of this class, the methods in the {@link uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder} class should suffice.
   * 
   */
  public ECJwkBuilder() {
  }
  
  @Override
  public boolean canHandleKey(PublicKey key) {
    return key instanceof ECPublicKey;
  }
  
  private static String oidToCurve(String oid) {
    switch (oid) {
      case "1.2.840.10045.3.1.7":
        // return "secp256r1";
        return "P-256";
      case "1.3.132.0.34":
        // return "secp384r1";
        return "P-384";
      case "1.3.132.0.35":
        // return "secp521r1";
        return "P-521";
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
  public JsonObject toJson(String kid, String algorithm, PublicKey publicKey) throws InvalidParameterSpecException, NoSuchAlgorithmException {
    ECPublicKey key = (ECPublicKey) publicKey;

    JsonObject json = new JsonObject();
    if (VALID_ALGS.contains(algorithm)) {
      json.put("alg", algorithm);
    } else {
      logger.warn("The algorithm {} is not in {}", algorithm, VALID_ALGS);
      throw new NoSuchAlgorithmException(algorithm);
    }
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
    
    return json;
  }
  
  
}
