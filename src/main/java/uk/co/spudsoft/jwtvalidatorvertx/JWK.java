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

import com.google.common.primitives.Bytes;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;

/**
 * Represent a single Json Web Key as defined in RFC 7517.
 * https://datatracker.ietf.org/doc/html/rfc7517
 * 
 * @author jtalbut
 */
public class JWK {
  
  private static final Logger logger = LoggerFactory.getLogger(JWK.class);
  
  private final long expiryMs;
  
  private final String kid;
  private final String use;
  private final String kty;
  private final Key key;

  /**
   * Constructor.
   * 
   * @param expiryMs The time in ms from the epoch (i.e. to be compared with System.currentTimeMillis) at which this data should be discarded.
   *    Should be found by parsing cache-control headers.
   * @param jo The JsonObject that contains the JWK as defined in RFC7517.
   * @throws java.security.NoSuchAlgorithmException if the algorithm in the JWK is not known.
   * @throws java.security.spec.InvalidKeySpecException if the key specification in the JWK is inappropriate for the key factory to produce a key.
   * @throws java.security.spec.InvalidParameterSpecException  if there is a bug in the JWK code.
   */
  public JWK(long expiryMs, JsonObject jo) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
    this.expiryMs = expiryMs;
    
    this.kid = jo.getString("kid");
    this.use = jo.getString("use");
    this.kty = jo.getString("kty");
    
    if (!hasValue(kid)) {
      throw new IllegalArgumentException("Key ID (kid) not specified in JWK");
    }
    
    if (!hasValue(kty)) {
      throw new IllegalArgumentException("Key type (kty) not specified in JWK");
    } else {
      switch (kty) {
        case "RSA":
        case "RSASSA":
          validateAlg(jo, "RSA");
          key = createRSA(jo);
          break;
        case "EC":
          validateAlg(jo, "ECDSA");
          key = createEC(jo);
          break;
        case "OKP":
          validateAlg(jo, "EdDSA");
          key = createOKP(jo);
          break;
        default:
          throw new IllegalArgumentException("Unsupported key type: " + kty);
      }
    }
  }
  
  private void validateAlg(JsonObject jo, String requiredFamily) {
    // From RFC 7515 alg is optional and I haven't ever seen it in the wild.
    // If it is provided we just validate that it is compatible with the kty.
    String algString = jo.getString("alg");
    if (algString != null) {
      JsonWebAlgorithm alg = JsonWebAlgorithm.valueOf(algString);
      if (!requiredFamily.equals(alg.getFamilyName())) {
        logger.warn("Algorithm ({}) does not match key type ({})", algString, kty);
        throw new IllegalArgumentException("Algorithm (" + algString + ") does not match key type (" + kty + ")");
      }
    }
  }

  /**
   * Get the expiry time in ms from the epoch.
   * @return the expiry time in ms from the epoch.
   */
  public long getExpiryMs() {
    return expiryMs;
  }

  /**
   * Get the key identifier.
   * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">https://datatracker.ietf.org/doc/html/rfc7517#section-4.5</a>
   * @return the key identifier.
   */
  public String getKid() {
    return kid;
  }

  /**
   * Get the key use string.
   * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">https://datatracker.ietf.org/doc/html/rfc7517#section-4.2</a>
   * This should be "sig" for all known uses, but its presence is optional, so it's ignored.
   * @return the key use string.
   */
  public String getUse() {
    return use;
  }

  /**
   * Get the key represented by this JWK.
   * @return the key represented by this JWK.
   */
  public Key getKey() {
    return key;
  }
  
  /**
   * Verify a signature using the key in this JWK.
   * 
   * @param algorithm The algorithm specified in the token, which may not be the same as the JWK algorithm (RSA-PSS).
   * @param signature The signature that has been provided for the JWT.
   * @param data The data to be verified.
   * @return True if the signature can only have been created using this key and the data provided.
   * 
   * @throws InvalidKeyException if the key is not appropriate for the signer.
   * @throws NoSuchAlgorithmException if the algorithm is not known to the JDK security subsystem,.
   * @throws SignatureException if the signature is invalid
   * @throws InvalidAlgorithmParameterException if the algorithm is configured with incorrect parameters.
   */
  public boolean verify(JsonWebAlgorithm algorithm, byte[] signature, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException {
    Signature signer = Signature.getInstance(algorithm.getJdkAlgName());
    if (algorithm.getParameter() != null) {
      signer.setParameter(algorithm.getParameter());
    }
    signer.initVerify((PublicKey) key);
    signer.update(data);
    return signer.verify(signature);
  }
  
  private static boolean hasValue(String s) {
    return s != null && !s.isBlank();
  }

  private static Key createRSA(JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException {
    String nStr = json.getString("n");
    String eStr = json.getString("e");
    if (hasValue(nStr) && hasValue(eStr)) {
      final BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(nStr));
      final BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(eStr));
      return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }
    throw new IllegalArgumentException("JWK (" + json + ") does not contain valid RSA public key");
  }
  
  private static String getJdkEcCurveName(String curve) {
   if (!hasValue(curve)) {
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
  
  private static Key createEC(JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    
    String curve = getJdkEcCurveName(json.getString("crv"));
    parameters.init(new ECGenParameterSpec(curve));

    String xStr = json.getString("x");
    String yStr = json.getString("y");
    if (hasValue(xStr) && hasValue(yStr)) {
      final BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(xStr));
      final BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(yStr));
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)));
    }
    throw new IllegalArgumentException("JWK (" + json + ") does not contain valid EC public key");
  }
  
  private static EdECPoint byteArrayToEdPoint(byte[] arr) {
    byte msb = arr[arr.length - 1];
    boolean xOdd = (msb & 0x80) != 0;
    arr[arr.length - 1] &= (byte) 0x7F;
    Bytes.reverse(arr, 0, arr.length);
    BigInteger y = new BigInteger(1, arr);
    return new EdECPoint(xOdd, y);
  }
  
  private static Key createOKP(JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException {
    String xStr = json.getString("x");
    String curve = json.getString("crv");
    
    if (hasValue(xStr) && hasValue(curve)) {
      KeyFactory kf = KeyFactory.getInstance("EdDSA");
      NamedParameterSpec paramSpec = new NamedParameterSpec(curve);
      EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, byteArrayToEdPoint(Base64.getUrlDecoder().decode(xStr)));
      return kf.generatePublic(pubSpec);
    }
    throw new IllegalArgumentException("JWK (" + json + ") does not contain valid OKP public key");
  }

}
