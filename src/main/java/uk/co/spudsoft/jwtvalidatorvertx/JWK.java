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

import com.google.common.base.Strings;
import io.vertx.core.json.JsonObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;
import uk.co.spudsoft.jwtvalidatorvertx.impl.ECJwkBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.impl.EdECJwkBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.impl.RSAJwkBuilder;

/**
 * Represent a single Json Web Key as defined in RFC 7517.https://datatracker.ietf.org/doc/html/rfc7517.
 * 
 * This class (more specifically the implementations of JwkBuilder that this class uses) is the bridge between JDK {@link java.security.PublicKey}s and the JSON of a JWK.
 * 
 * @author jtalbut
 * @param <T> The specific class of PublicKey represented by this JWK.
 * A typical usage of the JWK should not care about the type of key and should be able to use JWK&lt;?>.
 */
public abstract class JWK<T extends PublicKey> {
  
  private static final List<JwkBuilder<?>> BUILDERS = Arrays.asList(
    new RSAJwkBuilder()
    , new ECJwkBuilder()
    , new EdECJwkBuilder()
  );
  
  private final long expiryMs;
  
  private final JsonObject json;
  private final String kid;
  private final String use;
  private final String kty;
  private final T key;

  /**
   * Constructor, for use by (probably private) sub classes.
   * 
   * @param expiryMs The expiry time for the JWK.
   * This value is only relevant if the JWK is cached, it is not part of the JWK itself.
   * @param json The JSON for the JWK.
   * @param key The key in the JWK.
   */
  protected JWK(long expiryMs, JsonObject json, T key) {
    this.expiryMs = expiryMs;
    this.json = json;

    this.kid = json.getString("kid");
    this.use = json.getString("use");
    this.kty = json.getString("kty");
    
    this.key = key;
    assert(key != null);

    if (Strings.isNullOrEmpty(kid)) {
      throw new IllegalArgumentException("Key ID (kid) not specified in JWK");
    }    
  }  
  
  /**
   * Factory method to create a JWK from its JSON representation.
   * 
   * This is expected to result in a call to the JWK constructor that takes in both the JSON and the PublicKey.
   * 
   * @param expiryMs The time in ms from the epoch (i.e. to be compared with System.currentTimeMillis) at which this data should be discarded.
   *    Should be found by parsing cache-control headers.
   * @param jo The JsonObject that contains the JWK as defined in RFC7517.
   * @return a newly created JWK of an appropriate type.
   * @throws java.security.NoSuchAlgorithmException if the algorithm in the JWK is not known.
   * @throws java.security.spec.InvalidKeySpecException if the key specification in the JWK is inappropriate for the key factory to produce a key.
   * @throws java.security.spec.InvalidParameterSpecException  if there is a bug in the JWK code.
   */
  public static JWK<?> create(long expiryMs, JsonObject jo) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {

    String kty = jo.getString("kty");
    
    if (Strings.isNullOrEmpty(kty)) {
      throw new IllegalArgumentException("Key type (kty) not specified in JWK");
    } else {
      for (JwkBuilder<?> builder : BUILDERS) {
        if (builder.canCreateFromKty(kty)) {
          return builder.create(expiryMs, jo);
        }
      }
      throw new IllegalArgumentException("Unsupported key type: " + kty);
    }
  }
  
  /**
   * Factory method to create a JWK from a PublicKey.
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
  public static JWK<?> create(long expiryMs, String kid, PublicKey key) throws InvalidParameterSpecException, NoSuchAlgorithmException {
    for (JwkBuilder<?> builder : BUILDERS) {
      if (builder.canCreateFromKey(key)) {
        return builder.create(expiryMs, kid, key);
      }
    }
    throw new IllegalArgumentException("Cannot process key of type " + key.getClass().getSimpleName());
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
   * Get the type of key represented by the JWK.
   * @return the type of key represented by the JWK.
   */
  public String getKty() {
    return kty;
  }
  
  /**
   * Get the key use string.
   * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">https://datatracker.ietf.org/doc/html/rfc7517#section-4.2</a>
   * This should be "sig" for all known uses, but its presence is optional, so it's ignored.
   *
   * @return the key use string.
   */
  public String getUse() {
    return use;
  }

  /**
   * Get the key represented by this JWK.
   *
   * @return the key represented by this JWK.
   */
  public T getKey() {
    return key;
  }

  /**
   * Get the key in its original, JWK compatible, JSON format.
   *
   * @return the key in its original, JWK compatible, JSON format.
   */
  public JsonObject getJson() {
    return json;
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
    return verify(algorithm.getJdkAlgName(), algorithm.getParameter(), (PublicKey) key, signature, data);
  }

  /**
   * Verify a signature using JDK terminology.
   *
   * @param jdkAlgName The name of the algorithm as used by the JDK.
   * @param parameter Any parameter required by the algorithm.
   * @param key The public key to verify the signature.
   * @param signature The signature that has been provided for the JWT.
   * @param data The data to be verified.
   * @return True if the signature can only have been created using this key and the data provided.
   *
   * @throws InvalidKeyException if the key is not appropriate for the signer.
   * @throws NoSuchAlgorithmException if the algorithm is not known to the JDK security subsystem,.
   * @throws SignatureException if the signature is invalid
   * @throws InvalidAlgorithmParameterException if the algorithm is configured with incorrect parameters.
   */
  public static boolean verify(String jdkAlgName, @Nullable AlgorithmParameterSpec parameter, PublicKey key, byte[] signature, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException {
    Signature signer = Signature.getInstance(jdkAlgName);
    if (parameter != null) {
      signer.setParameter(parameter);
    }
    signer.initVerify(key);
    signer.update(data);
    return signer.verify(signature);
  }

}
