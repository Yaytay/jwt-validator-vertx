/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.google.common.cache.Cache;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;
import uk.co.spudsoft.jwtvalidatorvertx.TokenBuilder;




/**
 * Abstract implementation of TokenBuilder.
 * <p>
 * The actual creation of keys is left to a subclass to implement.
 * <p>
 * This class can perform all the work of a TokenBuilder implementation apart from the generation of keys, however most methods
 * are designed to be overrideable so that a specific implementation can do something different if that is useful.
 * @author jtalbut
 */
public abstract class AbstractTokenBuilder implements TokenBuilder {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(AbstractTokenBuilder.class);

  /**
   * Base64 encoded that implementations may (should) use.
   */
  protected static final Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  /**
   * Secure random number generator that implementations may  use.
   */
  protected static final SecureRandom RANDOM = new SecureRandom();
  
  private boolean headerNotValidBase64 = false;
  private boolean payloadNotValidBase64 = false;
  private boolean signatureNotValidBase64 = false;
  private boolean headerNotJson = false;
  private boolean payloadNotJson = false;
  private boolean signatureNotValidHash = false;
  private boolean kidInvalid = false;
  
  /**
   * The key cache that is shared with the {@link uk.co.spudsoft.jwtvalidatorvertx.JwksHandler}.
   * <p>
   * Note that it is the TokenBuilder that is responsible for causing keys to be created and cached, the 
   * {@link uk.co.spudsoft.jwtvalidatorvertx.JwksHandler} just makes them available.
   */
  protected final Cache<String, AlgorithmAndKeyPair> keyCache;

  /**
   * Constructor.
   * 
   * @param keyCache The key cache that is shared with the {@link uk.co.spudsoft.jwtvalidatorvertx.JwksHandler}.
   */
  public AbstractTokenBuilder(Cache<String, AlgorithmAndKeyPair> keyCache) {
    this.keyCache = keyCache;
  }

  @Override
  public TokenBuilder setHeaderNotValidBase64(boolean headerNotValidBase64) {
    this.headerNotValidBase64 = headerNotValidBase64;
    return this;
  }

  @Override
  public TokenBuilder setPayloadNotValidBase64(boolean payloadNotValidBase64) {
    this.payloadNotValidBase64 = payloadNotValidBase64;
    return  this;
  }

  @Override
  public TokenBuilder setSignatureNotValidBase64(boolean signatureNotValidBase64) {
    this.signatureNotValidBase64 = signatureNotValidBase64;
    return this;
  }

  @Override
  public TokenBuilder setHeaderNotJson(boolean headerNotJson) {
    this.headerNotJson = headerNotJson;
    return this;
  }

  @Override
  public TokenBuilder setPayloadNotJson(boolean payloadNotJson) {
    this.payloadNotJson = payloadNotJson;
    return this;
  }

  @Override
  public TokenBuilder setSignatureNotValidHash(boolean signatureNotValidHash) {
    this.signatureNotValidHash = signatureNotValidHash;
    return this;
  }
  
  @Override
  public TokenBuilder setKidInvalid(boolean kidInvalid) {
    this.kidInvalid = kidInvalid;
    return this;
  }
  
  @Override
  public String buildToken(JsonWebAlgorithm jwa,
           String kid,
           String iss,
           String sub,
           List<String> aud,
           Long nbf,
           Long exp,
           Map<String, Object> otherClaims
  ) throws Exception {

    JsonObject header = generateHeaderNode(kid, jwa);

    JsonObject claims = generateClaimsNode(iss, sub, exp, nbf, aud, otherClaims);

    String headerBase64 = base64Header(header);

    String claimsBase64 = base64Claims(claims);

    String signatureBase64;
    
    if ((kid != null) && (jwa != JsonWebAlgorithm.none)) {
      byte[] signature = generateSignature(kid, jwa, headerBase64, claimsBase64);
      if (signatureNotValidHash) {
        signature = Arrays.copyOf(signature, signature.length - 1);
      }
      signatureBase64 = base64Signature(signature);
    } else {
      signatureBase64 = "";
    }

    String token = constructToken(headerBase64, claimsBase64, signatureBase64);

    logger.debug("{} Token: {}", jwa, token);

    return token;
  }

  /**
   * Helper method to generate the token header node.
   * @param kid The key ID.
   * @param algorithm The algorithm.
   * @return The created JsonObject header node.
   */
  protected JsonObject generateHeaderNode(String kid, JsonWebAlgorithm algorithm) {
    JsonObject header = new JsonObject();
    header.put("typ", "JWT");
    if (kid != null) {
      if (kidInvalid) {
        header.put("kid", "INVALID");
      } else {
        header.put("kid", kid);
      }
    }
    header.put("alg", algorithm.getName());
    return header;
  }

  /**
   * Helper method to build the payload for a token.
   * @param iss The iss (issuer) claim.
   * @param sub The sub (subject) claim.
   * @param exp The exp (expiry) claim.
   * @param nbf The nbf (not before) claim.
   * @param aud The aud (audience) claim.
   * @param otherClaims Map of other claims that are to be added.
   * Any claims in otherClaims will override anything else added to the claims.
   * @return a JsonObject of the payload for a token.
   */
  protected JsonObject generateClaimsNode(
          @Nullable String iss
          , @Nullable String sub
          , @Nullable Long exp
          , @Nullable Long nbf
          , @Nullable List<String> aud
          , @Nullable Map<String, Object> otherClaims
  ) {
    JsonObject claims = new JsonObject();
    if (sub != null) {
      claims.put("sub", sub);
    }
    if (iss != null) {
      claims.put("iss", iss);
    }
    if (exp != null) {
      claims.put("exp", exp);
    }
    if (nbf != null) {
      claims.put("nbf", nbf);
    }
    if (aud != null) {
      if (aud.size() == 1) {
        claims.put("aud", aud.get(0));
      } else {
        JsonArray array = new JsonArray();
        claims.put("aud", array);
        for (String member : aud) {
          array.add(member);
        }
      }
    }
    if (otherClaims != null) {
      for (Entry<String, Object> claim : otherClaims.entrySet()) {
        claims.put(claim.getKey(), claim.getValue());
      }
    }
    return claims;
  }

  /**
   * Helper method to convert a JsonObject into a base64 representation.
   * Optionally provides two ways in which the result can be invalidated.
   * @param notJson If the JSON should be broken before the base64 encoding.
   * @param brokenBase64 The the base64 encoding should be broken.
   * @param json The JSON to be encoded.
   * @return The JSON encoded as base64 (possibly broken).
   */
  protected String base64JSon(boolean notJson, boolean brokenBase64, JsonObject json) {
    String jsonString = json.toString();
    if (notJson) {
      jsonString = jsonString.replaceAll("\"", "");
    }
    String base64 = BASE64.encodeToString(jsonString.getBytes(StandardCharsets.UTF_8));
    if (brokenBase64) {
      base64 = base64.substring(0, base64.length() - 1);
    }
    return base64;
  }

  /**
   * Helper method to convert the header to base64, possibly breaking it.
   * Uses the headerNotJson and headerNotValidBase64 fields to determine whether the result should be valid.
   * @param header The header to convert.
   * @return The JSON encoded as base64 (possibly broken).
   */
  protected String base64Header(JsonObject header) {
    return base64JSon(headerNotJson, headerNotValidBase64, header);
  }

  /**
   * Helper method to convert the payload to base64, possibly breaking it.
   * Uses the payloadNotJson and payloadNotValidBase64 fields to determine whether the result should be valid.
   * @param claims The claims to convert.
   * @return The JSON encoded as base64 (possibly broken).
   */
  protected String base64Claims(JsonObject claims) {
    return base64JSon(payloadNotJson, payloadNotValidBase64, claims);
  }

  /**
   * Sign the token header and claims using the specified key.
   * @param kid The key to use to sign the header and claims, if this key is not found in the cache it will be generated.
   * @param algorithm The algorithm to use to generate the key, if it is not found in the cache.
   * @param headerBase64 The header to include in the signature.
   * @param claimsBase64 The claims to include in the signature.
   * @return The signature of the header and claims.
   * @throws Exception If the security subsystem is unable to complete the operation.
   */
  protected abstract byte[] generateSignature(String kid, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception;

  /**
   * Helper method to base6t4 encode the signature, possibly breaking it.
   * Uses the signatureNotValidBase64 fields to determine whether the result should be valid.
   * @param signature The signature of the header and payload.
   * @return The base64 encoded signature.
   */
  protected String base64Signature(byte[] signature) {
    String signatureBase64 = BASE64.encodeToString(signature);
    if (signatureNotValidBase64) {
      signatureBase64 = signatureBase64.substring(0, signatureBase64.length() - 1);
    }
    return signatureBase64;
  }

  /**
   * Helper method to concatenate the three parts of the token.
   * @param headerBase64 The header, base 64 encoded.
   * @param claimsBase64 The claims, base 64 encoded.
   * @param signatureBase64 The signature, base 64 encoded.
   * @return The final JWS.
   */
  protected String constructToken(String headerBase64, String claimsBase64, String signatureBase64) {
    String token = headerBase64 + "." + claimsBase64 + "." + signatureBase64;
    return token;
  }

}
