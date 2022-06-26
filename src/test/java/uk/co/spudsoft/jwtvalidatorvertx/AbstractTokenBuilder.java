/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;




/**
 *
 * @author njt
 */
public abstract class AbstractTokenBuilder implements TokenBuilder {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(AbstractTokenBuilder.class);

  protected Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  protected static final SecureRandom RANDOM = new SecureRandom();
  
  private boolean breakHeader = false;
  private boolean breakPayload = false;
  private boolean breakSignature = false;
  private boolean headerNotJson = false;
  private boolean payloadNotJson = false;
  private boolean invalidSignature = false;
  private boolean invalidKid = false;

  @Override
  public TokenBuilder setBreakHeader(boolean breakHeader) {
    this.breakHeader = breakHeader;
    return this;
  }

  @Override
  public TokenBuilder setBreakPayload(boolean breakPayload) {
    this.breakPayload = breakPayload;
    return  this;
  }

  @Override
  public TokenBuilder setBreakSignature(boolean breakSignature) {
    this.breakSignature = breakSignature;
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
  public TokenBuilder setInvalidSignature(boolean invalidSignature) {
    this.invalidSignature = invalidSignature;
    return this;
  }
  
  @Override
  public TokenBuilder setInvalidKid(boolean invalidKid) {
    this.invalidKid = invalidKid;
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
      if (invalidSignature) {
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

  protected JsonObject generateHeaderNode(String kid, JsonWebAlgorithm algorithm) {
    JsonObject header = new JsonObject();
    header.put("typ", "JWT");
    if (kid != null) {
      if (invalidKid) {
        header.put("kid", "INVALID");
      } else {
        header.put("kid", kid);
      }
    }
    header.put("alg", algorithm.getName());
    return header;
  }

  protected JsonObject generateClaimsNode(String iss, String sub, Long exp, Long nbf, List<String> aud, Map<String, Object> otherClaims) {
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

  protected String base64Header(JsonObject header) {
    String headerString = header.toString();
    if (headerNotJson) {
      headerString = headerString.replaceAll("\"", "");
    }
    String headerBase64 = BASE64.encodeToString(headerString.getBytes(StandardCharsets.UTF_8));
    if (breakHeader) {
      headerBase64 = headerBase64.substring(0, headerBase64.length() - 1);
    }
    return headerBase64;
  }

  protected String base64Claims(JsonObject claims) {
    String claimsString = claims.toString();
    if (payloadNotJson) {
      claimsString = claimsString.replaceAll("\"", "");
    }
    String claimsBase64 = BASE64.encodeToString(claimsString.getBytes(StandardCharsets.UTF_8));
    if (breakPayload) {
      claimsBase64 = claimsBase64.substring(0, claimsBase64.length() - 1);
    }
    return claimsBase64;
  }

  protected abstract byte[] generateSignature(String kid, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception;

  protected String base64Signature(byte[] signature) {
    String signatureBase64 = BASE64.encodeToString(signature);
    if (breakSignature) {
      signatureBase64 = signatureBase64.substring(0, signatureBase64.length() - 1);
    }
    return signatureBase64;
  }

  protected String constructToken(String headerBase64, String claimsBase64, String signatureBase64) {
    String token = headerBase64 + "." + claimsBase64 + "." + signatureBase64;
    return token;
  }

}
