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
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * A JWT as defined by <A href="https://datatracker.ietf.org/doc/html/rfc7519">RFC7519</A>.
 * 
 * The internal representation is two JSON objects, the signature (as string) and the original string that was used to generate the signature (concatenated base 64 header and payload).
 * Values are not extracted or cached, they are simply retrieved on demand.
 * 
 * @author jtalbut
 */
public class JwtWindows {
  
  private static final Base64.Decoder B64DECODER = Base64.getUrlDecoder();
  private static final int SPACE = " ".codePointAt(0);
  
  private final JsonObject header;
  private final JsonObject payload;
  private final String signatureBase;
  private final String signature;
  
  /**
   * Constructor.
   * @param header The header from the JWT.
   * @param payload The payload from the JWT.
   * @param signatureBase The value used to calculate the signature - base64(header) + "." + base64(payload).
   * @param signature The signature from the JWT.
   */
  public JwtWindows(JsonObject header, JsonObject payload, String signatureBase, String signature) {
    this.header = header == null ? new JsonObject() : header;
    this.payload = payload == null ? new JsonObject() : payload;
    this.signatureBase = signatureBase;
    this.signature = signature;
  }
  
  /**
   * Parse a JWT in delimited string form.
   * @param token The JWT in delimited string form.
   * @return A newly created JWT object.
   */
  public static JwtWindows parseJws(final String token) {
    String[] segments = token.split("\\.");
    if (segments.length < 2 || segments.length > 3) {
      throw new IllegalArgumentException("Not enough or too many segments [" + segments.length + "]");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = segments.length == 2 ? null : segments[2];

    // base64 decode and parseJws JSON
    JsonObject header = new JsonObject(new String(B64DECODER.decode(headerSeg), StandardCharsets.UTF_8));
    JsonObject payload = new JsonObject(new String(B64DECODER.decode(payloadSeg), StandardCharsets.UTF_8));

    return new JwtWindows(header, payload, headerSeg + "." + payloadSeg, signatureSeg);
  }
  
  /**
   * Get the number of claims in the payload.
   * @return the number of claims in the payload.
   */
  public int getPayloadSize() {
    return payload.size();
  }
  
  /**
   * Get a single payload claim by name.
   * @param claim The name of the claim to return.
   * @return the claim with the given name.
   */
  public Object getClaim(String claim) {
    return payload.getValue(claim);
  }
  
  /**
   * Get a payload claim by name returning a List or Strings.
   * @param claim The name of the claim to return.
   * @return the claim with the given name, as a List of Strings.
   */
  public List<String> getClaimAsList(String claim) {
    List<String> result = new ArrayList<>();
    
    Object value = payload.getValue(claim);
    if (value instanceof String) {
      result.add((String) value);
    } else if (value instanceof Iterable<?>) {
      ((Iterable<?>) value).forEach(a -> {
        if (a instanceof String) {
          result.add((String) a);
        } else if (a != null) {
          result.add(a.toString());
        }
      });
    } else if (value instanceof Object[]) {
      Object[] objArray = (Object[]) value;
      for (int i = 0; i < objArray.length; ++i) {
        if (objArray[i] instanceof String) {
          result.add((String) objArray[i]);
        } else if (objArray[i] != null) {
          result.add(objArray[i].toString());
        }
      }
    }
    return result;
  }
  
  /**
   * Checks whether the JWT has the given claim with the given value.
   * If the claim has multiple values this check returns true if any of the values matches value.
   * The comparison with value is case sensitive.
   * Note that this method cannot be used for scope claims because they are a single space-delimited string.
   * @param claim The name of the claim to check.
   * @param requiredValue The value to check it against.
   * @return True if any value of the claim in the JWT matches the value.
   */
  public boolean has(String claim, String requiredValue) {
    Object value = payload.getValue(claim);
    if (value instanceof String) {
      return requiredValue.equals(value);
    } else if (value instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) value) {
        if (item != null) {
          if (item instanceof String) {
            if (requiredValue.equals(item)) {
              return true;
            }
          } else {
            if (requiredValue.equals(item.toString())) {
              return true;
            }
          }
        }
      }
    } else if (value instanceof Object[]) {
      Object[] objArray = (Object[]) value;
      for (int i = 0; i < objArray.length; ++i) {
        Object item = objArray[i];
        if (item != null) {
          if (item instanceof String) {
            if (requiredValue.equals(item)) {
              return true;
            }
          } else {
            if (requiredValue.equals(item.toString())) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }
  
  /**
   * Get the value used to calculate the signature - base64(header) + "." + base64(payload).
   * @return the value used to calculate the signature - base64(header) + "." + base64(payload).
   */
  public String getSignatureBase() {
    return signatureBase;
  }

  /**
   * Get the signature from the JWT.
   * @return the signature from the JWT.
   */
  public String getSignature() {
    return signature;
  }
  
  /**
   * Get the algorithm specified in the JWT header.
   * @return the algorithm specified in the JWT header.
   */
  public String getAlgorithm() {
    return header.getString("alg");
  }
  
  /**
   * Get the algorithm specified in the JWT header as a {@link uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm}.
   * @return the algorithm specified in the JWT header as a {@link uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm}.
   */
  public JsonWebAlgorithm getJsonWebAlgorithm() {
    String alg = getAlgorithm();
    if (Strings.isNullOrEmpty(alg)) {
      return null;
    } else {
      return JsonWebAlgorithm.valueOf(alg);
    }
  }
  
  /**
   * Get the key ID specified in the JWT header.
   * @return the key ID specified in the JWT header.
   */
  public String getKid() {
    return header.getString("kid");
  }
  
  /**
   * Get the token subject specified in the JWT payload.
   * @return the token subject specified in the JWT payload.
   */
  public String getSubject() {
    return payload.getString("sub");
  }
  
  /**
   * Get the token issuer specified in the JWT payload.
   * @return the token issuer specified in the JWT payload.
   */
  public String getIssuer() {
    return payload.getString("iss");
  }
  
  /**
   * Get the token audience specified in the JWT payload.
   * The audience can be specified as either a single value or a JSON array, this method normalizes the result to an array of strings.
   * @return the token audience specified in the JWT payload.
   */
  public List<String> getAudience() {
    return getClaimAsList("aud");
  }
  
  /**
   * Return true if the aud claim contains the requiredValue.
   * @param requiredValue The value being sought in the aud claim.
   * @return true if the aud claim contains the requiredValue. 
   */
  public boolean hasAudience(String requiredValue) {
    return has("aud", requiredValue);
  }
  
  /**
   * Get the scopes specified in the JWT payload.
   * Note that this method parses the scope string into separate scopes.
   * @return the scopes specified in the JWT payload.
   */
  public List<String> getScope() {
    String scopeString = payload.getString("scope");
    if (Strings.isNullOrEmpty(scopeString)) {
      return Collections.emptyList();
    } else {
      return Arrays.asList(scopeString.split(" "));
    }
  }
  
  /**
   * Return true if the requiredValue is found in the scope.
   * 
   * The scope claim in JWTs is space delimited, which means that:
   * <ul>
   * <li>Either the requiredValue is found at the beginning of the claim or the code point before the requiredValue is s space.
   * <li>Either the requiredValue is found at the end of the claim or the code point after the requiredValue is s space.
   * </ul>
   * 
   * @param requiredValue The value being sought in the scope.
   * @return True if the requiredValue is found in the scope.
   */
  public boolean hasScope(String requiredValue) {
    String scopeString = payload.getString("scope");
    if (Strings.isNullOrEmpty(scopeString)) {
      return false;
    } else {
      int idx = scopeString.indexOf(requiredValue);
      if (idx < 0) {
        return false;
      }
      if (idx == 0 || scopeString.codePointBefore(idx) == SPACE) {
        int reqLen = requiredValue.length();
        if (idx == (scopeString.length() - reqLen) || scopeString.codePointAt(idx + reqLen) == SPACE) {
          return true;
        }
      }
      return false;
    }
  }
  
  /**
   * Get the groups specified in the JWT payload.
   * @return the groups specified in the JWT payload.
   */
  public List<String> getGroups() {
    return getClaimAsList("groups");
  }
  
  /**
   * Return true if the groups claim contains the requiredValue.
   * @param requiredValue The value being sought in the groups claim.
   * @return true if the groups claim contains the requiredValue. 
   */
  public boolean hasGroup(String requiredValue) {
    return has("groups", requiredValue);
  }    
  
  /**
   * Get the roles specified in the JWT payload.
   * @return the roles specified in the JWT payload.
   */
  public List<String> getRoles() {
    return getClaimAsList("roles");
  }
  
  /**
   * Return true if the roles claim contains the requiredValue.
   * @param requiredValue The value being sought in the roles claim.
   * @return true if the roles claim contains the requiredValue. 
   */
  public boolean hasRole(String requiredValue) {
    return has("roles", requiredValue);
  }    
  
  /**
   * Get the expiration timestamp specified in the JWT payload.
   * 
   * The expiration timestamp is defined as seconds since epoch (1970-01-01T00:00:00Z UTC), see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a> and <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-2">Section 2</a>.
   * 
   * @return the expiration timestamp specified in the JWT payload.
   */
  public Long getExpiration() {
    // Seconds since epoch
    return payload.getLong("exp");    
  }
  
  /**
   * Get the expiration timestamp specified in the JWT payload as a LocalDateTime.
   * @return the expiration timestamp specified in the JWT payload as a LocalDateTime.
   */
  public LocalDateTime getExpirationLocalDateTime() {
    // Seconds since epoch
    Long exp = getExpiration();
    if (exp != null) {
      return LocalDateTime.ofEpochSecond(getExpiration(), 0, ZoneOffset.UTC);
    } else {
      return null;
    }
  }
  
  /**
   * Get the not-valid-before timestamp specified in the JWT payload.
   * 
   * The not-valid-before timestamp is defined as seconds since epoch (1970-01-01T00:00:00Z UTC), see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">RFC 7519 Section 4.1.5</a> and <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-2">Section 2</a>.
   * 
   * @return the not-valid-before timestamp specified in the JWT payload.
   */
  public Long getNotBefore() {
    // Seconds since epoch
    return payload.getLong("nbf");    
  }
  
  /**
   * Get the not-valid-before timestamp specified in the JWT payload as a LocalDateTime.
   * @return the not-valid-before timestamp specified in the JWT payload as a LocalDateTime.
   */
  public LocalDateTime getNotBeforeLocalDateTime() {
    // Seconds since epoch
    Long nbf = getNotBefore();
    if (nbf != null) {
      return LocalDateTime.ofEpochSecond(getNotBefore(), 0, ZoneOffset.UTC);
    } else {
      return null;
    }
  }

  /**
   * Get the payload as a JSON string.
   * @return the payload as a JSON string.
   */
  public String getPayloadAsString() {
    return payload.encode();
  }
  
}
