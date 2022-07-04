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

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;

/**
 * A JWT as defined by <A href="https://datatracker.ietf.org/doc/html/rfc7519">RFC7519</A>.
 * 
 * The internal representation is two JSON objects, the signature (as string) and the original string that was used to generate the signature (concatenated base 64 header and payload).
 * Values are not extracted or cached, they are simply retrieved on demand.
 * 
 * @author jtalbut
 */
public class JWT {
  
  private static final Base64.Decoder BASE64 = Base64.getUrlDecoder();
  
  private final JsonObject header;
  private final JsonObject payload;
  private final String signatureBase;
  private final String signature;
  
  private JWK jwk;

  /**
   * Constructor.
   * @param header The header from the JWT.
   * @param payload The payload from the JWT.
   * @param signatureBase The value used to calculate the signature - base64(header) + "." + base64(payload).
   * @param signature The signature from the JWT.
   */
  public JWT(JsonObject header, JsonObject payload, String signatureBase, String signature) {
    this.header = header;
    this.payload = payload;
    this.signatureBase = signatureBase;
    this.signature = signature;
  }
  
  /**
   * Parse a JWT in delimited string form.
   * @param token The JWT in delimited string form.
   * @return A newly created JWT object.
   */
  public static JWT parseJws(final String token) {
    String[] segments = token.split("\\.");
    if (segments.length < 2 || segments.length > 3) {
      throw new IllegalArgumentException("Not enough or too many segments [" + segments.length + "]");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = segments.length == 2 ? null : segments[2];

    // base64 decode and parseJws JSON
    JsonObject header = new JsonObject(new String(BASE64.decode(headerSeg), StandardCharsets.UTF_8));
    JsonObject payload = new JsonObject(new String(BASE64.decode(payloadSeg), StandardCharsets.UTF_8));

    return new JWT(header, payload, headerSeg + "." + payloadSeg, signatureSeg);
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
    return JsonWebAlgorithm.valueOf(header.getString("alg"));
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
  public String[] getAudience() {
    Object aud = payload.getValue("aud");
    if (aud instanceof String) {
      return new String[]{(String) aud};
    } else if (aud instanceof Iterable<?>) {
      ArrayList<String> result = new ArrayList<>();
      ((Iterable<?>) aud).forEach(a -> {
        if (a instanceof String) {
          result.add((String) a);
        }
      });
      return result.toArray(size -> new String[size]);
    } else {
      return null;
    }
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
   * Use the provided OpenIdDiscoveryHandler to call the jwks_uri from the discovery data to obtain the correct JWK for this JWT.
   *
   * The JWK will be cached in this JWT after it has been retrieved (and this method will return immediately if called again).
   * 
   * @param handler the OpenIdDiscoveryHandler that will perform the request for the JWK Set.
   * @return A Future that will be completed with a {@link uk.co.spudsoft.jwtvalidatorvertx.JWK} object when the discovery completes.
   */
  public Future<JWK> getJwk(JsonWebKeySetHandler handler) {
    if (this.jwk == null) {
      return handler.findJwk(getIssuer(), getKid())
              .onSuccess(j -> this.jwk = j);
    } else {
      return Future.succeededFuture(jwk);
    }
  }
  
  /**
   * Get the jwk cached by a successful call to {@link #getJwk(uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler)}.
   * This method should only be called in a handler chain following a successful called to {@link #getJwk(uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler)}.
   * 
   * @return the jwk cached by a successful called to {@link #getJwk(uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler)}.
   */
  public JWK getJwk() {
    return jwk;
  }
  
}
