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

import java.util.List;
import java.util.Map;

/**
 * Builder for creating simple JWTs.
 * <p>
 * This is not the most flexible JWT creator, but it many cases it is adequate.
 * <p>
 * Originally written for test purposes there are some circumstances in which it can be used for providing a simple JWT/JWKS setup.
 * @author jtalbut
 */
public interface TokenBuilder {

  /**
   * Construct a JWT.
   * If any of the testing methods are set the resulting token will be invalid.
   * 
   * @param jwa The algorithm to use to create the key if the key does not already exist in the cache.
   * If the key is already in ths cache then the jwa is only used to set the "alg" header claim.
   * If it permitted to use the {@link uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm#none} algorithm to generate the token, but this should only be done for testing and all validators will reject it.
   * @param kid The ID of the key to use to sign the token, may be null if (and only if) the jwa is {@link JsonWebAlgorithm#none}.
   * @param iss The issuer to put in the payload claims.
   * @param sub The subject to put in the payload claims.
   * @param aud The audience to put in the payload claims.v
   * @param nbf The not-before to put in the payload claims.
   * @param exp The expiry to put in the payload claims.
   * @param otherClaims Other claims to put in the payload.
   * @return A fully constructed and signed JWS (that may be broken in various ways if other settings are set).
   * @throws Exception If the security subsystem is unable to carry out required operations.
   */
  String buildToken(JsonWebAlgorithm jwa, String kid, String iss, String sub, List<String> aud, Long nbf, Long exp, Map<String, Object> otherClaims) throws Exception;

  /**
   * If set the header will not be valid base 64.
   * @param headerNotValidBase64 If true the header will not be valid base 64 (it will have one character removed from the end).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setHeaderNotValidBase64(boolean headerNotValidBase64);
  /**
   * If set the payload will not be valid base 64.
   * @param payloadNotValidBase64 If true the payload will not be valid base 64 (it will have one character removed from the end).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setPayloadNotValidBase64(boolean payloadNotValidBase64);
  /**
   * If set the signature will not be valid base 64.
   * @param signatureNotValidBase64 If true the signature will not be valid base 64 (it will have one character removed from the end).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setSignatureNotValidBase64(boolean signatureNotValidBase64);
  /**
   * If set the header will not be valid base 64.
   * @param headerNotJson If true the header will not be valid JSON (strings will have quotes stripped from them).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setHeaderNotJson(boolean headerNotJson);
  /**
   * If set the payload will not be valid base 64.
   * @param payloadNotJson If true the payload will not be valid JSON (strings will have quotes stripped from them).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setPayloadNotJson(boolean payloadNotJson);
  /**
   * If set the signature will not be a valid hash of the contents.
   * @param signatureNotValidHash If true signature will not be a valid hash of the contents (the final byte will be stripped).
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setSignatureNotValidHash(boolean signatureNotValidHash);
  /**
   * If set the kid in the token will be set to 'INVALID'.
   * @param kidInvalid If true the kid in the token will be set to 'INVALID'.
   * @return this, so that the method may be used in a fluent manner.
   */
  TokenBuilder setKidInvalid(boolean kidInvalid);
  
  
}
