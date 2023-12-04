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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Represents the data returned in an OpenID Connect Discovery response.
 * 
 * The data is stored in a JsonObject and fields are extracted from it as required (i.e. this class does not parse the JSON as such).
 * The specification for OpenID Connect Discovery is at https://openid.net/specs/openid-connect-discovery-1_0.html
 * 
 * @author jtalbut
 */
public class DiscoveryData {
  
  private final JsonObject json;

  /**
   * Constructor.
   * @param json The JSON data in the body of the discovery response.
   */
  public DiscoveryData(JsonObject json) {
    this.json = json;
  }

  /**
   * Get a value from the response.
   * @param key the key to extract from the response.
   * @return the value from the response with the given key.
   */
  public Object get(String key) {
    return json.getValue(key);
  }

  
  /**
   * Get the issuer.
   * 
   * REQUIRED. 
   * URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier. 
   * If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. 
   * This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.

   * @return the issuer.
   */
  public String getIssuer() {
    return json.getString("issuer");
  }
  
  /**
   * Get the authorization endpoint.
   * 
   * REQUIRED. 
   * URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
   * 
   * @return the authorization endpoint.
   */
  public String getAuthorizationEndpoint() {
    return json.getString("authorization_endpoint");
  }

  /**
   * Get the token endpoint.
   * 
   * URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
   * 
   * @return the token endpoint.
   */
  public String getTokenEndpoint() {
    return json.getString("token_endpoint");
  }

  /**
   * Get the user-info endpoint.
   * 
   * RECOMMENDED. 
   * URL of the OP's UserInfo Endpoint [OpenID.Core]. 
   * This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
   * 
   * @return the user-info endpoint.
   */
  public String getUserinfoEndpoint() {
    return json.getString("userinfo_endpoint");
  }

  /**
   * Get the JWKS URI.
   * 
   * REQUIRED. 
   * URL of the OP's JSON Web Key Set [JWK] document. 
   * This contains the signing key(s) the RP uses to validate signatures from the OP. 
   * The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. 
   * When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. 
   * Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. 
   * The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. 
   * When used, the bare key values MUST still be present and MUST match those in the certificate.
   * 
   * @return the JWKS URI.
   */
  public String getJwksUri() {
    return json.getString("jwks_uri");
  }
  
  /**
   * Get the registration endpoint.
   * 
   * RECOMMENDED. 
   * URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
   * 
   * @return the registration endpoint.
   */
  public String getRegistrationEndpoint() {
    return json.getString("registration_endpoint");
  }
  
  /**
   * Get the scopes supported.
   * 
   * RECOMMENDED. 
   * JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. 
   * The server MUST support the openid scope value. 
   * Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
   * 
   * @return the scopes supported.
   */
  public JsonArray getScopesSupported() {
    return json.getJsonArray("scopes_supported");
  }
  
  /**
   * Get the response types supported.
   * 
   * REQUIRED. 
   * JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. 
   * Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
   * 
   * @return the response types supported.
   */
  public JsonArray getResponseTypesSupported() {
    return json.getJsonArray("response_types_supported");
  }

  /**
   * Get the response modes supported.
   * 
   * OPTIONAL. 
   * JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. 
   * If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
   * 
   * @return the response modes supported.
   */
  public JsonArray getResponseModesSupported() {
    return json.getJsonArray("response_modes_supported");
  }

  /**
   * Get the grant types supported.
   * 
   * OPTIONAL. 
   * JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. 
   * Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. 
   * If omitted, the default value is ["authorization_code", "implicit"].
   * 
   * @return the grant types supported.
   */
  public JsonArray getGrantTypesSupported() {
    return json.getJsonArray("grant_types_supported");
  }

  /**
   * Get the authentication context class references supposed.
   * 
   * OPTIONAL. 
   * JSON array containing a list of the Authentication Context Class References that this OP supports.
   * 
   * @return the authentication context class references supposed.
   */
  public JsonArray getAcrValuesSupported() {
    return json.getJsonArray("acr_values_supported");
  }
  
  /**
   * Get the subject types supported.
   * 
   * REQUIRED. 
   * JSON array containing a list of the Subject Identifier types that this OP supports. 
   * Valid types include pairwise and public.
   * 
   * @return the subject types supported.
   */
  public JsonArray getSubjectTypesSupported() {
    return json.getJsonArray("subject_types_supported");
  }

  /**
   * Get the token signing algorithms supported.
   * 
   * REQUIRED. 
   * JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. 
   * The algorithm RS256 MUST be included. 
   * The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
   * 
   * @return the token signing algorithms supported.
   */
  public JsonArray getIdTokenSigningAlgValuesSupported() {
    return json.getJsonArray("id_token_signing_alg_values_supported");
  }
}
