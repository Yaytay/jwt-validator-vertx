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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author jtalbut
 */
public class DiscoveryDataTest {
  
  private static final String JSON = "{\n" +
                "  \"issuer\": \"http://users.test/api\",\n" +
                "  \"authorization_endpoint\": \"http://users.test/oauth/authorize\",\n" +
                "  \"token_endpoint\": \"http://users.test/api/token\",\n" +
                "  \"response_types_supported\": [\n" +
                "    \"code\",\n" +
                "    \"id_token\",\n" +
                "    \"token id_token\"\n" +
                "  ],\n" +
                "  \"jwks_uri\": \"http://users.test/api/certificates\",\n" +
                "  \"id_token_signing_alg_values_supported\": [\n" +
                "    \"RS256\",\n" +
                "    \"RS512\"\n" +
                "  ],\n" +
                "  \"token_endpoint_auth_methods_supported\": [\n" +
                "    \"client_secret_basic\"\n" +
                "  ],\n" +
                "  \"subject_types_supported\": [\n" +
                "    \"public\"\n" +
                "  ]\n" +
                "}          \n" +
                "";

  @Test
  public void testGetExpiry() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertEquals(0, dd.getExpiry());
  }

  @Test
  public void testGet() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.get("wibble"));
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals(new JsonArray("[\"client_secret_basic\"]"), dd.get("token_endpoint_auth_methods_supported"));
  }

  @Test
  public void testGetIssuer() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getIssuer());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals("http://users.test/api", dd.getIssuer());
  }

  @Test
  public void testGetAuthorizationEndpoint() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getAuthorizationEndpoint());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals("http://users.test/oauth/authorize", dd.getAuthorizationEndpoint());
  }

  @Test
  public void testGetTokenEndpoint() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getTokenEndpoint());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals("http://users.test/api/token", dd.getTokenEndpoint());
  }

  @Test
  public void testGetUserinfoEndpoint() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getUserinfoEndpoint());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getUserinfoEndpoint());
  }

  @Test
  public void testGetJwksUri() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getJwksUri());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals("http://users.test/api/certificates", dd.getJwksUri());
  }

  @Test
  public void testGetRegistrationEndpoint() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getRegistrationEndpoint());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getRegistrationEndpoint());
  }

  @Test
  public void testGetScopesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getScopesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getScopesSupported());
  }

  @Test
  public void testGetResponseTypesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getResponseTypesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals(new JsonArray("[\"code\",\"id_token\",\"token id_token\"]"), dd.getResponseTypesSupported());
  }

  @Test
  public void testGetResponseModesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getResponseModesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getResponseModesSupported());
  }

  @Test
  public void testGetGrantTypesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getGrantTypesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getGrantTypesSupported());
  }

  @Test
  public void testGetAcrValuesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getAcrValuesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertNull(dd.getAcrValuesSupported());
  }

  @Test
  public void testGetSubjectTypesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getSubjectTypesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals(new JsonArray("[\"public\"]"), dd.getSubjectTypesSupported());
  }

  @Test
  public void testGetIdTokenSigningAlgValuesSupported() {
    DiscoveryData dd = new DiscoveryData(0, new JsonObject("{}"));
    assertNull(dd.getIdTokenSigningAlgValuesSupported());
    dd = new DiscoveryData(0, new JsonObject(JSON));
    assertEquals(new JsonArray("[\"RS256\",\"RS512\"]"), dd.getIdTokenSigningAlgValuesSupported());
  }
  
}
