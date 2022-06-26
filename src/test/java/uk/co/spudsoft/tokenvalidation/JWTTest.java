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
package uk.co.spudsoft.tokenvalidation;

import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;


/**
 *
 * @author jtalbut
 */
public class JWTTest {
  
  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();  
  
  private static String buildJwt(JsonObject header, JsonObject payload) {
    return BASE64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString("SIGNATURE".getBytes(StandardCharsets.UTF_8))
            ;
  }
  
  @Test
  public void testParseJws() {
    assertThrows(IllegalArgumentException.class, () -> JWT.parseJws("a"));
    assertThrows(IllegalArgumentException.class, () -> JWT.parseJws("a.b.c.d"));
  }

  @Test
  public void testGetPayloadSize() {
  }

  @Test
  public void testGetClaim() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                    , 
                    new JsonObject()
                            .put("key", "value")
            )
    );
    assertNull(jwt.getClaim("nonexistant"));
    assertEquals("value", jwt.getClaim("key"));
  }

  @Test
  public void testGetSignatureBase() {
    JsonObject header = new JsonObject()
            .put("alg", "none")
            ;
    JsonObject payload = new JsonObject()
            .put("key", "value")
            ;
    JWT jwt = JWT.parseJws(buildJwt(header, payload));
    String requiredSignatureBase = 
            BASE64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8))
            ;
    assertEquals(requiredSignatureBase, jwt.getSignatureBase());
  }

  @Test
  public void testGetSignature() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                    , 
                    new JsonObject()
                            .put("key", "value")
            )
    );
    assertEquals("U0lHTkFUVVJF", jwt.getSignature());
  }

  @Test
  public void testGetAlgorithm() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
                            .put("key", "value")
            )
    );
    assertEquals("none", jwt.getAlgorithm());
  }

  @Test
  public void testGetJsonWebAlgorithm() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
                            .put("key", "value")
            )
    );
    assertEquals(JsonWebAlgorithm.none, jwt.getJsonWebAlgorithm());
  }

  @Test
  public void testGetAudience() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getAudience());
    jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
                            .put("aud", new String[] {"Bob", "Carol"})
            )
    );
    assertArrayEquals(new String[] {"Bob", "Carol"}, jwt.getAudience());
  }

  @Test
  public void testGetExpiration() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getExpiration());
    assertNull(jwt.getExpirationLocalDateTime());
    jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
                            .put("exp", 1234567)
                              
            )
    );
    assertEquals(1234567, jwt.getExpiration());
    assertEquals(LocalDateTime.of(1970, 01, 15, 06, 56, 07), jwt.getExpirationLocalDateTime());
  }

  @Test
  public void testGetNotBefore() {
    JWT jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getNotBefore());
    assertNull(jwt.getNotBeforeLocalDateTime());
    jwt = JWT.parseJws(
            buildJwt(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
                            .put("nbf", 1234567)
                              
            )
    );
    assertEquals(1234567, jwt.getNotBefore());
    assertEquals(LocalDateTime.of(1970, 01, 15, 06, 56, 07), jwt.getNotBeforeLocalDateTime());
  }

  @Test
  public void testGetDiscoveryData_OpenIdDiscoveryHandler() {
  }

  @Test
  public void testGetDiscoveryData_0args() {
  }

  @Test
  public void testGetJwk_OpenIdDiscoveryHandler() {
  }

  @Test
  public void testGetJwk_0args() {
  }
  
}
