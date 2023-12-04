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
import java.util.Arrays;
import java.util.Base64;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author jtalbut
 */
public class JwtTester {
  
  private static final Logger logger = LoggerFactory.getLogger(JwtTester.class);
  
  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();  
  
  private static String buildJwtString(JsonObject header, JsonObject payload) {
    return BASE64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString("SIGNATURE".getBytes(StandardCharsets.UTF_8))
            ;
  }
  
  private static Jwt buildJwt(JsonObject header, JsonObject payload) {
    return new Jwt(header, payload, null, null);
  }
  
  @Test
  public void testParseJws() {
    assertThrows(IllegalArgumentException.class, () -> Jwt.parseJws("a"));
    assertThrows(IllegalArgumentException.class, () -> Jwt.parseJws("a.b.c.d"));
  }

  @Test
  public void testGetPayloadSize() {
  }

  
  @Test
  public void testEmptyJwt() {
    Jwt jwt = new Jwt(null, null, null, null);
    assertNull(jwt.getAlgorithm());
    assertThat(jwt.getAudience(), empty());
    assertNull(jwt.getClaim("bob"));
    assertNull(jwt.getExpiration());
    assertNull(jwt.getExpirationLocalDateTime());
    assertThat(jwt.getGroups(), empty());
    assertNull(jwt.getIssuer());
    assertNull(jwt.getJsonWebAlgorithm());
    assertNull(jwt.getKid());
    assertNull(jwt.getNotBefore());
    assertNull(jwt.getNotBeforeLocalDateTime());
    assertEquals(0, jwt.getPayloadSize());
    assertThat(jwt.getRoles(), empty());
    assertThat(jwt.getScope(), empty());
    assertNull(jwt.getSignature());
    assertNull(jwt.getSignatureBase());
    assertNull(jwt.getSubject());
  }
  @Test
  public void testGetClaim() {
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
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
    Jwt jwt = Jwt.parseJws(buildJwtString(header, payload));
    String requiredSignatureBase = 
            BASE64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8))
            ;
    assertEquals(requiredSignatureBase, jwt.getSignatureBase());
  }

  @Test
  public void testGetSignature() {
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
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
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
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
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
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
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertThat(jwt.getAudience(), empty());
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("aud", new Object[] {"Bob", "Carol", null, 9})
    );
    assertEquals(Arrays.asList("Bob", "Carol", "9"), jwt.getAudience());
    assertTrue(jwt.hasAudience("Bob"));
    assertTrue(jwt.hasAudience("Carol"));
    assertTrue(jwt.hasAudience("9"));
    assertFalse(jwt.hasAudience("Ted"));
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("aud", Arrays.asList("Bob", "Carol", null, 9))
    );
    assertEquals(Arrays.asList("Bob", "Carol", "9"), jwt.getAudience());
  }

  @Test
  public void testHasGroup() {
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertFalse(jwt.hasGroup("g1"));
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("groups", new Object[] {"g1", "g2", null, 9})
    );
    assertEquals(Arrays.asList("g1", "g2", "9"), jwt.getGroups());
    assertTrue(jwt.hasGroup("g1"));
    assertTrue(jwt.hasGroup("g2"));
    assertTrue(jwt.hasGroup("9"));
    assertFalse(jwt.hasGroup("Ted"));
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("groups", Arrays.asList("g1", "g2", null, 9))
    );
    assertTrue(jwt.hasGroup("g1"));
    assertTrue(jwt.hasGroup("g2"));
    assertTrue(jwt.hasGroup("9"));
    assertFalse(jwt.hasGroup("Ted"));
  }

  @Test
  public void testHasRole() {
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertFalse(jwt.hasRole("r1"));
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("roles", new Object[] {"r1", "r2", null, 9})
    );
    assertEquals(Arrays.asList("r1", "r2", "9"), jwt.getRoles());
    assertTrue(jwt.hasRole("r1"));
    assertTrue(jwt.hasRole("r2"));
    assertTrue(jwt.hasRole("9"));
    assertFalse(jwt.hasRole("Ted"));
    jwt = buildJwt(
            new JsonObject()
                    .put("alg", "none")
            , 
            new JsonObject()
                    .put("roles", Arrays.asList("r1", "r2", null, 9))
    );
    assertTrue(jwt.hasRole("r1"));
    assertTrue(jwt.hasRole("r2"));
    assertTrue(jwt.hasRole("9"));
    assertFalse(jwt.hasRole("Ted"));
  }

  @Test
  public void testGetExpiration() {
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getExpiration());
    assertNull(jwt.getExpirationLocalDateTime());
    jwt = Jwt.parseJws(
            buildJwtString(
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
    Jwt jwt = Jwt.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getNotBefore());
    assertNull(jwt.getNotBeforeLocalDateTime());
    jwt = Jwt.parseJws(
            buildJwtString(
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
  public void testGetScopes() {
    Jwt jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one")));
    assertEquals(Arrays.asList("one"), jwt.getScope());
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scopes", "one")));
    assertEquals(Arrays.asList(), jwt.getScope());
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one two")));
    assertEquals(Arrays.asList("one", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("three"));
  }
  
  @Test
  public void testHasScope() {
    Jwt jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one αβγδεζηθικλμνξοπρςστυφχψω two")));
    assertEquals(Arrays.asList("one", "αβγδεζηθικλμνξοπρςστυφχψω", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "αβγδεζηθικλμνξοπρςστυφχψω one two")));
    assertEquals(Arrays.asList("αβγδεζηθικλμνξοπρςστυφχψω", "one", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one two αβγδεζηθικλμνξοπρςστυφχψω")));
    assertEquals(Arrays.asList("one", "two", "αβγδεζηθικλμνξοπρςστυφχψω"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one Xαβγδεζηθικλμνξοπρςστυφχψω two")));
    assertEquals(Arrays.asList("one", "Xαβγδεζηθικλμνξοπρςστυφχψω", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one αβγδεζηθικλμνξοπρςστυφχψωX two")));
    assertEquals(Arrays.asList("one", "αβγδεζηθικλμνξοπρςστυφχψωX", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject()));
    assertEquals(Arrays.asList(), jwt.getScope());
    assertFalse(jwt.hasScope("one"));
    assertFalse(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
  }

  @Test
  public void testGetPayloadAsString() {
    Jwt jwt = Jwt.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one αβγδεζηθικλμνξοπρςστυφχψω two")));
    assertEquals("{\"scope\":\"one αβγδεζηθικλμνξοπρςστυφχψω two\"}", jwt.getPayloadAsString());
  }  
}
