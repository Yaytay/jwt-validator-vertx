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
public class JWTTest {
  
  private static final Logger logger = LoggerFactory.getLogger(JWTTest.class);
  
  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();  
  
  private static String buildJwtString(JsonObject header, JsonObject payload) {
    return BASE64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8))
            + "."
            + BASE64.encodeToString("SIGNATURE".getBytes(StandardCharsets.UTF_8))
            ;
  }
  
  private static JWT buildJwt(JsonObject header, JsonObject payload) {
    return new JWT(header, payload, null, null);
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
  public void testEmptyJwt() {
    JWT jwt = new JWT(null, null, null, null);
    assertNull(jwt.getAlgorithm());
    assertThat(jwt.getAudience(), empty());
    assertNull(jwt.getClaim("bob"));
    assertNull(jwt.getExpiration());
    assertNull(jwt.getExpirationLocalDateTime());
    assertThat(jwt.getGroups(), empty());
    assertNull(jwt.getIssuer());
    assertNull(jwt.getJsonWebAlgorithm());
    assertNull(jwt.getJwk());
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(buildJwtString(header, payload));
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getExpiration());
    assertNull(jwt.getExpirationLocalDateTime());
    jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getNotBefore());
    assertNull(jwt.getNotBeforeLocalDateTime());
    jwt = JWT.parseJws(
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
    JWT jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one")));
    assertEquals(Arrays.asList("one"), jwt.getScope());
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scopes", "one")));
    assertEquals(Arrays.asList(), jwt.getScope());
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one two")));
    assertEquals(Arrays.asList("one", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("three"));
  }
  
  @Test
  public void testHasScope() {
    JWT jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one αβγδεζηθικλμνξοπρςστυφχψω two")));
    assertEquals(Arrays.asList("one", "αβγδεζηθικλμνξοπρςστυφχψω", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "αβγδεζηθικλμνξοπρςστυφχψω one two")));
    assertEquals(Arrays.asList("αβγδεζηθικλμνξοπρςστυφχψω", "one", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one two αβγδεζηθικλμνξοπρςστυφχψω")));
    assertEquals(Arrays.asList("one", "two", "αβγδεζηθικλμνξοπρςστυφχψω"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertTrue(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one Xαβγδεζηθικλμνξοπρςστυφχψω two")));
    assertEquals(Arrays.asList("one", "Xαβγδεζηθικλμνξοπρςστυφχψω", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject().put("scope", "one αβγδεζηθικλμνξοπρςστυφχψωX two")));
    assertEquals(Arrays.asList("one", "αβγδεζηθικλμνξοπρςστυφχψωX", "two"), jwt.getScope());
    assertTrue(jwt.hasScope("one"));
    assertTrue(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
    jwt = JWT.parseJws(buildJwtString(new JsonObject().put("alg", "none"), new JsonObject()));
    assertEquals(Arrays.asList(), jwt.getScope());
    assertFalse(jwt.hasScope("one"));
    assertFalse(jwt.hasScope("two"));
    assertFalse(jwt.hasScope("αβγδεζηθικλμνξοπρςστυφχψω"));
    assertFalse(jwt.hasScope("three"));
  }

  private final static class TestJwksHandler implements JsonWebKeySetHandler {

    @Override
    public void validateIssuer(String issuer) throws IllegalArgumentException {
    }

    @Override
    public Future<JWK<?>> findJwk(String issuer, String kid) {
      try {
        return Future.succeededFuture(
                JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}"))
        );
      } catch(Throwable ex) {
        logger.error("Failed: ", ex);
        return null;
      }
    }
  }
  
  @Test
  public void testGetJwk() {
    JWT jwt = JWT.parseJws(
            buildJwtString(
                    new JsonObject()
                            .put("alg", "none")
                    , 
                    new JsonObject()
            )
    );
    assertNull(jwt.getJwk());
    assertEquals("d480cda8-8461-44cb-80cc-9ae13f8dafa8", jwt.getJwk(new TestJwksHandler()).result().getKid());
    assertEquals("d480cda8-8461-44cb-80cc-9ae13f8dafa8", jwt.getJwk(new TestJwksHandler()).result().getKid());
    assertEquals("d480cda8-8461-44cb-80cc-9ae13f8dafa8", jwt.getJwk().getKid());
  }
  
}
