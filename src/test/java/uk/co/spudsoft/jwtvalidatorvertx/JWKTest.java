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

import io.vertx.core.json.JsonObject;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 *
 * @author jtalbut
 */
public class JWKTest {
  
  /**
   * Test of getKey method, of class JWK.
   */
  @Test
  public void testConstructor() throws Throwable {
    System.out.println("getKey");
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject()));
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject().put("kty", "")));
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject().put("kty", " ")));
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject().put("kty", "bob")));
    // Bad algorithm
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"alg\":\"RS256\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}")));
  }

  @Test  
  public void testBadEcJwks() throws Throwable {
    // Sample good one:
    JWK<?> jwk = JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}"));
    // No kty
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}")));
    // No crv
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}")));
    // No kid
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}")));
    // No x
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}")));
    // No y
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\"}")));
  }

  @Test  
  public void testBadEdJwks() throws Throwable {
    // Sample good one:
    JWK<?> jwk = JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}"));
    // No kty
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
    // No crv
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
    // No kid
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
    // No x
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\"}")));
  }

  @Test  
  public void testBadRsaJwks() throws Throwable {
    // Sample good one:
    JWK<?> jwk = JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}"));
    // No kty
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
    // No e
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
    // No kid
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
    // No n
    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\"}")));
  }

  @Test
  public void testGetKid() throws Throwable {
    JWK<?> jwk = JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}"));
    assertEquals("d480cda8-8461-44cb-80cc-9ae13f8dafa8", jwk.getKid());
  }

  @Test
  public void testGetUse() throws Throwable {
    JWK<?> jwk = JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}"));
    assertEquals("sig", jwk.getUse());
    jwk = JWK.create(0, new JsonObject("{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"d480cda8-8461-44cb-80cc-9ae13f8dafa8\",\"x\":\"IhfvcFBxDBU1jXMlNQmf77IbzIfuj2jMcx8Vd3dUZeA\",\"y\":\"ZfAvxJn56o8IJoHAysSKZ5LQt9mKMb2_nIB0ohmpCsY\"}"));
    assertNull(jwk.getUse());
  }
  
}
