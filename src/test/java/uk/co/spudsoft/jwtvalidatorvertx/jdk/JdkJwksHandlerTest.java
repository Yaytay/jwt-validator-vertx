/*
 * Copyright (C) 2023 njt
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
package uk.co.spudsoft.jwtvalidatorvertx.jdk;

import static io.restassured.RestAssured.given;
import java.net.URI;
import static org.hamcrest.Matchers.equalTo;
import org.junit.jupiter.api.Test;


/**
 *
 * @author njt
 */
public class JdkJwksHandlerTest {
  
  @Test
  public void testStart() throws Exception {
    try (JdkJwksHandler handler = JdkJwksHandler.create()) {
      handler.start();

      given()
              .log().all()
              .get(new URI(handler.getBaseUrl() + "/.well-known/openid-configuration"))
              .then()
              .log().all()
              .statusCode(200)
              .body(equalTo("{\"jwks_uri\":\"" + handler.getBaseUrl() + "/jwks\"}"))
              ;

      given()
              .log().all()
              .get(new URI(handler.getBaseUrl() + "/fred"))
              .then()
              .log().all()
              .statusCode(404)
              .body(equalTo("Not found"))
              ;
    }
  }

}
