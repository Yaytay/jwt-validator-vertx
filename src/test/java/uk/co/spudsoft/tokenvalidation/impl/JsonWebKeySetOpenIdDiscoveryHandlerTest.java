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
package uk.co.spudsoft.tokenvalidation.impl;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import uk.co.spudsoft.tokenvalidation.DiscoveryData;
import uk.co.spudsoft.tokenvalidation.JWK;


/**
 *
 * @author jtalbut
 */
@ExtendWith(VertxExtension.class)
public class JsonWebKeySetOpenIdDiscoveryHandlerTest {
  
  @Test
  public void testIssuerRegexes(Vertx vertx) {
    WebClient webClient = WebClient.create(vertx);
    assertThrows(IllegalArgumentException.class, () -> new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(), 60));
    assertThrows(IllegalArgumentException.class, () -> new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(""), 60));
    assertThrows(IllegalArgumentException.class, () -> new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList("[a-"), 60));
  }
  
  @Test
  public void testValidateIssuer(Vertx vertx) {
    WebClient webClient = WebClient.create(vertx);
    JWKSOpenIdDiscoveryHandlerImpl impl = new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList("bob"), 60);
    assertThrows(IllegalArgumentException.class, () -> impl.validateIssuer("fred"));
  }

  @Test
  public void testPerformOpenIdDiscoveryWithBadUrl(Vertx vertx) {
    WebClient webClient = WebClient.create(vertx);
    JWKSOpenIdDiscoveryHandlerImpl impl = new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(".*"), 60);
    assertTrue(impl.performOpenIdDiscovery("fred").failed());    
    assertEquals("Parse of signed JWT failed", impl.performOpenIdDiscovery("fred").cause().getMessage());    
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testPerformOpenIdDiscoveryReturnsBadStatus() {
    WebClient webClient = mock(WebClient.class);

    HttpRequest<Buffer> request = mock(HttpRequest.class);
    when(webClient.getAbs("http://fred/.well-known/openid-configuration")).thenReturn(request);
    HttpResponse<Buffer> response = mock(HttpResponse.class);
    when(request.send()).thenReturn(Future.succeededFuture(response));
    when(response.statusCode()).thenReturn(567);
    
    JWKSOpenIdDiscoveryHandlerImpl impl = new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(".*"), 60);
    assertEquals("Request to http://fred/.well-known/openid-configuration returned 567", impl.performOpenIdDiscovery("http://fred/").cause().getMessage());    
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testPerformOpenIdDiscovery() {
    WebClient webClient = mock(WebClient.class);

    HttpRequest<Buffer> request = mock(HttpRequest.class);
    when(webClient.getAbs("http://carol/.well-known/openid-configuration")).thenReturn(request);
    HttpResponse<Buffer> response = mock(HttpResponse.class);
    when(request.send()).thenReturn(Future.succeededFuture(response));
    when(response.statusCode()).thenReturn(200);
    when(response.bodyAsString()).thenReturn("{\"jwks_uri\":\"http://henry/jwks\"}");
    when(response.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap().add("cache-control", "bob=3,    max-age=1000, fred=1,max-age=900,max-age=-14, max-age=seven  "));
    
    JWKSOpenIdDiscoveryHandlerImpl impl = new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(".*"), 60);
    assertEquals("http://henry/jwks", impl.performOpenIdDiscovery("http://carol").result().getJwksUri());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testFindJwk() {
    WebClient webClient = mock(WebClient.class);

    HttpRequest<Buffer> request = mock(HttpRequest.class);
    when(webClient.getAbs("http://carol/.well-known/openid-configuration")).thenReturn(request);
    HttpResponse<Buffer> response = mock(HttpResponse.class);
    when(request.send()).thenReturn(Future.succeededFuture(response));
    when(response.statusCode()).thenReturn(200);
    when(response.bodyAsString()).thenReturn("{\"jwks_uri\":\"http://henry/jwks\"}");
    when(response.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap().add("cache-control", "bob=3,    max-age=1000, fred=1,max-age=900,max-age=-14, max-age=seven  "));
    
    JWKSOpenIdDiscoveryHandlerImpl impl = new JWKSOpenIdDiscoveryHandlerImpl(webClient, Arrays.asList(".*"), 60);
    DiscoveryData dd1 = impl.performOpenIdDiscovery("http://carol").result();
    assertNotNull(dd1);
    assertEquals("http://henry/jwks", dd1.getJwksUri());
    DiscoveryData dd2 = impl.performOpenIdDiscovery("http://carol").result();
    assertNotNull(dd2);
    assertEquals("http://henry/jwks", dd2.getJwksUri());
    
    HttpRequest<Buffer> request2 = mock(HttpRequest.class);
    when(webClient.getAbs("http://henry/jwks")).thenReturn(request2);
    HttpResponse<Buffer> response2 = mock(HttpResponse.class);
    when(request2.send()).thenReturn(Future.succeededFuture(response2));
    when(response2.statusCode()).thenReturn(200);
    when(response2.bodyAsString()).thenReturn("{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"4cefa0d5-faa5-4a32-896e-aa3ff7effa7a\",\"x\":\"gYaeDr1C3-qbtzWrm8KKgAd6wLWLUlqti6fuqT2TXOM\",\"y\":\"zBhaNgmNDcjOU3XgaayWjpB2fURjiiw5SFK9UKjo3v8\"}]}");
    when(response2.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap().add("cache-control", "bob=3,    max-age=100000, fred=1,max-age=900,max-age=-14, max-age=seven  "));
    
    JWK jwk1 = impl.findJwk(dd1, "4cefa0d5-faa5-4a32-896e-aa3ff7effa7a").result();
    JWK jwk2 = impl.findJwk(dd1, "4cefa0d5-faa5-4a32-896e-aa3ff7effa7a").result();
  }
  
}
