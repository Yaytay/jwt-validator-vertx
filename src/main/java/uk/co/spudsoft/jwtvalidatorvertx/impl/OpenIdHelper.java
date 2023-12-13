/*
 * Copyright (C) 2023 jtalbut
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
package uk.co.spudsoft.jwtvalidatorvertx.impl;

import io.vertx.core.Future;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AsyncLoadingCache.TimedObject;

/**
 * Helper class for performing OpenID Discovery and JWKS requests.
 * 
 * @author njt
 */
public class OpenIdHelper {
  
  private static final Logger logger = LoggerFactory.getLogger(OpenIdHelper.class);
  
  private final WebClient webClient;
  private final long defaultCacheDurationS;

  /**
   * Constructor.
   * @param webClient The Vert.x WebClient to use for making HTTP requests.
   * @param defaultCacheDurationS The default time that the caller should cache results.
   */
  public OpenIdHelper(WebClient webClient, long defaultCacheDurationS) {
    this.webClient = webClient;
    this.defaultCacheDurationS = defaultCacheDurationS;
  }

  private static boolean succeeded(int statusCode) {
    return statusCode >= 200 && statusCode < 300;
  }  
  
  private long calculateExpiry(long requestTimeMsSinceEpoch, HttpResponse<?> response) {
    long maxAgeSecondsSinceEpoch = Long.MAX_VALUE;
    for (String header : response.headers().getAll(HttpHeaders.CACHE_CONTROL)) {
      for (String headerDirective : header.split(",")) {
        String[] directiveParts = headerDirective.split("=", 2);
        
        directiveParts[0] = directiveParts[0].trim();
        if ("max-age".equals(directiveParts[0])) {
          try {
            long value = Long.parseLong(directiveParts[1].replaceAll("\"", "").trim().toLowerCase());
            if (value > 0 && value < maxAgeSecondsSinceEpoch) {
              maxAgeSecondsSinceEpoch = value;
            }
          } catch (NumberFormatException e) {
            logger.warn("Invalid max-age cache-control directive ({}): ", directiveParts[1], e);
          }
        }
      }
    }
    // If we don't get any other instruction the value gets cached for one minute.
    if (maxAgeSecondsSinceEpoch == Long.MAX_VALUE) {
      maxAgeSecondsSinceEpoch = defaultCacheDurationS;
    }
    return requestTimeMsSinceEpoch + maxAgeSecondsSinceEpoch * 1000;
  }
  
  /**
   * Get a JsonObject from a URL and return it as Future with an expiry time.
   * @param url The URL to be got.
   * @return A TimedObject containing JSON from the URL and an expiry time based on the Cache-Control max-age header.
   */
  public Future<TimedObject<JsonObject>> get(String url) {

    long requestTime = System.currentTimeMillis();
    try {
      return webClient.getAbs(url)
              .send()
              .map(response -> {
                if (succeeded(response.statusCode())) {
                  String body = response.bodyAsString();
                  return new TimedObject<>(new JsonObject(body), calculateExpiry(requestTime, response));
                } else {
                  logger.debug("Request to {} returned {}: {}", url, response.statusCode(), response.bodyAsString());
                  throw new IllegalStateException("Request to " + url + " returned " + response.statusCode());
                }
              });
    } catch (Exception ex) {
      logger.error("The JWKS URI ({}) is not a valid URL: ", url, ex);
      return Future.failedFuture(new IllegalArgumentException("Parse of signed JWT failed", ex));
    }

  }
  
  
}
