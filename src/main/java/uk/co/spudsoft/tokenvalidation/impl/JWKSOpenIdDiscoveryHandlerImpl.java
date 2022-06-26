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

import com.google.common.base.Strings;
import io.vertx.core.Future;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.tokenvalidation.DiscoveryData;
import uk.co.spudsoft.tokenvalidation.JWK;
import uk.co.spudsoft.tokenvalidation.JsonWebKeySetOpenIdDiscoveryHandler;

/**
 * Default implementation of {@link uk.co.spudsoft.tokenvalidation.JsonWebKeySetHandler}.
 * @author jtalbut
 */
public class JWKSOpenIdDiscoveryHandlerImpl implements JsonWebKeySetOpenIdDiscoveryHandler {

  private static final Logger logger = LoggerFactory.getLogger(JWKSOpenIdDiscoveryHandlerImpl.class);
  
  private final long defaultJwkCacheDurationS;
  
  /**
   * Map from Issuer to DiscoveryData.
   */
  private final AsyncLoadingCache<String, DiscoveryData> discoveryDataCache;
  
  /**
   * Map from jwks_uri to Map from kid to JWK.
   */
  private final Map<String, AsyncLoadingCache<String, JWK>> kidCache;

  private final List<Pattern> acceptableIssuers;
  
  private final WebClient webClient;
  
  /**
   * Constructor.
   * @param webClient Vertx WebClient, for the discovery handler to make asynchronous web requests.
   * @param acceptableIssuerRegexes Collection of regular expressions that any issues will be checked against.
   * @param defaultJwkCacheDurationS Time (in seconds) to keep JWKs in cache if no cache-control: max-age header is found.
   * 
   * It is vital for the security of any system using OpenID Connect Discovery that it is only used with trusted issuers.
   */
  public JWKSOpenIdDiscoveryHandlerImpl(WebClient webClient, Collection<String> acceptableIssuerRegexes, long defaultJwkCacheDurationS) {
    this.webClient = webClient;
    if (acceptableIssuerRegexes == null || acceptableIssuerRegexes.isEmpty()) {
      throw new IllegalArgumentException("Acceptable issuer regular expressions must be passed in");
    }
    this.defaultJwkCacheDurationS = defaultJwkCacheDurationS;
    this.acceptableIssuers = acceptableIssuerRegexes.stream()
                    .map(re -> {
                      if (re == null || re.isBlank()) {
                        logger.warn("Null or empty pattern cannot be used: ", re);
                        return null;
                      }
                      try {
                        Pattern pattern = Pattern.compile(re);
                        logger.trace("Compiled acceptable issuer regex as {}", pattern.pattern());
                        return pattern;
                      } catch (Throwable ex) {
                        logger.warn("The pattern \"{}\" cannot be compiled: ", re, ex);
                        return null;
                      }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
    if (acceptableIssuers.isEmpty()) {
      throw new IllegalArgumentException("Acceptable issuer regular expressions must be passed in");
    }
    this.discoveryDataCache = new AsyncLoadingCache<>(dd -> dd.getExpiry());  
    this.kidCache = new HashMap<>();
  }

  @Override
  public void validateIssuer(String issuer) throws IllegalArgumentException {
    if (discoveryDataCache.containsKey(issuer)) {
      return ;
    }
    for (Pattern acceptableIssuer : acceptableIssuers) {
      if (acceptableIssuer.matcher(issuer).matches()) {
        return;
      }
    }
    logger.warn("Failed to find issuer \"{}\" in {}", issuer, acceptableIssuers);
    throw new IllegalArgumentException("Parse of signed JWT failed");
  }
  
  @Override
  public Future<DiscoveryData> performOpenIdDiscovery(String issuer) {
    
    try {
      validateIssuer(issuer);
    } catch (Throwable ex) {
      return Future.failedFuture(ex);
    }

    String discoveryUrl = issuer + (issuer.endsWith("/") ? "" : "/") + ".well-known/openid-configuration";
    return discoveryDataCache.get(issuer
            , () -> get(discoveryUrl)
                    .map(tjo -> new DiscoveryData(tjo.expiresMs, tjo.json))
    );
  }

  @Override
  public Future<JWK> findJwk(DiscoveryData discoveryData, String kid) {
    
    String jwksUri = discoveryData.getJwksUri();
    if (Strings.isNullOrEmpty(jwksUri)) {
      return Future.failedFuture("Discovery data does not contain jwks_uri");
    }
    
    AsyncLoadingCache<String, JWK> finalJwkCache;
    synchronized (kidCache) {
      AsyncLoadingCache<String, JWK> jwkCache = kidCache.get(jwksUri);
      if (jwkCache == null) {
        jwkCache = new AsyncLoadingCache<>(jwk -> jwk == null ? null : jwk.getExpiryMs());
        kidCache.put(jwksUri, jwkCache);
      }
      finalJwkCache = jwkCache;
    }
    
    return finalJwkCache.get(kid, () -> {
      return get(discoveryData.getJwksUri())
              .compose(tjo -> processJwkSet(finalJwkCache, tjo, kid));
    });
  }

  @Override
  public Future<JWK> findJwk(String issuer, String kid) {
    return performOpenIdDiscovery(issuer)
            .compose(dd -> findJwk(dd, kid));
  }
  
  static Future<JWK> processJwkSet(AsyncLoadingCache<String, JWK> jwkCache, TimedJsonObject data, String kid) {
    long expiry = data.expiresMs;
    JWK result = null;
    JsonObject foundKey = null;
    
    try {
      Object keysObject = data.json.getValue("keys");
      if (keysObject instanceof JsonArray) {
        JsonArray ja = (JsonArray) keysObject;
        for (Iterator<Object> iter = ja.iterator(); iter.hasNext();) {
          Object keyData = iter.next();
          try {
            if (keyData instanceof JsonObject) {
              JsonObject jo = (JsonObject) keyData;
              String keyId = jo.getString("kid");
              if (kid.equals(keyId)) {
                result = new JWK(expiry, jo);
                foundKey = jo;
              } else {
                JWK other = new JWK(expiry, jo);
                jwkCache.put(keyId, other);
              }
            }
          } catch (Throwable ex) {
            logger.warn("Failed to parse {} as a JWK: ", keyData, ex);
          }
        }
      } else {
        logger.error("Failed to get key {} from JWKS from {}", kid, data.json);
        return Future.failedFuture(
                new IllegalArgumentException("Parse of signed JWT failed",
                         new IllegalArgumentException("Failed to get public key for " + kid)
                )
        );
      }
    } catch (Throwable ex) {
      logger.error("Failed to get public key for {} from {}", kid, data.json);
      return Future.failedFuture(
              new IllegalArgumentException("Parse of signed JWT failed",
                       new IllegalArgumentException("Failed to get public key for " + kid)
              )
      );
    }
    if (result == null) {
      logger.error("Failed to find key {} from JWKS from {}", kid, data.json);
      return Future.failedFuture(
              new IllegalArgumentException("Parse of signed JWT failed",
                       new IllegalArgumentException("Failed to find key " + kid)
              )
      );
    } else {
      if (logger.isDebugEnabled()) {
        logger.debug("Got new {} public key with id {}: {}", result.getKey().getAlgorithm(), kid, foundKey);
      } else {
        logger.info("Got new public key with id {}", kid);
      }
      return Future.succeededFuture(result);
    }
  }
 
  private static boolean succeeded(int statusCode) {
    return statusCode >= 200 && statusCode < 300;
  }  
  
  private static class TimedJsonObject {
    public final long expiresMs;
    public final JsonObject json;

    TimedJsonObject(long expiresMs, JsonObject json) {
      this.expiresMs = expiresMs;
      this.json = json;
    }
        
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
      maxAgeSecondsSinceEpoch = defaultJwkCacheDurationS;
    }
    return requestTimeMsSinceEpoch + maxAgeSecondsSinceEpoch * 1000;
  }
  
  
  private Future<TimedJsonObject> get(String url) {

    try {
      new URL(url);
    } catch (MalformedURLException ex) {
      logger.error("The JWKS URI ({}) is not a valid URL: ", url, ex);
      return Future.failedFuture("Parse of signed JWT failed");
    }

    long requestTime = System.currentTimeMillis();
    return webClient.getAbs(url)
            .send()
            .map(response -> {
              if (succeeded(response.statusCode())) {
                String body = response.bodyAsString();
                return new TimedJsonObject(calculateExpiry(requestTime, response), new JsonObject(body));
              } else {
                logger.debug("Request to {} returned {}: {}", url, response.statusCode(), response.bodyAsString());
                throw new IllegalStateException("Request to " + url + " returned " + response.statusCode());
              }
            });
  }
}
