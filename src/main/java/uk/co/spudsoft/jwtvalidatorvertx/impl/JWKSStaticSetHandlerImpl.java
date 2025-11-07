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
package uk.co.spudsoft.jwtvalidatorvertx.impl;

import com.google.common.collect.ImmutableList;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetKnownJwksHandler;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AsyncLoadingCache.TimedObject;

/**
 * Implementation of {@link JsonWebKeySetKnownJwksHandler} that stores JWKs in a HashMap.
 * 
 * @author jtalbut
 */
public class JWKSStaticSetHandlerImpl implements JsonWebKeySetKnownJwksHandler {
  
  private static final Logger logger = LoggerFactory.getLogger(JWKSOpenIdDiscoveryHandlerImpl.class);
  
  private final List<String> jwksUrls;
  private final Map<String, TimedObject<JWK>> keys = new HashMap<>();
  private final AtomicReference<Future<Void>> refreshFuture = new AtomicReference<>(null);
  
  private final OpenIdHelper openIdHelper;

  /**
   * Constructor.
   * 
   * With a static map of JWKs the security of the system is not compromised by allowing any issuer, though you should question why this is necessary.
   * 
   * Each JWKs endpoint must use KIDs that are globally unique.
   * 
   * When a KID is requested and cannot be found ALL the configured JWKS URLs will be queried and the single cache will be updated.
   * Entries in the cache will be retained for a duration based on either the Cache-Control max-age header of the response or, 
   * if that is not present, the defaultJwkCacheDuration.
   * Given that only positive responses are cached it is reasonable for the defaultJwkCacheDuration to be 24 hours (or more).
   * 
   * @param webClient Vertx WebClient instance, that will be used for querying the JWKS URLs.
   * @param jwksUrls Static set of URLs that will be used for obtaining JWKs.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * 
   * The JWKS URLs must be accessed via https for the environment to offer any security.
   * This is not enforced at the code level.
   * 
   */
  public JWKSStaticSetHandlerImpl(WebClient webClient, Collection<String> jwksUrls, Duration defaultJwkCacheDuration) {
    this.jwksUrls = ImmutableList.copyOf(jwksUrls);
    this.openIdHelper = new OpenIdHelper(webClient, defaultJwkCacheDuration.toSeconds());
  }
  
  @Override
  public void optimize() {
    findJwk(null, "");
  }
  
  private JWK findJwk(String kid) {
    TimedObject<JWK> jwk = keys.get(kid);
    long now = System.currentTimeMillis();
    if (null != jwk) {
      if (jwk.expiredBefore(now)) {
        keys.remove(kid);
      } else {
        return jwk.getValue();
      }
    }
    return null;
  }

  @Override
  public Future<JWK> findJwk(String issuer, String kid) {
    synchronized (keys) {
      JWK jwk = findJwk(kid);
      if (jwk != null) {
        return Future.succeededFuture(jwk);
      }
    
      Promise<Void> refreshPromise = Promise.promise();
      Future<Void> newRefreshFuture = refreshPromise.future();
      Future<Void> result = refreshFuture.compareAndExchange(null, newRefreshFuture);
      if (result == null) {
        result = updateCache()
                .compose(newkeys -> {
                  synchronized (keys) {
                    keys.putAll(newkeys);
                  }
                  refreshPromise.complete();
                  refreshFuture.set(null);
                  return Future.succeededFuture();
                });
      } 
      return result.compose(v -> {
        synchronized (keys) {
          JWK newjwk = findJwk(kid);
          if (newjwk != null) {
            return Future.succeededFuture(newjwk);
          }
          return Future.failedFuture(new IllegalArgumentException("The key \"" + kid + "\" cannot be found."));
        }
      });
    }
  }
  
  private Future<Map<String, TimedObject<JWK>>> updateCache() {
    
    if (jwksUrls.isEmpty()) {
      logger.error("Unable to validate any JWKs because no jwksUrls have been configured");
      IllegalStateException ex = new IllegalStateException("Unable to validate any JWKs because no jwksUrls have been configured");
      return Future.failedFuture(ex);
    }
    
    Map<String, TimedObject<JWK>> result = new HashMap<>();
    List<Future<Void>> futures = new ArrayList<>();
    
    for (String jwksUrl : jwksUrls) {
      futures.add(
              openIdHelper.get(jwksUrl)
                      .compose(tjo -> {
                        return addKeysToCache(jwksUrl, tjo, result);
                      })
                      .onFailure(ex -> {
                        logger.warn("Failed to get JWKS from {}: ", jwksUrl, ex);
                      })
      );
    }
    
    return Future.join(futures)
            .compose(cf -> {
              return Future.succeededFuture(result);
            })
            .recover(ex -> {
              logger.warn("There were some failures to download JWKSs: ", ex);
              return Future.succeededFuture(result);
            });
  }
  
  private Future<Void> addKeysToCache(String url, TimedObject<JsonObject> data, Map<String, TimedObject<JWK>> result) {
    try {
      Object keysObject = data.getValue().getValue("keys");
      if (keysObject instanceof JsonArray) {
        JsonArray ja = (JsonArray) keysObject;
        for (Iterator<Object> iter = ja.iterator(); iter.hasNext();) {
          Object keyData = iter.next();
          try {
            if (keyData instanceof JsonObject) {
              JsonObject jo = (JsonObject) keyData;
              String keyId = jo.getString("kid");
              JWK jwk = new JWK(jo);
              synchronized (result) {
                result.put(keyId, new TimedObject<>(jwk, data.getExpiryMs()));
              }
            }
          } catch (Throwable ex) {
            logger.warn("Failed to parse {} from {} as a JWK: ", keyData, url, ex);
          }
        }
      } else {
        logger.error("Failed to get JWKS from {} (returned value does not contain a keys array: {}))", url, data.getValue());
        return Future.failedFuture(new IllegalArgumentException("Failed to parse JWKS from " + url));
      }
    } catch (Throwable ex) {
      logger.error("Failed to get process JWKS from {} ({}): ", url, data.getValue(), ex);
      return Future.failedFuture(new IllegalArgumentException("Failed to process JWKS from " + url));
    }
    return Future.succeededFuture();
  }
  
}
