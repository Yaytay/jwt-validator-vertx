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

import com.google.common.base.Strings;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.DiscoveryData;
import uk.co.spudsoft.jwtvalidatorvertx.IssuerAcceptabilityHandler;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetOpenIdDiscoveryHandler;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AsyncLoadingCache.TimedObject;

/**
 * Default implementation of {@link uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetHandler}.
 * @author jtalbut
 */
public class JWKSOpenIdDiscoveryHandlerImpl implements JsonWebKeySetOpenIdDiscoveryHandler {

  private static final Logger logger = LoggerFactory.getLogger(JWKSOpenIdDiscoveryHandlerImpl.class);
  
  /**
   * Map from Issuer to DiscoveryData.
   */
  private final AsyncLoadingCache<String, DiscoveryData> discoveryDataCache;
  
  /**
   * Map from jwks_uri to Map from kid to JWK.
   */
  private final Map<String, AsyncLoadingCache<String, JWK>> kidCache;

  private final IssuerAcceptabilityHandler issuerAcceptabilityHandler;
  
  private final OpenIdHelper openIdHelper;
  
  /**
   * Constructor.
   * @param webClient Vertx WebClient, for the discovery handler to make asynchronous web requests.
   * @param issuerAcceptabilityHandler Object used to determine the acceptability of JWT issuers.
   * @param defaultJwkCacheDuration Time (in seconds) to keep JWKs in cache if no cache-control: max-age header is found.
   * 
   * It is vital for the security of any system using OpenID Connect Discovery that it is only used with trusted issuers.
   */
  public JWKSOpenIdDiscoveryHandlerImpl(WebClient webClient, IssuerAcceptabilityHandler issuerAcceptabilityHandler, Duration defaultJwkCacheDuration) {
    this.issuerAcceptabilityHandler = issuerAcceptabilityHandler;
    issuerAcceptabilityHandler.validate();    
    this.discoveryDataCache = new AsyncLoadingCache<>();  
    this.kidCache = new HashMap<>();
    this.openIdHelper = new OpenIdHelper(webClient, defaultJwkCacheDuration.toSeconds());
  }

  @Override
  public void optimize() {
    // No preload of keys is possible.
  }

  private void validateIssuer(String issuer) throws IllegalArgumentException {
    if (discoveryDataCache.containsKey(issuer)) {
      return ;
    }
    if (issuerAcceptabilityHandler.isAcceptable(issuer)) {
      return;
    }
    logger.warn("Issuer ({}) not considered acceptable by {}", issuer, issuerAcceptabilityHandler);
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
            , () -> openIdHelper.get(discoveryUrl)
                    .map(tjo -> discoveryDataCache.entry(new DiscoveryData(tjo.getValue()), tjo.getExpiryMs()))
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
        jwkCache = new AsyncLoadingCache<>();
        kidCache.put(jwksUri, jwkCache);
      }
      finalJwkCache = jwkCache;
    }
    
    return finalJwkCache.get(kid
            , () -> openIdHelper.get(discoveryData.getJwksUri())
                    .compose(tjo -> processJwkSet(finalJwkCache, tjo, kid))
    );
  }

  @Override
  public Future<JWK> findJwk(String issuer, String kid) {
    return performOpenIdDiscovery(issuer)
            .compose(dd -> findJwk(dd, kid));
  }
  
  static Future<TimedObject<JWK>> processJwkSet(AsyncLoadingCache<String, JWK> jwkCache, TimedObject<JsonObject> data, String kid) {
    long expiry = data.getExpiryMs();
    JWK result = null;
    JsonObject foundKey = null;
    
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
              if (kid.equals(keyId)) {
                result = new JWK(jo);
                foundKey = jo;
              } else {
                JWK other = new JWK(jo);
                jwkCache.put(keyId, jwkCache.entry(other, expiry));
              }
            }
          } catch (Throwable ex) {
            logger.warn("Failed to parse {} as a JWK: ", keyData, ex);
          }
        }
      } else {
        logger.error("Failed to get key {} from JWKS from {}", kid, data.getValue());
        return Future.failedFuture(
                new IllegalArgumentException("Parse of signed JWT failed",
                         new IllegalArgumentException("Failed to get public key for " + kid)
                )
        );
      }
    } catch (Throwable ex) {
      logger.error("Failed to get public key for {} from {}", kid, data.getValue());
      return Future.failedFuture(
              new IllegalArgumentException("Parse of signed JWT failed",
                       new IllegalArgumentException("Failed to get public key for " + kid)
              )
      );
    }
    if (result == null) {
      logger.error("Failed to find key {} from JWKS from {}", kid, data.getValue());
      return Future.failedFuture(
              new IllegalArgumentException("Parse of signed JWT failed",
                       new IllegalArgumentException("Failed to find key " + kid)
              )
      );
    } else {
      if (logger.isDebugEnabled()) {
        logger.debug("Got new {} public key with id {}: {}", result.getAlgorithm(), kid, foundKey);
      } else {
        logger.info("Got new public key with id {}", kid);
      }
      return Future.succeededFuture(jwkCache.entry(result, expiry));
    }
  }
 }
