/*
 * Copyright (C) 2025 jtalbut
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
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetAwsElbHandler;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AsyncLoadingCache.TimedObject;

/**
 * Implementation of {@link JsonWebKeySetAwsElbHandler} that stores JWKs in a HashMap.
 *
 * @author jtalbut
 */
public class JWKSAwsElbHandlerImpl implements JsonWebKeySetAwsElbHandler {

  private static final Logger logger = LoggerFactory.getLogger(JWKSOpenIdDiscoveryHandlerImpl.class);

  private final List<String> keyBaseUrls;
  private final WebClient webClient;
  private final long cacheDurationMillis;
  private final Map<String, TimedObject<JWK>> keys = new HashMap<>();

  /**
   * Constructor.
   *
   * With a static map of JWKs the security of the system is not compromised by allowing any issuer, though you should question
   * why this is necessary.
   *
   * Each JWKs endpoint must use KIDs that are globally unique.
   *
   * When a KID is requested and cannot be found ALL the configured JWKS URLs will be queried and the single cache will be
   * updated. Entries in the cache will be retained for a duration based on either the Cache-Control max-age header of the
   * response or, if that is not present, the defaultJwkCacheDuration. Given that only positive responses are cached it is
   * reasonable for the defaultJwkCacheDuration to be 24 hours (or more).
   *
   * @param webClient Vertx WebClient instance, that will be used for querying the JWKS URLs.
   * @param keyBaseUrls Static set of base URLs that will be used for constructing the URLs to the AWS keys.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   *
   * The JWKS URLs must be accessed via https for the environment to offer any security. This is not enforced at the code level.
   *
   * @see <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding">listener-authenticate-users.html#user-claims-encoding</a>
   */
  public JWKSAwsElbHandlerImpl(WebClient webClient, Collection<String> keyBaseUrls, Duration defaultJwkCacheDuration) {
    this.webClient = webClient;
    this.cacheDurationMillis = defaultJwkCacheDuration.toMillis();
    this.keyBaseUrls = keyBaseUrls.stream().map(url -> url.endsWith("/") ? url : url + "/").collect(ImmutableList.toImmutableList());
  }

  @Override
  public void optimize() {
  }

  private JWK findJwk(String kid) {
    synchronized (keys) {
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
  }

  @Override
  public Future<JWK> findJwk(String issuer, String kid) {

    if (!kid.matches("^[A-Za-z0-9._~-]*$")) {
      logger.error("The kid \"{}\" is not a valid AWS ELB kid", kid);
      throw new IllegalArgumentException("The kid is not a valid AWS ELB kid.");
    }

    JWK foundJwk = findJwk(kid);
    if (foundJwk != null) {
      return Future.succeededFuture(foundJwk);
    }

    Promise<JWK> resultPromise = Promise.promise();
    List<Future<Void>> trackingFutures = new ArrayList<>();

    for (String baseUrl : this.keyBaseUrls) {
      String awsKeyUrl = baseUrl + kid;

      Future<Void> future = webClient.getAbs(awsKeyUrl)
              .send()
              .compose(response -> {
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                  JWK jwk;
                  Buffer body = response.body();
                  try {
                    jwk = pemToJwk(kid, body);
                  } catch (Throwable ex) {
                    logger.warn("From {} failed to parse body ({}) as JWKRequest: ", awsKeyUrl, body, response.body());
                    return Future.<Void>succeededFuture();
                  }
                  synchronized (keys) {
                    keys.put(kid, new TimedObject<>(jwk, System.currentTimeMillis() + cacheDurationMillis));
                  }

                  resultPromise.tryComplete(jwk);
                } else {
                  logger.warn("Request to {} returned {}: {}", awsKeyUrl, response.statusCode(), response.body());
                }
                return Future.<Void>succeededFuture();
              })
              .recover(ex -> {
                logger.warn("Failed request to {}: ", awsKeyUrl, ex);
                return Future.<Void>succeededFuture();
              });

      trackingFutures.add(future);
    }

    // After all requests finish, fail the promise if none succeeded
    Future.all(trackingFutures).onComplete(ar -> {
      if (!resultPromise.future().isComplete()) {
        resultPromise.fail("No valid response found");
      }
    });

    return resultPromise.future();
  }

  private static JWK pemToJwk(String kid, Buffer pem) {
    PubSecKeyOptions keyOptions = new PubSecKeyOptions()
      .setAlgorithm("ES256")
      .setBuffer(pem)
      .setId(kid);
    return new JWK(keyOptions);
  }

}
