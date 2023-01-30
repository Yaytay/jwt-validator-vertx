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

import io.vertx.core.Future;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.JWK;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebKeySetStaticHandler;

/**
 * Implementation of {@link JsonWebKeySetStaticHandler} that stores JWKs in a HashMap.
 * 
 * @author jtalbut
 */
public class JWKSStaticSetHandlerImpl implements JsonWebKeySetStaticHandler {
  
  private static final Logger logger = LoggerFactory.getLogger(JWKSOpenIdDiscoveryHandlerImpl.class);
  
  private final List<Pattern> acceptableIssuers;
  private final Map<String, JWK<?>> keys = new HashMap<>();

  /**
   * Constructor.
   * @param acceptableIssuerRegexes Collection of regular expressions (as Strings) that any passed in issuer must match.
   * 
   * This JsonWebKeySet handler is entirely static, so the specification of acceptable issuers is not a vital security feature.
   * 
   */
  public JWKSStaticSetHandlerImpl(Collection<String> acceptableIssuerRegexes) {
    if (acceptableIssuerRegexes == null || acceptableIssuerRegexes.isEmpty()) {
      throw new IllegalArgumentException("Acceptable issuer regular expressions must be passed in");
    }
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
  }

  @Override
  public JsonWebKeySetStaticHandler addKey(String issuer, JWK<?> key) {
    keys.put(issuer + '^' + key.getKid(), key);
    return this;
  }

  @Override
  public JsonWebKeySetStaticHandler removeKey(String issuer, String kid) {
    keys.remove(issuer + '^' + kid);
    return this;
  }

  @Override
  public void validateIssuer(String issuer) throws IllegalArgumentException {
    for (Pattern acceptableIssuer : acceptableIssuers) {
      if (acceptableIssuer.matcher(issuer).matches()) {
        return;
      }
    }
    logger.warn("Failed to find issuer \"{}\" in {}", issuer, acceptableIssuers);
    throw new IllegalArgumentException("Parse of signed JWT failed");
  }

  @Override
  public Future<JWK<?>> findJwk(String issuer, String kid) {
    JWK<?> jwk = keys.get(issuer + '^' + kid);
    if (null == jwk) {
      logger.error("Failed to find key {} from store from {}", kid, keys.keySet());
      return Future.failedFuture(
              new IllegalArgumentException("Parse of signed JWT failed",
                       new IllegalArgumentException("Failed to find key " + kid)
              )
      );
    } else {
      return Future.succeededFuture(jwk);
    }
  }

  
  
  
}
