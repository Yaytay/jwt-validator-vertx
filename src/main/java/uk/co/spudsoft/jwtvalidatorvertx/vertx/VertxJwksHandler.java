/*
 * Copyright (C) 2025 njt
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
package uk.co.spudsoft.jwtvalidatorvertx.vertx;

import com.google.common.cache.Cache;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.PublicKey;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.JwksHandler;
import uk.co.spudsoft.jwtvalidatorvertx.TokenBuilder;
import uk.co.spudsoft.jwtvalidatorvertx.jdk.JdkJwksHandler;
import uk.co.spudsoft.jwtvalidatorvertx.jdk.JdkTokenBuilder;

/**
 * An implementation of JwksHandler as a Vertx {@link Handler}&lt;{@link RoutingContext}&gt;.
 *
 * @author njt
 */
public class VertxJwksHandler implements Handler<RoutingContext>, JwksHandler {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkJwksHandler.class);

  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  
  private final Vertx vertx;
  private final HttpServer httpServer;
  
  private final String host;
  private final int port;
  private final String basePath; 
  private final String issuer;
  private final String configUrl;
  private final String jwksUrl;
  private final String tokenUrl;
  private final boolean withTokenBuilder;
  
  private Cache<String, AlgorithmAndKeyPair> keyCache;
  private TokenBuilder tokenBuilder = null;
  
  @Override
  public void setKeyCache(Cache<String, AlgorithmAndKeyPair> keyCache) {
    this.keyCache = keyCache;
    if (withTokenBuilder) {
      tokenBuilder = new JdkTokenBuilder(keyCache);
    }
  }

  @Override
  public String getBaseUrl() {
    return "http://localhost:" + port + basePath;
  }

  /**
   * Get the port that the handler is listening on.
   * @return the port that the handler is listening on.
   */
  public int getPort() {
    return port;
  }
  
  /**
   * Factory method to create a new VertxJwksHandler.
   * 
   * Note that this differs from the constructor in that it creates a dedicated Vertx instance and {@link HttpServer}.
   * If this factory method is used then {@link #start()} must be called, if the constructor is called directly then
   * the caller may choose to control the lifetime of the HttpServer manually.
   * 
   * The URL generated from the host, post and basePath is the issuer that will be used in tokens.
   * 
   * @param host The hostname to use - typically this will just be localhost.
   * @param port The port to use - may be 0 to choose a random available port.
   * @param basePath The path to use - should being with a slash but not end with one.
   * @param withTokenBuilder If true provide an endpoint for creating test tokens.
   * @return A newly created (but not yet active) VertxJwksHandler.
   * @throws IOException if port &lt;= 0 and unable to find an available port.
   */
  public static VertxJwksHandler create(String host, int port, String basePath, boolean withTokenBuilder) throws IOException {

    if (port <= 0) {
      try (ServerSocket s = new ServerSocket(0)) {
        port = s.getLocalPort();
      }
    }
    
    Vertx vertx = Vertx.vertx();
    HttpServer httpServer = vertx.createHttpServer();
    Router router = Router.router(vertx);
    VertxJwksHandler handler = new VertxJwksHandler(vertx, httpServer, host, port, basePath, withTokenBuilder);
    router.route(basePath + "/*").handler(handler);
    httpServer.requestHandler(router);
    return handler;
  }
  
  static String checkPath(String path) {
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    if (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }    
    return path;
  }

  /**
   * Constructor.
   * 
   * The URL generated from the host, post and basePath is the issuer that will be used in tokens.
   * 
   * @param vertx The Vertx instance to be owned by the handler.
   *        Pass in null if the lifetime of the Vertx instance is not managed by this handler.
   * @param httpServer The Vertx server  to be owned by the handler.
   *        Pass in null if the lifetime of the Vertx server is not managed by this handler.
   * @param host The hostname to use in URLs generated and provided to clients.
   * @param port The port to use in URLs generated and provided to clients.
   *        Also the port to listen on if the httpServer is managed by this handler.
   *        This must not be zero.
   * @param basePath The path to use in URLs generated and provided to clients.
   * @param withTokenBuilder If true provide an endpoint for creating test tokens.
   *        
   */
  public VertxJwksHandler(Vertx vertx, HttpServer httpServer, String host, int port, String basePath, boolean withTokenBuilder) {
    this.vertx = vertx;
    this.httpServer = httpServer;
    this.host = host;
    this.port = port;
    this.basePath = checkPath(basePath);
    this.issuer = "http://" + host + ":" + port + basePath;
    this.configUrl = "http://" + host + ":" + port + basePath + "/.well-known/openid-configuration";
    this.jwksUrl = "http://" + host + ":" + port + basePath + "/jwks";
    this.tokenUrl = withTokenBuilder ? "http://" + host + ":" + port + basePath + "/token" : "";
    this.withTokenBuilder = withTokenBuilder;
  }
    
  @Override
  public void start() {
    if (httpServer != null) {
      httpServer.listen(port);
    }
  }

  @Override
  public void close() throws IOException {
    if (httpServer != null) {
      httpServer.close();
      vertx.close();
    }
  }
  

  private void sendResponse(RoutingContext exchange, int responseCode, String contentType, Buffer body) {
    exchange.response()
            .setStatusCode(responseCode)
            .putHeader("Content-Type", contentType)
            .end(body);
  }

  @Override
  public void handle(RoutingContext exchange) {
    HttpServerRequest request = exchange.request();
    String url = request.absoluteURI();
    logger.debug("handle {} {}", request.method(), url);

    if (request.method() == HttpMethod.GET) {
      if (configUrl.equals(url)) {
        handleConfigRequest(exchange);
      } else if (jwksUrl.equals(url)) {
        handleJwksRequest(exchange);
      } else {
        exchange.next();
      }
    } else if (request.method() == HttpMethod.PUT) {
      if (tokenUrl.equals(url)) {
        handleTokenRequest(exchange);
      } else {
        exchange.next();
      }
    } else {
      exchange.next();
    }
  }

  private void handleConfigRequest(RoutingContext exchange) {
    JsonObject config = new JsonObject();
    config.put("jwks_uri", jwksUrl);
    sendResponse(exchange, 200, "application/json", config.toBuffer());
  }

  private void handleJwksRequest(RoutingContext exchange) {

    JsonObject jwkSet = new JsonObject();
    JsonArray jwks = new JsonArray();
    jwkSet.put("keys", jwks);
    synchronized (keyCache) {
      keyCache.asMap().forEach((kid, akp) -> {
        PublicKey key = akp.getKeyPair().getPublic();
        try {
          JsonObject json = JwkBuilder.get(key).toJson(kid, akp.getAlgorithm().getName(), key);
          jwks.add(json);
        } catch (Exception ex) {
          logger.warn("Failed to add key {} to JWKS: ", kid, ex);
        }
      });
    }
    exchange.response().putHeader("cache-control", "max-age=100");
    sendResponse(exchange, 200, "application/json", jwkSet.toBuffer());
  }
  
  private void handleTokenRequest(RoutingContext exchange) {
    HttpServerRequest request = exchange.request();
    request.body()
            .andThen(ar -> {
              if (ar.succeeded()) {
                try {
                  JsonObject body = ar.result().length() > 0 ? ar.result().toJsonObject() : new JsonObject();
                  
                  long nbf = (System.currentTimeMillis() / 1000);
                  long exp = nbf + 60 * 60;                  
                  
                  String token = tokenBuilder.buildToken(JsonWebAlgorithm.RS512, "test", this.issuer, null, null, nbf, exp, body.getMap());
                  sendResponse(exchange, 200, "text/plain", Buffer.buffer(token));
                } catch (Throwable ex) {
                  logger.debug("Failed to get request body as json: ", ar.cause());
                  sendResponse(exchange, 400, "text/plain", Buffer.buffer("Failed to read request body"));
                }
              } else {
                logger.debug("Failed to get request body: ", ar.cause());
                sendResponse(exchange, 500, "text/plain", Buffer.buffer("Failed to get request body"));
              }
            });
  }
}
