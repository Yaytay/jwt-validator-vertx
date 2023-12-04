/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx.jdk;

import uk.co.spudsoft.jwtvalidatorvertx.JwksHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.cache.Cache;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.JwkBuilder;

/**
 * An implementation of JwksHandler as a JDK HttpHandler.
 * <p>
 * This provides the simplest (and easiest to deploy) implementation of JwksHandler, but it is not very compatible with a Vertx application.
 * 
 * @author jtalbut
 */
public class JdkJwksHandler implements HttpHandler, Closeable, JwksHandler {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkJwksHandler.class);

  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private final String context = "/bob";
  private final String configUrl = context + "/.well-known/openid-configuration";
  private final String jwksUrl = context + "/jwks";

  private final int port;

  private final HttpServer server;
  private final Executor executor;
  
  private Cache<String, AlgorithmAndKeyPair> keyCache;

  @Override
  public void setKeyCache(Cache<String, AlgorithmAndKeyPair> keyCache) {
    this.keyCache = keyCache;
  }

  @Override
  public String getBaseUrl() {
    return "http://localhost:" + port + context;
  }
  
  /**
   * Factory method to create a new JdkJwsHandler on a random port.
   * The {@link #start() } method must still be called on the returned object.
   * @return A newly created (but not yet active) JdkJwsHandler.
   * @throws IOException If the server cannot be created or started.
   */
  public static JdkJwksHandler create() throws IOException {
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    ExecutorService exeSvc = Executors.newFixedThreadPool(2);
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 2);
    server.setExecutor(exeSvc);
    return new JdkJwksHandler(port, server, exeSvc);
  }
  
  private JdkJwksHandler(int port, HttpServer server, Executor executor) {
    this.port = port;
    this.server = server;
    this.executor = executor;
  }
  
  @Override
  public void start() {
    server.createContext(context, this);
    server.start();
  }

  @Override
  public void close() throws IOException {
    server.stop(1);
  }

  private void sendResponse(HttpExchange exchange, int responseCode, String body) throws IOException {
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(responseCode, bodyBytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bodyBytes);
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    logger.debug("handle {} {}", exchange.getRequestMethod(), exchange.getRequestURI());

    switch (exchange.getRequestURI().getPath()) {
      case configUrl:
        handleConfigRequest(exchange);
        break;
      case jwksUrl:
        handleJwksRequest(exchange);
        break;
      default:
        sendResponse(exchange, 404, "Not found");
    }
  }

  private void handleConfigRequest(HttpExchange exchange) throws IOException {
    ObjectNode config = MAPPER.createObjectNode();
    config.put("jwks_uri", "http://localhost:" + port + jwksUrl);
    sendResponse(exchange, 200, config.toString());
  }

  private void handleJwksRequest(HttpExchange exchange) throws IOException {

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
    exchange.getResponseHeaders().add("cache-control", "max-age=100");
    sendResponse(exchange, 200, jwkSet.encode());
  }
  
}
