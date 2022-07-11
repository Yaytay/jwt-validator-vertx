/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx.jdk;

import uk.co.spudsoft.jwtvalidatorvertx.JwksHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.primitives.Bytes;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author njt
 */
public class JdkJwksHandler implements HttpHandler, Closeable, JwksHandler<JdkTokenBuilder> {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkJwksHandler.class);

  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private final String context = "/bob";
  private final String configUrl = context + "/.well-known/openid-configuration";
  private final String jwksUrl = context + "/jwks";
  private final String introspectUrl = context + "/protocol/openid-connect/token/introspect";

  private JdkTokenBuilder tokenBuilder;
  private final int port;

  private final HttpServer server;
  private final Executor executor;

  @Override
  public void setTokenBuilder(JdkTokenBuilder tokenBuilder) {
    this.tokenBuilder = tokenBuilder;
  }

  @Override
  public String getBaseUrl() {
    return "http://localhost:" + port + context;
  }

  public JdkJwksHandler() throws IOException {
    try (ServerSocket s = new ServerSocket(0)) {
      this.port = s.getLocalPort();
    }
    executor = Executors.newFixedThreadPool(2);
    server = HttpServer.create(new InetSocketAddress(this.port), 2);
    server.setExecutor(executor);
  }

  public void start() {
    server.createContext(context, this);
    server.start();
  }

  @Override
  public void close() throws IOException {
    server.stop(1);
  }

  protected void sendResponse(HttpExchange exchange, int responseCode, String body) throws IOException {
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(responseCode, bodyBytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bodyBytes);
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    logger.debug("handle {} {}", exchange.getRequestMethod(), exchange.getRequestURI());

    if (null == exchange.getRequestURI().getPath()) {
      sendResponse(exchange, 404, "Not found");
    } else switch (exchange.getRequestURI().getPath()) {
      case configUrl:
        handleConfigRequest(exchange);
        break;
      case jwksUrl:
        handleJwksRequest(exchange);
        break;
      case introspectUrl:
        handleIntrospectRequest(exchange);
        break;
      default:
        sendResponse(exchange, 404, "Not found");
    }
  }

  protected void handleConfigRequest(HttpExchange exchange) throws IOException {
    ObjectNode config = MAPPER.createObjectNode();
    config.put("jwks_uri", "http://localhost:" + port + jwksUrl);
    sendResponse(exchange, 200, config.toString());
  }

  protected void handleJwksRequest(HttpExchange exchange) throws IOException {

    Map<String, KeyPair> keyMap = tokenBuilder.getKeys();

    JsonObject jwkSet = new JsonObject();
    JsonArray jwks = new JsonArray();
    jwkSet.put("keys", jwks);
    for (Entry<String, KeyPair> keyEntry : keyMap.entrySet()) {
      try {
        JsonObject jwkObject = publicKeyToJson(keyEntry.getKey(), keyEntry.getValue().getPublic());
        jwkObject.put("kid", keyEntry.getKey());
        jwks.add(jwkObject);
      } catch(Throwable ex) {
        logger.error("Failed to add key {} to JWK Set: ", keyEntry.getKey(), ex);
      }
    }
    exchange.getResponseHeaders().add("cache-control", "max-age=100");
    sendResponse(exchange, 200, jwkSet.encode());
  }
  
  public static JsonObject publicKeyToJson(String kid, PublicKey key) throws InvalidParameterSpecException, NoSuchAlgorithmException {
    if (key instanceof RSAPublicKey) {
      return RSAPublicKeyToJson(kid, (RSAPublicKey) key);
    } else if (key instanceof ECPublicKey) {
      return ECPublicKeyToJson(kid, (ECPublicKey) key);
    } else if (key instanceof EdECPublicKey) {
      return EdECPublicKeyToJson(kid, (EdECPublicKey) key);
    } else {
      throw new IllegalArgumentException("Cannot process key of type " + key.getClass().getSimpleName());
    }
  }
  
  public static JsonObject RSAPublicKeyToJson(String kid, RSAPublicKey key) {
    JsonObject result = new JsonObject();
    result.put("kid", kid);
    result.put("kty", "RSA");
    // This is just to test the alg handling in JWK constructor, we don't know (or care) whether it's RSA256, 384 or 512.
    result.put("alg", "RS256");
    result.put("e", BASE64.encodeToString(key.getPublicExponent().toByteArray()));
    result.put("n", BASE64.encodeToString(key.getModulus().toByteArray()));
    return result;
  }
  
  private static String oidToCurve(String oid) {
    switch(oid) {
      case "1.2.840.10045.3.1.7":
        return "secp256r1";
      case "1.3.132.0.34":
        return "secp384r1";
      case "1.3.132.0.35":
        return "secp521r1";
      default:
        logger.warn("Unrecognised OID passed in: {}", oid);
        throw new IllegalArgumentException("Unknown OID");
    }
  }
  
  public static JsonObject ECPublicKeyToJson(String kid, ECPublicKey key) throws InvalidParameterSpecException, NoSuchAlgorithmException {
    
    JsonObject result = new JsonObject();
    result.put("kid", kid);
    result.put("kty", "EC");
    
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(key.getParams());
    String oid = params.getParameterSpec(ECGenParameterSpec.class).getName();
    String curve = oidToCurve(oid);
    result.put("crv", curve);
    
    int fieldSize = key.getParams().getCurve().getField().getFieldSize();
    // This is just to test the alg handling in JWK constructor, we don't know (or care) whether it's RSA256, 384 or 512.
    result.put("x", BASE64.encodeToString(coordinateToByteArray(fieldSize, key.getW().getAffineX())));
    result.put("y", BASE64.encodeToString(coordinateToByteArray(fieldSize, key.getW().getAffineY())));

    return result;
  }
  
  private static byte[] modulusToByteArray(BigInteger modulus) {
    // https://tools.ietf.org/html/rfc7518#section-6.3.1 specifies the that initial bytes must not be zero
    byte[] modulusByteArray = modulus.toByteArray();
    if ((modulus.bitLength() % 8 == 0) && (modulusByteArray[0] == 0) && modulusByteArray.length > 1) {
      return Arrays.copyOfRange(modulusByteArray, 1, modulusByteArray.length - 1);
    } else {
      return modulusByteArray;
    }
  }

  private static byte[] coordinateToByteArray(int fieldSize, BigInteger coordinate) {
    byte[] coordinateByteArray = modulusToByteArray(coordinate);
    int fullSize = (int) Math.ceil(fieldSize / 8d);

    if (fullSize > coordinateByteArray.length) {
      final byte[] fullSizeCoordinateByteArray = new byte[fullSize];
      System.arraycopy(coordinateByteArray, 0, fullSizeCoordinateByteArray, fullSize - coordinateByteArray.length, coordinateByteArray.length);
      return fullSizeCoordinateByteArray;
    } else {
      return coordinateByteArray;
    }
  }

  public static JsonObject EdECPublicKeyToJson(String kid, EdECPublicKey key) {
    
    JsonObject result = new JsonObject();
    result.put("kid", kid);
    result.put("kty", "OKP");
    result.put("crv", key.getParams().getName());
    
    BigInteger y = key.getPoint().getY();
    byte[] arr = y.toByteArray();
    Bytes.reverse(arr, 0, arr.length);
    if (key.getPoint().isXOdd()) {
      logger.debug("X is odd");
      arr[arr.length - 1] |= 0x8;
    }
    result.put("x", BASE64.encodeToString(arr));
    return result;
    
  }

  protected void handleIntrospectRequest(HttpExchange exchange) throws IOException {
    ObjectNode config = MAPPER.createObjectNode();
    config.put("bobby", "bobby value");
    sendResponse(exchange, 200, config.toString());
  }
}
