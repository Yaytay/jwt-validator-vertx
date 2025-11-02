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
package uk.co.spudsoft.jwtvalidatorvertx;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWS;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.jdk.JdkTokenBuilder;

/**
 *
 * @author jtalbut
 */
public class JWKSelfMadeKeysTest {
  
  private static final Logger logger = LoggerFactory.getLogger(JWKSelfMadeKeysTest.class);
  
  @Test  
  public void testEcJwks256() throws Throwable {    
    String kid = "testEcJwks256";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES256", key);    
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES256, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES256, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEcJwks384() throws Throwable {    
    String kid = "testEcJwks384";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES384", key);    
    // Can't determine hash size from key alone
    jo.put("alg", "ES384");
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES384, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES384, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEcJwks521() throws Throwable {    
    String kid = "testEcJwks521";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp521r1");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES512", key);
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES512, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES512, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEcJwks256Oid() throws Throwable {    
    String kid = "testEcJwks256";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("1.2.840.10045.3.1.7");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES256", key);    
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES256, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES256, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEcJwks384Oid() throws Throwable {    
    String kid = "testEcJwks384";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("1.3.132.0.34");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES384", key);    
    // Can't determine hash size from key alone
    jo.put("alg", "ES384");
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES384, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES384, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEcJwks521Oid() throws Throwable {    
    String kid = "testEcJwks521";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("1.3.132.0.35");
    keyGen.initialize(spec);
    KeyPair pair = keyGen.genKeyPair();
    ECPublicKey key = (ECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "ES512", key);
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.ES512, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.ES512, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testRsaJwks256() throws Throwable {    
    String kid = "testRsaJwks256";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair pair = keyGen.genKeyPair();
    RSAPublicKey key = (RSAPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "RS256", key);    
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.RS256, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.RS256, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testRsaJwks384() throws Throwable {    
    String kid = "testRsaJwks384";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair pair = keyGen.genKeyPair();
    RSAPublicKey key = (RSAPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "RS384", key);
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.RS384, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.RS384, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testRsaJwks512() throws Throwable {    
    String kid = "testRsaJwks512";
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair pair = keyGen.genKeyPair();
    RSAPublicKey key = (RSAPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "RS512", key);
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.RS512, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.RS512, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  @Test  
  public void testEdJwks() throws Throwable {    
    String kid = "testEdJwks";
    
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
    KeyPair pair = keyGen.generateKeyPair();
    EdECPublicKey key = (EdECPublicKey) pair.getPublic();
    
    JsonObject jo = JwkBuilder.get(key).toJson(kid, "EdDSA", key);    
    JWK jwk = new JWK(jo);
    assertEquals(kid, jwk.getId());
    
    // We can't compare the key because the representation may differ, so can we validate something signed.
    String signingInput = "Signing input";
    byte[] signature = JdkTokenBuilder.generateSignature(pair.getPrivate(), JsonWebAlgorithm.EdDSA, signingInput);
    JWS jws = new JWS(jwk);
    assertEquals(JWS.EdDSA, jwk.getAlgorithm());
    jws.verify(signature, signingInput.getBytes(StandardCharsets.UTF_8));
  }
  
  

//  @Test  
//  public void testBadEdJwks() throws Throwable {
//    // Sample good one:
//    JWK jwk = JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}"));
//    // No kty
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
//    // No crv
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
//    // No kid
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}")));
//    // No x
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\"}")));
//  }
//
//  @Test  
//  public void testBadRsaJwks() throws Throwable {
//    // Sample good one:
//    JWK jwk = JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}"));
//    // No kty
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
//    // No e
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
//    // No kid
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"n\":\"AMhg9V1sVBq3nLWtmP0Nxi7dD38dpqCD_PI0KnE1qr55FUld1jSkrRCiyY7VWr6iiEs0pbEVr7PKVWcsuYyCWrRImtlwwwvtJ2nXwkyFvW3mWmbKj7bgwKKqUZXpSRNA76SaoE34bnNh6lm93Dco_1B8jXcMbcn0nP2F4HFtD3wL9vEZRXTgskUA1NLRM6pApJFjtUQFn64AFtKXL3n4OhuojHPRIXP1Nx0T9SRO81ue0Uo2B4qpQlWkogBvVqbg1Fw3tEl6Z7XHyUzNGwhNLEdtQVl_7NjTX4jrRnhOXJnMXbpSDbrIFPu2AIG4mUpOJE6WVXR9BQ2VlX00vndqNcs\"}")));
//    // No n
//    assertThrows(IllegalArgumentException.class, () -> JWK.create(0, new JsonObject("{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"02ccbee4-57ae-4919-b93f-30853469f2fd\",\"alg\":\"RS256\"}")));
//  }
}
