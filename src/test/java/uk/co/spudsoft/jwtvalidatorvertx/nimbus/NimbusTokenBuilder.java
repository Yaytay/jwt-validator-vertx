/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx.nimbus;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AbstractTokenBuilder;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;




/**
 *
 * @author njt
 */
public class NimbusTokenBuilder extends AbstractTokenBuilder {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(NimbusTokenBuilder.class);

  protected final Map<String, JWK> keys = new HashMap<>();

  public Map<String, JWK> getKeys() {
    return ImmutableMap.copyOf(keys);
  }
  
  protected JWK generateKey(String kid, JsonWebAlgorithm algorithm) throws Exception {

    if (algorithm == JsonWebAlgorithm.none) {
      return null;
    } else if ("RSA".equals(algorithm.getFamilyName())) {
      return new RSAKeyGenerator(algorithm.getMinKeyLength())
              .keyUse(KeyUse.SIGNATURE) 
              .keyID(kid)
              .generate();
    } else if ("ECDSA".equals(algorithm.getFamilyName())) {
      return new ECKeyGenerator(Curve.forStdName(algorithm.getSubName()))
              .keyUse(KeyUse.SIGNATURE)
              .keyID(kid)
              .generate();
    } else if ("EdDSA".equals(algorithm.getFamilyName())) {
      return new OctetKeyPairGenerator(Curve.forStdName(algorithm.getSubName()))
              .keyUse(KeyUse.SIGNATURE) 
              .keyID(kid)
              .generate();      
    } else {
      throw new IllegalArgumentException("Test harness does not support keys for " + algorithm.toString());
    }
  }

  @Override
  protected byte[] generateSignature(String kid, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception {
    JWK jwk;
    synchronized (keys) {
      jwk = keys.get(kid);
      if (jwk == null) {
        jwk = generateKey(kid, algorithm);
        keys.put(kid, jwk);
      }
    }
    return generateSignature(jwk, algorithm, headerBase64, claimsBase64);
  }

  private byte[] generateSignature(JWK jwk, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception {

    byte[] signingInput = (headerBase64 + "." + claimsBase64).getBytes(StandardCharsets.UTF_8);

    switch (algorithm.getFamilyName()) {
      case "RSA": {
        RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
        JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm.getName()));
        return signer.sign(header, signingInput).decode();
      }
      case "ECDSA": {
        ECDSASigner signer = new ECDSASigner((ECKey) jwk);
        JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm.getName()));
        return signer.sign(header, signingInput).decode();
      }
      case "EdDSA": {
        Ed25519Signer signer = new Ed25519Signer((OctetKeyPair) jwk);
        JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm.getName()));
        return signer.sign(header, signingInput).decode();
      }
      default:
        throw new IllegalArgumentException("Unknown algorithm");
    }
  }

}
