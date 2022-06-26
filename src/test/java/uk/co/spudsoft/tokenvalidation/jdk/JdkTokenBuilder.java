/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.tokenvalidation.jdk;

import com.google.common.collect.ImmutableMap;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.tokenvalidation.AbstractTokenBuilder;
import uk.co.spudsoft.tokenvalidation.JsonWebAlgorithm;

/**
 *
 * @author njt
 */
public class JdkTokenBuilder extends AbstractTokenBuilder {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkTokenBuilder.class);

  protected final Map<String, KeyPair> keys = new HashMap<>();

  public Map<String, KeyPair> getKeys() {
    return ImmutableMap.copyOf(keys);
  }
  
  protected KeyPair generateKey(String kid, JsonWebAlgorithm algorithm) throws Exception {

    if ("RSA".equals(algorithm.getFamilyName())) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(algorithm.getMinKeyLength());
      return keyGen.genKeyPair();
    }

    if ("ECDSA".equals(algorithm.getFamilyName())) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      ECGenParameterSpec spec = new ECGenParameterSpec(algorithm.getSubName());
      keyGen.initialize(spec);
      return keyGen.genKeyPair();
    }

    if (algorithm == JsonWebAlgorithm.none) {
      return null;
    }

    throw new IllegalArgumentException("Test harness does not support keys for " + algorithm.toString());
  }

  @Override
  protected byte[] generateSignature(String kid, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception {
    KeyPair keyPair;
    synchronized (keys) {
      keyPair = keys.get(kid);
      if (keyPair == null) {
        keyPair = generateKey(kid, algorithm);
        keys.put(kid, keyPair);
      }
    }
    return generateSignature(keyPair.getPrivate(), algorithm, headerBase64, claimsBase64);
  }

  private byte[] generateSignature(PrivateKey privateKey, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception {
    Signature signer = Signature.getInstance(algorithm.getJdkAlgName());
    String signingInput = headerBase64 + "." + claimsBase64;
    signer.initSign(privateKey);
    signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
    return signer.sign();
  }

}
