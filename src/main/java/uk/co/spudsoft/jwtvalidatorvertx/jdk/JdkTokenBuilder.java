/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.jwtvalidatorvertx.jdk;

import com.google.common.cache.Cache;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.AlgorithmAndKeyPair;
import uk.co.spudsoft.jwtvalidatorvertx.JsonWebAlgorithm;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AbstractTokenBuilder;

/**
 * Implementation of TokenBuilder that uses the JDK {@link java.security.KeyPairGenerator} to generate key pairs.
 * @author jtalbut
 */
public class JdkTokenBuilder extends AbstractTokenBuilder {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkTokenBuilder.class);

  /**
   * Constructor.
   * @param keyCache The key cache to be filled with keys created by the token builder.
   */
  public JdkTokenBuilder(Cache<String, AlgorithmAndKeyPair> keyCache) {
    super(keyCache);
  }

  private KeyPair generateKey(String kid, JsonWebAlgorithm algorithm) throws Exception {

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
    
    if ("EdDSA".equals(algorithm.getFamilyName())) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.getJdkAlgName());
      return keyGen.genKeyPair();
    }

    if (algorithm == JsonWebAlgorithm.none) {
      return null;
    }

    throw new IllegalArgumentException("Test harness does not support keys for " + algorithm.toString());
  }

  @Override
  protected byte[] generateSignature(String kid, JsonWebAlgorithm algorithm, String headerBase64, String claimsBase64) throws Exception {
    AlgorithmAndKeyPair akp;
    synchronized (keyCache) {
      akp = keyCache.get(kid, () -> {
        KeyPair kp = generateKey(kid, algorithm);
        return new AlgorithmAndKeyPair(algorithm, kp);
      });
    }
    return generateSignature(akp.getKeyPair().getPrivate(), algorithm, headerBase64 + "." + claimsBase64);
  }

  /**
   * Generate a signature using the JDK security classes.
   * @param privateKey The private key to sign the input with.
   * @param algorithm The algorithm to use for the signing.
   * @param signingInput The content to be signed.
   * @return A byte array containing the signature.
   * @throws Exception If thrown by the JDK security subsystem.
   */
  public static byte[] generateSignature(PrivateKey privateKey, JsonWebAlgorithm algorithm, String signingInput) throws Exception {
    Signature signer = Signature.getInstance(algorithm.getJdkAlgName());
    signer.initSign(privateKey);
    signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
    return signer.sign();
  }

}
