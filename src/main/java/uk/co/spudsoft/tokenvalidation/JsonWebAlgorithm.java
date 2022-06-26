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
package uk.co.spudsoft.tokenvalidation;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Algorithm for use with JWTs as specified by RFC7518.
 * 
 * https://datatracker.ietf.org/doc/html/rfc7518.
 * 
 * Where algorithms are defined in RFC7518 the description for the algorithm is that found there.
 * 
 * @author jtalbut
 */
public enum JsonWebAlgorithm {

  /**
  * HMAC using SHA-256.
  */
  HS256("HS256", "HMAC using SHA-256", "HMAC", "HmacSHA256", 256, 256, "1.2.840.113549.2.9", null),
  /**
   * HMAC using SHA-384.
   */
  HS384("HS384", "HMAC using SHA-384", "HMAC", "HmacSHA384", 384, 384, "1.2.840.113549.2.10", null),
  /**
   * HMAC using SHA-512.
   */
  HS512("HS512", "HMAC using SHA-512", "HMAC", "HmacSHA512", 512, 512, "1.2.840.113549.2.11", null),
  
  /**
   * RSASSA-PKCS-v1_5 using SHA-256.
   */
  RS256("RS256", "RSASSA-PKCS-v1_5 using SHA-256", "RSA", "SHA256withRSA", 256, 2048, null, null),
  /**
   * RSASSA-PKCS-v1_5 using SHA-384.
   */
  RS384("RS384", "RSASSA-PKCS-v1_5 using SHA-384", "RSA", "SHA384withRSA", 384, 2048, null, null),
  /**
   * RSASSA-PKCS-v1_5 using SHA-512.
   */
  RS512("RS512", "RSASSA-PKCS-v1_5 using SHA-512", "RSA", "SHA512withRSA", 512, 2048, null, null),
  
  /**
   * ECDSA using P-256 and SHA-256.
   */
  ES256("ES256", "ECDSA using P-256 and SHA-256", "ECDSA", "SHA256withECDSAinP1363Format", 256, 256, "secp256r1", null),
  /**
   * ECDSA using P-384 and SHA-384.
   */
  ES384("ES384", "ECDSA using P-384 and SHA-384", "ECDSA", "SHA384withECDSAinP1363Format", 384, 384, "secp384r1", null),
  /**
   * ECDSA using P-521 and SHA-512.
   */
  ES512("ES512", "ECDSA using P-521 and SHA-512", "ECDSA", "SHA512withECDSAinP1363Format", 512, 521, "secp521r1", null),
  
  /**
   * RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
   */
  PS256("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "RSA", "RSASSA-PSS", 256, 2048, null, new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
  /**
   * RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
   */
  PS384("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "RSA", "RSASSA-PSS", 384, 2048, null, new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
  /**
   * RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
   */
  PS512("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "RSA", "RSASSA-PSS", 512, 2048, null, new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),
  
  /**
   * No digital signature or MAC performed.
   */
  none("none", "No digital signature or MAC performed", "None", null, 0, 0, null, null),
  
  /**
   * EdDSA using P-521 and SHA-512.
   */
  EdDSA("EdDSA", "EdDSA signature using SHA-512 and Curve25519", "EdDSA", "Ed25519", 512, 521, "Ed25519", null);
  
  private final String name;
  private final String description;
  private final String familyName;
  private final String jdkAlgName;
  private final int digestLength;
  private final int minKeyLength;
  private final String subName;
  private final AlgorithmParameterSpec parameterSpec;

  JsonWebAlgorithm(String name, String description, String familyName, String jdkAlgName, int digestLength, int minKeyLength, String subName, AlgorithmParameterSpec parameterSpec) {
    this.name = name;
    this.description = description;
    this.familyName = familyName;
    this.jdkAlgName = jdkAlgName;
    this.digestLength = digestLength;
    this.minKeyLength = minKeyLength;
    this.subName = subName;
    this.parameterSpec = parameterSpec;
  }

  /**
   * Get the name of the algorithm, in JWT terminology.
   * @return the name of the algorithm, in JWT terminology.
   */
  public String getName() {
    return name;
  }

  /**
   * Get the name of the algorithm, in JDK terminology.
   * @return the name of the algorithm, in JDK terminology.
   */
  public String getJdkAlgName() {
    return jdkAlgName;
  }

  /**
   * Get the name of the family of algorithms that this belongs to.
   * @return the name of the family of algorithms that this belongs to.
   */
  public String getFamilyName() {
    return familyName;
  }

  /**
   * Get the minimum length of keys for this algorithm.
   * @return the minimum length of keys for this algorithm.
   */
  public int getMinKeyLength() {
    return minKeyLength;
  }

  /**
   * Get any sub-name that the algorithm may have.
   * @return any sub-name that the algorithm may have.
   */
  public String getSubName() {
    return subName;
  }

  /**
   * Get the parameter spec needed for configuring a signer.
   * @return the parameter spec needed for configuring a signer, may be null.
   */
  public AlgorithmParameterSpec getParameter() {
    return parameterSpec;
  }
    
}
