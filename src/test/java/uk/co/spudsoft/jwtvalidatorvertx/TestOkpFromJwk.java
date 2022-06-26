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

import com.google.common.primitives.Bytes;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import io.vertx.ext.auth.impl.asn.ASN1;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jtalbut
 */
public class TestOkpFromJwk {
  
  private static final Logger logger = LoggerFactory.getLogger(JWK.class);

  private static byte[] getJdkEdCurve(String curve) {
    switch (curve) {
      case "Ed25519":
        return new byte[]{0x6, 0x3, 0x2b, 101, 112};    // 1.3.101.112
      case "Ed448":
        return new byte[]{0x6, 0x3, 0x2b, 101, 113};    // 1.3.101.113
      case "X25519":
        return new byte[]{0x6, 3, 0x2b, 101, 110};      // 1.3.101.110
      case "X448":
        return new byte[]{0x6, 3, 0x2b, 101, 111};      // 1.3.101.111
      default:
        throw new IllegalArgumentException("Unknown curve \"" + curve + "\"");
    }
  }

  private static EdECPoint byteArrayToEdPoint(byte[] arr) {
    byte msb = arr[arr.length - 1];
    boolean xOdd = (msb & 0x80) != 0;
    arr[arr.length - 1] &= (byte) 0x7F;
    Bytes.reverse(arr, 0, arr.length);
    BigInteger y = new BigInteger(1, arr);
    return new EdECPoint(xOdd, y);
  }

  @Test
  public void testParse() throws Exception {
    JsonObject jwk = new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}");

    String xStr = jwk.getString("x");

    EdECPublicKey key1 = (EdECPublicKey) viaAsn(xStr);
    logger.info("Via ASN: {}: {}/{}", key1.getAlgorithm(), key1.getPoint().isXOdd(), key1.getPoint().getY());
    EdECPublicKey key2 = (EdECPublicKey) viaConvert(xStr);
    logger.info("Via Convert: {}: {}/{}", key2.getAlgorithm(), key2.getPoint().isXOdd(), key2.getPoint().getY());
    assertEquals(key1.getPoint().isXOdd(), key2.getPoint().isXOdd());
    assertEquals(key1.getPoint().getY(), key2.getPoint().getY());
  }

  private Key viaAsn(String xStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
    final byte[] key = Base64.getUrlDecoder().decode(xStr);

    byte[] spki = ASN1.sequence(
            Buffer.buffer()
                    .appendBytes(ASN1.sequence(getJdkEdCurve("Ed25519")))
                    .appendByte((byte) 0x3)
                    .appendBytes(ASN1.length(key.length + 1))
                    .appendByte((byte) 0x00)
                    .appendBytes(key)
                    .getBytes());
    return KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(spki));
  }

  private Key viaConvert(String xStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
    KeyFactory kf = KeyFactory.getInstance("EdDSA");
    NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
    byte xBytes[] = Base64.getUrlDecoder().decode(xStr);
    EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, byteArrayToEdPoint(xBytes));
    return kf.generatePublic(pubSpec);
  }
}
