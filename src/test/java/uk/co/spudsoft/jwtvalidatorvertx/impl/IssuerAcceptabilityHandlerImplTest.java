/*
 * Copyright (C) 2023 jtalbut
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

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import uk.co.spudsoft.jwtvalidatorvertx.IssuerAcceptabilityHandler;

/**
 *
 * @author jtalbut
 */
public class IssuerAcceptabilityHandlerImplTest {
  
  /**
   * Test of validate method, of class IssuerAcceptabilityHandlerImpl.
   */
  @Test
  public void testValidate() {
    assertThrows(IllegalArgumentException.class, () -> IssuerAcceptabilityHandler.create(null, null, Duration.ZERO).validate());
  }

  /**
   * Test of isAcceptable method, of class IssuerAcceptabilityHandlerImpl.
   */
  @Test
  public void testIsAcceptableFile() throws Exception {
    File file = new File("target/temp/issuers");
    file.getParentFile().mkdirs();
    if (file.exists()) {
      file.delete();
    }
    IssuerAcceptabilityHandler iah = IssuerAcceptabilityHandler.create(null, file.toString(), Duration.ofMillis(100));
    
    assertFalse(iah.isAcceptable("carol"));
    try (FileOutputStream strm = new FileOutputStream(file)) {
      strm.write(" bob\r\n carol\r\n   ted".getBytes(StandardCharsets.UTF_8));
    }
    Thread.sleep(250);
    assertTrue(iah.isAcceptable("bob"));
    assertTrue(iah.isAcceptable("carol"));
    assertTrue(iah.isAcceptable("ted"));
    assertFalse(iah.isAcceptable("ringo"));
    
  }
  
}
