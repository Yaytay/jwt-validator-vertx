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

import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;


/**
 *
 * @author njt
 */
public class EdECJwkBuilderTest {
  
  @Test
  public void testToJson() throws Exception {
    EdECJwkBuilder builder = new EdECJwkBuilder();
    assertThrows(NoSuchAlgorithmException.class, () -> {
      builder.toJson("kid", "bob", null);
    });
  }
  
}
