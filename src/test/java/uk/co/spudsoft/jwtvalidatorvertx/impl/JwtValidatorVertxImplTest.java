/*
 * Copyright (C) 2023 njt
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

import com.google.common.collect.ImmutableSet;
import java.security.NoSuchAlgorithmException;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

/**
 *
 * @author njt
 */
public class JwtValidatorVertxImplTest {
  
  @Test
  public void testGetPermittedAlgorithms() {
    JwtValidatorVertxImpl instance = new JwtValidatorVertxImpl(null, null);
    assertThat(instance.getPermittedAlgorithms(), hasSize(11));
  }

  @Test
  public void testSetPermittedAlgorithms() throws Exception {
    JwtValidatorVertxImpl instance = new JwtValidatorVertxImpl(null, null);
    assertThat(instance.getPermittedAlgorithms(), hasSize(11));
    instance.setPermittedAlgorithms(ImmutableSet.<String>builder().add("RS256").build());
    assertThat(instance.getPermittedAlgorithms(), hasSize(1));
    assertThrows(NoSuchAlgorithmException.class, () -> {
      instance.setPermittedAlgorithms(ImmutableSet.<String>builder().add("bob").build());
    });
    assertThat(instance.getPermittedAlgorithms(), hasSize(1));
  }

  @Test
  public void testAddPermittedAlgorithm() throws Exception {
    JwtValidatorVertxImpl instance = new JwtValidatorVertxImpl(null, null);
    assertThat(instance.getPermittedAlgorithms(), hasSize(11));
    instance.setPermittedAlgorithms(ImmutableSet.<String>builder().add("RS256").build());
    assertThat(instance.getPermittedAlgorithms(), hasSize(1));
    instance.addPermittedAlgorithm("RS384");
    assertThat(instance.getPermittedAlgorithms(), hasSize(2));
    assertThrows(NoSuchAlgorithmException.class, () -> {
      instance.addPermittedAlgorithm("bob");
    });
    assertThat(instance.getPermittedAlgorithms(), hasSize(2));
  }

}
