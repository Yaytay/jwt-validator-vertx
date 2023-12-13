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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import uk.co.spudsoft.jwtvalidatorvertx.impl.AsyncLoadingCache.TimedObject;

/**
 *
 * @author njt
 */
public class AsyncLoadingCacheTest {
  
  @Test
  public void testEntry() {
    AsyncLoadingCache<String, Integer> cache = new AsyncLoadingCache<>();
    TimedObject<Integer> entry = cache.entry(Integer.MIN_VALUE, 10);
    assertEquals(Integer.MIN_VALUE, entry.getValue());
    assertEquals(10, entry.getExpiryMs());
    assertTrue(entry.expiredBefore(11));
    assertFalse(entry.expiredBefore(10));
    assertFalse(entry.expiredBefore(9));
  }
}
