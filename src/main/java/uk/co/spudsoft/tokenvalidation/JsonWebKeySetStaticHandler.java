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

import java.util.Arrays;
import java.util.Collection;
import uk.co.spudsoft.tokenvalidation.impl.JWKSStaticSetHandlerImpl;

/**
 * Manage JWKs manually.
 * 
 * It is not usually necessary to use this interface for anything other than the Factory methods.
 * 
 * @author jtalbut
 */
public interface JsonWebKeySetStaticHandler extends JsonWebKeySetHandler {
  
  /**
   * Construct an instance of the implementation class that will accept any issuer.
   * 
   * With a static map of JWKs the security of the system is not compromised by allowing any issuer, though you should question why this is necessary.
   * 
   * @return a newly created instance of the implementation class.
   */
  static JsonWebKeySetStaticHandler create() {
    return create(Arrays.asList(".*"));
  }
  
  /**
   * Construct an instance of the implementation class.
   * 
   * With a static map of JWKs the security of the system is not compromised by allowing any issuer, though you should question why this is necessary.
   * 
   * @param acceptableIssuerRegexes Collection of regular expressions that any issues will be checked against.
   * @return a newly created instance of the implementation class.
   */
  static JsonWebKeySetStaticHandler create(Collection<String> acceptableIssuerRegexes) {
    return new JWKSStaticSetHandlerImpl(acceptableIssuerRegexes);
  }
  
  /**
   * Add a JWK to the known set.
   * 
   * @param issuer The issuer of the key being added.
   * @param key The key being added.
   * @return this for fluent configuration.
   */
  JsonWebKeySetStaticHandler addKey(String issuer, JWK key);
  
  /**
   * Remove a JWK from the known set.
   * 
   * @param issuer The issuer of the key being removed.
   * @param kid The ID of the key being removed.
   * @return this for fluent configuration.
   */
  JsonWebKeySetStaticHandler removeKey(String issuer, String kid);
  
}
