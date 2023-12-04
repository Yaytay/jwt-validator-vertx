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
package uk.co.spudsoft.jwtvalidatorvertx;

import java.time.Duration;
import java.util.List;
import uk.co.spudsoft.jwtvalidatorvertx.impl.IssuerAcceptabilityHandlerImpl;

/**
 * Simple interface to encapsulate the handling of issuers.
 * 
 * If a JWT is generated by an issue not approved of by the IssuerAcceptabilityHandler then it should be rejected.
 * Acceptability should be controlled by an operator, it is not something that can be generically solved algorithmically.
 * 
 * For OpenId, which this library is primarily aimed at, the issuer must be a URL that will be used to download keys 
 * that will be used to validate the token.
 * 
 * @author yaytay
 */
public interface IssuerAcceptabilityHandler {
  
  /**
   * Construct an instance of the implementation class.
   * @param acceptableIssuerRegexes The List of regular expressions (as Strings) that are acceptable.
   * @param acceptableIssuersFile   The path to a file that contains valid issuers, one per line.
   * @param pollPeriod              The time period between file checks (the check just looks at the last modified time, so make this about a minute).
   * 
   * It is vital for the security of any system using OpenID Connect Discovery that it is only used with trusted issuers
   * (otherwise any key that has an RFC compliant discovery endpoint will be accepted).
   * Equally the acceptable issuers must be accessed via https for the environment to offer any security.
   * 
   * @return a newly created instance of the implementation class.
   */
  static IssuerAcceptabilityHandler create(List<String> acceptableIssuerRegexes, String acceptableIssuersFile, Duration pollPeriod) {
    return new IssuerAcceptabilityHandlerImpl(acceptableIssuerRegexes, acceptableIssuersFile, pollPeriod);
  }
  
  
  /**
   * Validate the configuration.
   * 
   * @throws IllegalArgumentException if the configuration is not usable, or is not configured with usable values.
   */
  void validate() throws IllegalArgumentException;
  
  /**
   * Return true if the issuer is acceptable.
   * @param issuer The issuer of a JWT.
   * @return true if the issuer is acceptable.
   */
  boolean isAcceptable(String issuer);
  
}
