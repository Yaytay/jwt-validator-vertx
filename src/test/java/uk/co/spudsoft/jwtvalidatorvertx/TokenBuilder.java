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

import java.util.List;
import java.util.Map;

/**
 *
 * @author jtalbut
 */
public interface TokenBuilder {

  String buildToken(JsonWebAlgorithm jwa, String kid, String iss, String sub, List<String> aud, Long nbf, Long exp, Map<String, Object> otherClaims) throws Exception;
  
  TokenBuilder setBreakHeader(boolean breakHeader);
  TokenBuilder setBreakPayload(boolean breakPayload);
  TokenBuilder setBreakSignature(boolean breakSignature);
  TokenBuilder setHeaderNotJson(boolean headerNotJson);
  TokenBuilder setPayloadNotJson(boolean payloadNotJson);
  TokenBuilder setInvalidSignature(boolean invalidSignature);
  TokenBuilder setInvalidKid(boolean invalidKid);
  
  
}
