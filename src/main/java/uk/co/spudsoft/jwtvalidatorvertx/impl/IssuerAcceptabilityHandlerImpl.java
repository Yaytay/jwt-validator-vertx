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

import com.google.common.base.Strings;
import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.jwtvalidatorvertx.IssuerAcceptabilityHandler;

/**
 * The standard IssuerAcceptabilityHandler.
 * 
 * Provides two approaches, which can be used in isolation or together:
 * <ol>
 * <li> A list of acceptable issuers can be provided in a file.
 * The file can be changed whilst the system is up, but the path to the file is fixed.
 * It is recommended that the file be updated atomically (e.g. by changing a soft link).
 * <li> A list of regular expressions can be provided.
 * Each regular expression will be checked, one at a time.
 * </ol>
 * 
 * The use of a file is generally more secure, but there are some situations in which a small number of regular expressions can be useful.
 * 
 * Each line in the file is trimmed before adding to an internal Set, so leading and trailing whitespace is removed (and the line ending of the file is irrelevant).
 * It is strongly recommended that each line of the file be an https URL.
 * 
 * @author yaytay
 */
public class IssuerAcceptabilityHandlerImpl implements IssuerAcceptabilityHandler {
  
  private static final Logger logger = LoggerFactory.getLogger(IssuerAcceptabilityHandlerImpl.class);
  
  private final List<Pattern> acceptableIssuerRegexes;
  private final File acceptableIssuersFile;
  private final long pollPeriodMs;
  
  private final Object lock = new Object();
  private long lastFileCheck = 0;
  private Set<String> acceptableIssuers = Collections.emptySet();
  private long fileLastModified = 0;

  @Override
  public void validate() throws IllegalArgumentException {
    if (acceptableIssuerRegexes.isEmpty() && acceptableIssuersFile == null) {
      throw new IllegalArgumentException("No acceptable issuers configured - neither regular expressions nor file configured");
    }
  }

  /**
   * Constructor.
   * @param acceptableIssuerRegexes The List of regular expressions (as Strings) that are acceptable.
   * @param acceptableIssuersFile   The path to a file that contains valid issuers, one per line.
   * @param pollPeriod              The time period between file checks (the check just looks at the last modified time, so make this about a minute).
   */
  public IssuerAcceptabilityHandlerImpl(List<String> acceptableIssuerRegexes, String acceptableIssuersFile, Duration pollPeriod) {
    this.acceptableIssuerRegexes = acceptableIssuerRegexes == null ? Collections.emptyList() : acceptableIssuerRegexes.stream()
                    .map(re -> {
                      if (re == null || re.isBlank()) {
                        logger.warn("Null or empty pattern cannot be used: ", re);
                        return null;
                      }
                      try {
                        Pattern pattern = Pattern.compile(re);
                        logger.trace("Compiled acceptable issuer regex as {}", pattern.pattern());
                        return pattern;
                      } catch (Throwable ex) {
                        logger.warn("The pattern \"{}\" cannot be compiled: ", re, ex);
                        return null;
                      }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
    this.acceptableIssuersFile = Strings.isNullOrEmpty(acceptableIssuersFile) ? null : new File(acceptableIssuersFile);
    this.pollPeriodMs = pollPeriod.toMillis();
  }
  

  @Override
  public boolean isAcceptable(String issuer) {
    Set<String> localAcceptableIssuers;
    boolean shouldUpdate = false;
    long now;
    if (Strings.isNullOrEmpty(issuer)) {
      logger.warn("Invalid issuer: {}", (issuer == null ? "<null>" : "<blank>"));
      return false;
    }
    synchronized (lock) {
      now = System.currentTimeMillis();
      if (lastFileCheck + pollPeriodMs < now) {
        lastFileCheck = now;
        shouldUpdate = true;
      } 
      localAcceptableIssuers = acceptableIssuers;
    }
    if (shouldUpdate) {
      checkFile(now);
      synchronized (lock) {
        localAcceptableIssuers = acceptableIssuers;
      }
    }
    if (localAcceptableIssuers.contains(issuer)) {
      return true;
    }
    for (Pattern acceptableIssuer : acceptableIssuerRegexes) {
      if (acceptableIssuer.matcher(issuer).matches()) {
        return true;
      }
    }
    return false;
  }
  
  private void checkFile(long now) {
    if (acceptableIssuersFile == null) {
      return ;
    }
    try {
      if (acceptableIssuersFile.isFile()) {
        long lastModNew = acceptableIssuersFile.lastModified();
        if (lastModNew != fileLastModified && lastModNew + pollPeriodMs < now) {
          fileLastModified = lastModNew;
          
          Set<String> newSet = new HashSet<>();
          try (Stream<String> stream = Files.lines(acceptableIssuersFile.toPath())) {
            stream
                    .forEach(l -> {
                      if (l != null) {
                        l = l.trim();
                        if (!l.isEmpty()) {
                          newSet.add(l);
                        }
                      }
                    })
                    ;
          }
          synchronized (lock) {
            acceptableIssuers = newSet;
          }
        }
      } else {
        synchronized (lock) {
          acceptableIssuers = Collections.emptySet();
        }
      }
    } catch (Throwable ex) {
      logger.error("Error loading acceptable issuers file: ", ex);
    }
  }
  
}
