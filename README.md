# vertx-token-validation

[![Latest release](https://img.shields.io/github/release/yaytay/vertx-token-validation.svg)](https://github.com/yaytay/vertx-token-validation/latest)
[![License](https://img.shields.io/github/license/yaytay/vertx-token-validation)](https://github.com/yaytay/vertx-token-validation/blob/master/LICENCE.md)
[![Issues](https://img.shields.io/github/issues/yaytay/vertx-token-validation)](https://github.com/yaytay/vertx-token-validation/issues)
[![Build Status](https://github.com/yaytay/vertx-token-validation/actions/workflows/buildtest.yml/badge.svg)](https://github.com/Yaytay/vertx-token-validation/actions/workflows/buildtest.yml)
[![CodeCov](https://codecov.io/gh/Yaytay/vertx-token-validation/branch/main/graph/badge.svg?token=ACHVK20T9Q)](https://codecov.io/gh/Yaytay/vertx-token-validation)

A basic library to parse and verify JWTs, with OpenID discovery used to obtain JWKs asynchronously (via Vertx).

The library uses vertx-web, but does not use vertx-auth-common and does not attempt to provide a Vertx Auth solution (there is no implementation of AuthorizationProvider in this library).

# Getting Started
Release versions should be in maven central, so declare the dependency in your pom.xml:
```xml
    <dependency>
      <groupId>uk.co.spudsoft</groupId>
      <artifactId>vertx-token-validation</artifactId>
      <version>0.0.13</version>
    </dependency>
```

Then create a TokenValidator and ask it to validate a token:
```java
  // Create a TokenValidator
  TokenValidator validator = TokenValidator.create(
          // The Vertx instance that will be used to make web requests
          vertx, 
          // Array of acceptable issuers (as regular expressions).
          Arrays.asList("http://localhost.*"), 
          // Time to cache JWK keys for if they do have a cache-control(max-age) header
          Duration.of(1, ChronoUnit.MINUTES)
  );
  // By default the TokenValidator will accept RS256, RS384 and RS512, any others that must be handled must be specified.
  validator.addPermittedAlgorithm(jwa);
  // In this setup a token need not expire (this is bad practice, just to demonstrate that the validator has some configuration options).
  valiator.setRequireExp(false);

  // Get the JWT in its usual 3 x Base64 form.
  String authHeader = exchange.getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION.toString());
  if (authHeader.startsWith("Bearer ")) {
    String token = authHeader.substring(7);
    // Call the validator, requiring the token to contain "my-service" as an audience claim.
    validator.validateToken(token, Arrays.asList("my-service"), false)
            .compose(signedJwt -> {
              // Standard claims can be extracted with named methods
              logger.debug("Token valid from: {}", signedJwt.getNotBeforeLocalDateTime());
              // Non-standard claims can be extracted with the claim method
              logger.debug("Token tags: {}", signedJwt.getClaim("tags"));
            });
```

JavaDocs can be found on the site reports at (https://yaytay.github.io/vertx-token-validation/).

# How It Works

The TokenValidator first parses the JWT, then determines the algorithm that was used to sign it along with the key ID (kid) and issuer (iss).
Both the issuer and the algorithm must match those that the TokenValidator is configured to accept.
From this the TokenValidator carries out [OpenIdDiscovery](https://openid.net/specs/openid-connect-discovery-1_0.html) to obtain the [JWK Set](https://www.rfc-editor.org/rfc/rfc7517) from the issuer.
Once the JWK has been obtained the signature is verified.

If the signature is authentic the fields of the token are validated.

In the time validation methods there is a permitted time leeway that can be configured.
This defaults to 0, but it is recommended that it be set to a small number of seconds to avoid race conditions with clock synching and network delays.
The time validation methods can be disabled using the setRequireExp and setRequireNbf methods, but this should only be done if you are working with a third party JWT that does not provide them.

The fields that are validated are:
* [nbf](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5)
The nbf field of the token must be less than or equal to the current time since epoch in seconds (obtained via System.currentTimeMillis).
* [exp](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4)
The exp field of the token must be greater than or equal to the current time since epoch in seconds (obtained via System.currentTimeMillis).
* [aud](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3)
The aud field of the token (which can be a single value or an array) must contain at least one of the values that are passed in the call to validateToken.
The aud check can be disabled with the ignoreRequiredAud parameter in the call to validateToken.
* [sub](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2)
The sub field of the token must not be blank.


## Caching
If the response for the OpenId Discovery or JWK Set requests have [Cache-Control, max-age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#max-age) headers the response is cached according to that age.
If there is no max-age headers the values are cached according to the Duration passed in to the TokenValidator factory method.

The OpenID Discovery data is cached using the issuer as key, the JWK Set data is cached using the jwk_uri as key.

Valid tokens are not cached, though it is recommended that clients do so.

## Logging
All logging is via slf4j.

# Building

It's a standard maven project, just build it with:
```sh
mvn clean install
```

There are a few dependencies (guava, jackson, vertx-web-client), and quite a few maven plugins.
Note that the version is determined using [jgitver](https://jgitver.github.io/).
