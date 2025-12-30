# stateless-token

A Spring Boot library that provides easy-to-use JWT token objects (AccessToken and RefreshToken) with minimal configuration. This library simplifies JWT token creation and validation by abstracting away the complexity of JWT library implementation.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Configuration](#1-configuration)
  - [2. Using AccessToken](#2-using-accesstoken)
  - [3. Using RefreshToken](#3-using-refreshtoken)
  - [4. Using Token](#4-using-token)
  - [5. Using Complex Subject Types](#5-using-complex-subject-types)
  - [6. Token Validation](#6-token-validation)
- [Configuration Properties](#configuration-properties)
- [License](#license)
- [Contributing](#contributing)

## Overview

When working with JWT tokens, developers typically need to:

- Add JWT library dependencies
- Implement token creation logic
- Handle token parsing and validation
- Manage token expiration
- Separate AccessToken and RefreshToken implementations

This library provides ready-to-use token classes that handle all of this complexity, allowing you to focus on your business logic instead of JWT implementation details.

## Features

- **Simple API**: Create and validate tokens with minimal code
- **Type-safe**: Generic token classes support any subject type
- **Spring Boot Auto-configuration**: Automatically configured via Spring Boot properties
- **AccessToken & RefreshToken**: Pre-built token types following industry standards
- **Automatic Expiration Handling**: Built-in token expiration and validation

## Requirements

- Java 17 or higher
- Spring Boot 3.5.9 or higher

## Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.ohmry</groupId>
    <artifactId>stateless-token</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Quick Start

### 1. Configuration

Add the following properties to your `application.yml` or `application.properties`:

**application.yml**
```yaml
stateless:
  token:
    secret: "your-secret-key-at-least-64-characters-long-for-hmac-sha512"
    timeout: 300 # timeout in seconds (required)
  accessToken:
    secret: "optional-access-token-specific-secret"
    timeout: 1800  # Optional: access token timeout in seconds (defaults to 30 minutes)
  refreshToken:
    secret: "optional-refresh-token-specific-secret"
    timeout: 43200  # Optional: refresh token timeout in seconds (defaults to 12 hours)
```

**application.properties**
```properties
stateless.token.secret=your-secret-key-at-least-64-characters-long-for-hmac-sha512
stateless.token.timeout=300
stateless.accessToken.secret=optional-access-token-specific-secret
stateless.accessToken.timeout=1800
stateless.refreshToken.secret=optional-refresh-token-specific-secret
stateless.refreshToken.timeout=43200
```

### 2. Using AccessToken

```java
import io.github.ohmry.stateless.token.domain.AccessToken;

// Create an access token with default timeout from configuration
AccessToken<String> accessToken = AccessToken.create("user-id-123");

// Create an access token with custom timeout (in seconds)
AccessToken<String> accessToken = AccessToken.create("user-id-123", 300);

// Get token value
String tokenValue = accessToken.getValue();

// Parse and validate token
AccessToken<String> parsedToken = AccessToken.parse(tokenValue, String.class);
String subject = parsedToken.getSubject();
boolean isValid = !parsedToken.isInvalidate();
```

### 3. Using RefreshToken

```java
import io.github.ohmry.stateless.token.domain.RefreshToken;

// Create a refresh token with default timeout from configuration
RefreshToken<String> refreshToken = RefreshToken.create("user-id-123");

// Create a refresh token with custom timeout (in seconds)
RefreshToken<String> refreshToken = RefreshToken.create("user-id-123", 43200);

// Get token value
String tokenValue = refreshToken.getValue();

// Parse and validate token
RefreshToken<String> parsedToken = RefreshToken.parse(tokenValue, String.class);
String subject = parsedToken.getSubject();
boolean isValid = !parsedToken.isInvalidate();
```

### 4. Using Token

You can also use the base `Token` class directly:

```java
import io.github.ohmry.stateless.token.domain.Token;

// Create a token with default timeout from configuration
Token<String> token = Token.create("user-id-123");

// Create a token with custom timeout (in seconds)
Token<String> token = Token.create("user-id-123", 300);

// Get token value
String tokenValue = token.getValue();

// Parse and validate token
Token<String> parsedToken = Token.parse(tokenValue, String.class);
String subject = parsedToken.getSubject();
boolean isValid = !parsedToken.isInvalidate();
```

### 5. Using Complex Subject Types

You can use any type as the token subject:

```java
// Using a custom object
public class UserInfo {
    private String userId;
    private String username;
    // getters, setters, constructors
}

// Create token with custom object
UserInfo userInfo = new UserInfo("123", "john.doe");
AccessToken<UserInfo> accessToken = AccessToken.create(userInfo, 300);

// Parse token
AccessToken<UserInfo> parsedToken = AccessToken.parse(tokenValue, UserInfo.class);
UserInfo user = parsedToken.getSubject();
```

You can also use `Map<String, Object>` as the token subject:

```java
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.Map;

// Create token with Map
Map<String, Object> userData = Map.of(
    "id", 1,
    "name", "john.doe",
    "email", "john.doe@example.com"
);
AccessToken<Map<String, Object>> accessToken = AccessToken.create(userData, 300);

// Parse token using TypeReference
AccessToken<Map<String, Object>> parsedToken = AccessToken.parse(tokenValue, new TypeReference<>() {});
Map<String, Object> user = parsedToken.getSubject();
String name = (String) user.get("name");
```

### 6. Token Validation

```java
AccessToken<String> token = AccessToken.parse(tokenValue, String.class);

if (token.isInvalidate()) {
    // Token is expired or invalid
    // token.getSubject() will be null
} else {
    // Token is valid
    String subject = token.getSubject();
}
```

## Configuration Properties

| Property | Description | Default |
|----------|-------------|---------|
| `stateless.token.secret` | Common secret key for both access and refresh tokens | Required |
| `stateless.token.timeout` | Default timeout for tokens (seconds) | Required |
| `stateless.accessToken.secret` | Access token specific secret key | Uses common secret if not set |
| `stateless.accessToken.timeout` | Access token timeout in seconds | 1800 (30 minutes) |
| `stateless.refreshToken.secret` | Refresh token specific secret key | Uses common secret if not set |
| `stateless.refreshToken.timeout` | Refresh token timeout in seconds | 43200 (12 hours) |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
