# stateless-token

A Spring Boot library that provides easy-to-use JWT token objects (AccessToken and RefreshToken) with minimal configuration. This library simplifies JWT token creation and validation by abstracting away the complexity of JWT library implementation.

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

```yaml
stateless:
  token:
    secret: "your-secret-key-at-least-64-characters-long-for-hmac-sha512"
    access:
      secret: "optional-access-token-specific-secret"
    refresh:
      secret: "optional-refresh-token-specific-secret"
    timeout: 300  # Optional: default timeout in seconds
```

Or using `application.properties`:

```properties
stateless.token.secret=your-secret-key-at-least-64-characters-long-for-hmac-sha512
stateless.token.access.secret=optional-access-token-specific-secret
stateless.token.refresh.secret=optional-refresh-token-specific-secret
stateless.token.timeout=300
```

### 2. Create Access Token

```java
import io.github.ohmry.stateless.token.domain.AccessToken;

// Create an access token with default timeout from configuration
AccessToken<String> accessToken = AccessToken.create("user-id-123");

// Create an access token with custom timeout (in seconds)
AccessToken<String> accessToken = AccessToken.create("user-id-123", 300);

// Get token value
String tokenValue = accessToken.getValue();

// Parse and validate token
AccessToken<String> parsedToken = AccessToken.create(tokenValue, String.class);
String subject = parsedToken.getSubject();
boolean isValid = !parsedToken.isInvalidate();
```

### 3. Create Refresh Token

```java
import io.github.ohmry.stateless.token.domain.RefreshToken;

// Create a refresh token with default timeout from configuration
RefreshToken<String> refreshToken = RefreshToken.create("user-id-123");

// Create a refresh token with custom timeout (in seconds)
RefreshToken<String> refreshToken = RefreshToken.create("user-id-123", 43200);

// Get token value
String tokenValue = refreshToken.getValue();

// Parse and validate token
RefreshToken<String> parsedToken = RefreshToken.create(tokenValue, String.class);
String subject = parsedToken.getSubject();
boolean isValid = !parsedToken.isInvalidate();
```

### 4. Using Complex Subject Types

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
AccessToken<UserInfo> parsedToken = AccessToken.create(tokenValue, UserInfo.class);
UserInfo user = parsedToken.getSubject();
```

### 5. Token Validation

```java
AccessToken<String> token = AccessToken.create(tokenValue, String.class);

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
| `stateless.token.access.secret` | Access token specific secret key | Uses common secret if not set |
| `stateless.token.refresh.secret` | Refresh token specific secret key | Uses common secret if not set |
| `stateless.token.timeout` | Default timeout for tokens (seconds) | 300 (5 minutes) for access, 43200 (12 hours) for refresh |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
