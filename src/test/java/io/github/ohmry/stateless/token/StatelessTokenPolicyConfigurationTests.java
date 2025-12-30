package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyConfiguration;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class StatelessTokenPolicyConfigurationTests {
    @Test
    void stateless_token_secret_is_required() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        assertThatThrownBy(() -> configuration.statelessTokenPolicy(environment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stateless.token.secret is required.");
    }

    @Test
    void stateless_token_timeout_is_required() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        // Given
        Mockito.when(environment.getProperty("stateless.token.secret"))
                        .thenReturn("ABCDEFGH".repeat(8));

        // Then
        assertThatThrownBy(() -> configuration.statelessTokenPolicy(environment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("stateless.token.timeout is required.");
    }

    @Test
    void stateless_token_policy_default() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        SecretKey targetSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));

        // Given
        Mockito.when(environment.getProperty("stateless.token.secret"))
                .thenReturn("ABCDEFGH".repeat(8));
        Mockito.when(environment.getProperty("stateless.token.timeout"))
                        .thenReturn("300");

        // Then
        StatelessTokenPolicy statelessTokenPolicy = configuration.statelessTokenPolicy(environment);
        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(targetSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(targetSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(targetSecretKey);
        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }

    @Test
    void stateless_access_token_secret() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        SecretKey tokenSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));
        SecretKey accessTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));

        // When
        Mockito.when(environment.getProperty("stateless.token.secret"))
                .thenReturn("ABCDEFGH".repeat(8));
        Mockito.when(environment.getProperty("stateless.token.timeout"))
                .thenReturn("300");
        Mockito.when(environment.getProperty("stateless.accessToken.secret"))
                .thenReturn("12345678".repeat(8));

        // Then
        StatelessTokenPolicy statelessTokenPolicy = configuration.statelessTokenPolicy(environment);
        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(accessTokenSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }

    @Test
    void stateless_access_token_secret_with_timeout() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        SecretKey tokenSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));
        SecretKey accessTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));

        // When
        Mockito.when(environment.getProperty("stateless.token.secret"))
                .thenReturn("ABCDEFGH".repeat(8));
        Mockito.when(environment.getProperty("stateless.token.timeout"))
                .thenReturn("300");
        Mockito.when(environment.getProperty("stateless.accessToken.secret"))
                .thenReturn("12345678".repeat(8));
        Mockito.when(environment.getProperty("stateless.accessToken.timeout"))
                .thenReturn("600");

        // Then
        StatelessTokenPolicy statelessTokenPolicy = configuration.statelessTokenPolicy(environment);
        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(accessTokenSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(600);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }

    @Test
    void stateless_refresh_token_secret() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        SecretKey tokenSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));
        SecretKey refreshTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));

        // When
        Mockito.when(environment.getProperty("stateless.token.secret"))
                .thenReturn("ABCDEFGH".repeat(8));
        Mockito.when(environment.getProperty("stateless.token.timeout"))
                .thenReturn("300");
        Mockito.when(environment.getProperty("stateless.refreshToken.secret"))
                .thenReturn("12345678".repeat(8));

        // Then
        StatelessTokenPolicy statelessTokenPolicy = configuration.statelessTokenPolicy(environment);
        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(refreshTokenSecretKey);
        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }

    @Test
    void stateless_refresh_token_secret_with_timeout() {
        StatelessTokenPolicyConfiguration configuration = new StatelessTokenPolicyConfiguration();
        Environment environment = Mockito.mock(Environment.class);

        SecretKey tokenSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));
        SecretKey refreshTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));

        // When
        Mockito.when(environment.getProperty("stateless.token.secret"))
                .thenReturn("ABCDEFGH".repeat(8));
        Mockito.when(environment.getProperty("stateless.token.timeout"))
                .thenReturn("300");
        Mockito.when(environment.getProperty("stateless.refreshToken.secret"))
                .thenReturn("12345678".repeat(8));
        Mockito.when(environment.getProperty("stateless.refreshToken.timeout"))
                .thenReturn("600");

        // Then
        StatelessTokenPolicy statelessTokenPolicy = configuration.statelessTokenPolicy(environment);
        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(tokenSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(refreshTokenSecretKey);
        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30L);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(600);
    }
}
