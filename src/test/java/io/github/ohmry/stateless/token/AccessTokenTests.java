package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.config.*;
import io.github.ohmry.stateless.token.domain.AccessToken;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AccessTokenTests {
    private static final String TOKEN_SECRET = "A".repeat(64);
    private static final String ACCESS_SECRET = "B".repeat(64);
    private static final SecretKey TOKEN_SECRET_KEY = Keys.hmacShaKeyFor(TOKEN_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final SecretKey ACCESS_SECRET_KEY = Keys.hmacShaKeyFor(ACCESS_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long TOKEN_TIMEOUT = 3600;
    private static final long ACCESS_TIMEOUT = 300;

    private Environment environment;
    private ObjectProvider<StatelessTokenPolicyCustomizer> customizerProvider;
    private List<StatelessTokenPolicyAware> awareList;
    private StatelessTokenPolicyAutoConfiguration configuration;

    @BeforeEach
    void setUp() {
        environment = mock(Environment.class);
        customizerProvider = mock(ObjectProvider.class);
        awareList = new ArrayList<>();
        awareList.add(new StatelessTokenPolicyHolder());
        configuration = new StatelessTokenPolicyAutoConfiguration();
    }

    @Test
    void testBasicAccessTokenCreation() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        AccessToken<Map<String, String>> token = AccessToken.create(subject);

        assertThat(token).isNotNull();
        assertThat(token.getValue()).isNotNull();
        assertThat(token.getSubject()).isNotNull();
        assertThat(token.getSubject().get("userId")).isEqualTo("123");
        assertThat(token.getSubject().get("username")).isEqualTo("testuser");
        assertThat(token.isInvalidate()).isFalse();
    }

    @Test
    void testAccessTokenCreationWithTimeout() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        AccessToken<Map<String, String>> token = AccessToken.create(subject, ACCESS_TIMEOUT);

        assertThat(token).isNotNull();
        assertThat(token.getSubject()).isNotNull();
        assertThat(token.isInvalidate()).isFalse();
    }

    @Test
    void testAccessTokenParse() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject, ACCESS_TIMEOUT);
        String tokenValue = createdToken.getValue();

        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);

        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.getSubject().get("username")).isEqualTo("testuser");
        assertThat(parsedToken.isInvalidate()).isFalse();
    }

    @Test
    void testAccessTokenTimeout() throws InterruptedException {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        long shortTimeout = 1; // 1 second
        AccessToken<Map<String, String>> token = AccessToken.create(subject, shortTimeout);
        String tokenValue = token.getValue();

        Thread.sleep(1100); // Wait for token to expire

        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);

        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
        assertThat(parsedToken.getSubject()).isNull();
        assertThat(parsedToken.isInvalidate()).isTrue();
    }

    @Test
    void testAccessTokenWithProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with properties
        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with properties
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with properties
        long shortTimeout = 1;
        AccessToken<Map<String, String>> expiredToken = AccessToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedExpiredToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testAccessTokenWithAccessProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.access.secret")).thenReturn(ACCESS_SECRET);
        when(environment.getProperty("stateless.token.access.timeout")).thenReturn(String.valueOf(ACCESS_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with access properties
        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with access properties
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with access properties
        long shortTimeout = 1;
        AccessToken<Map<String, String>> expiredToken = AccessToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedExpiredToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testAccessTokenWithCommonSecretAndTimeout() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test that access token uses common secret when access secret is not set
        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
    }

    @Test
    void testAccessTokenWithCustomizer() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setAccessTokenSecretKey(ACCESS_SECRET);
                impl.setAccessTokenTimeoutSeconds(ACCESS_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with customizer
        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with customizer
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with customizer
        long shortTimeout = 1;
        AccessToken<Map<String, String>> expiredToken = AccessToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedExpiredToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testAccessTokenWithCustomizerCommonSecret() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setTokenSecretKey(TOKEN_SECRET);
                impl.setTokenTimeoutSeconds(TOKEN_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test that access token uses common secret from customizer when access secret is not set
        AccessToken<Map<String, String>> createdToken = AccessToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        AccessToken<Map<String, String>> parsedToken = (AccessToken<Map<String, String>>) (AccessToken<?>) AccessToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
    }
}

