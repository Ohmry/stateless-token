package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.config.*;
import io.github.ohmry.stateless.token.domain.RefreshToken;
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

class RefreshTokenTests {
    private static final String TOKEN_SECRET = "A".repeat(64);
    private static final String REFRESH_SECRET = "C".repeat(64);
    private static final SecretKey TOKEN_SECRET_KEY = Keys.hmacShaKeyFor(TOKEN_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final SecretKey REFRESH_SECRET_KEY = Keys.hmacShaKeyFor(REFRESH_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long TOKEN_TIMEOUT = 3600;
    private static final long REFRESH_TIMEOUT = 43200;

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
    void testBasicRefreshTokenCreation() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        RefreshToken<Map<String, String>> token = RefreshToken.create(subject);

            assertThat(token).isNotNull();
        assertThat(token.getValue()).isNotNull();
        assertThat(token.getSubject()).isNotNull();
        assertThat(token.getSubject().get("userId")).isEqualTo("123");
        assertThat(token.getSubject().get("username")).isEqualTo("testuser");
            assertThat(token.isInvalidate()).isFalse();
    }

    @Test
    void testRefreshTokenCreationWithTimeout() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        RefreshToken<Map<String, String>> token = RefreshToken.create(subject, REFRESH_TIMEOUT);

            assertThat(token).isNotNull();
        assertThat(token.getSubject()).isNotNull();
        assertThat(token.isInvalidate()).isFalse();
    }

    @Test
    void testRefreshTokenParse() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject, REFRESH_TIMEOUT);
        String tokenValue = createdToken.getValue();

        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);

            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.getSubject().get("username")).isEqualTo("testuser");
            assertThat(parsedToken.isInvalidate()).isFalse();
    }

    @Test
    void testRefreshTokenTimeout() throws InterruptedException {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        long shortTimeout = 1; // 1 second
        RefreshToken<Map<String, String>> token = RefreshToken.create(subject, shortTimeout);
            String tokenValue = token.getValue();

        Thread.sleep(1100); // Wait for token to expire

        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);

            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
            assertThat(parsedToken.getSubject()).isNull();
            assertThat(parsedToken.isInvalidate()).isTrue();
        }

    @Test
    void testRefreshTokenWithProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with properties
        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with properties
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with properties
        long shortTimeout = 1;
        RefreshToken<Map<String, String>> expiredToken = RefreshToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedExpiredToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testRefreshTokenWithRefreshProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.refresh.secret")).thenReturn(REFRESH_SECRET);
        when(environment.getProperty("stateless.token.refresh.timeout")).thenReturn(String.valueOf(REFRESH_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with refresh properties
        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with refresh properties
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with refresh properties
        long shortTimeout = 1;
        RefreshToken<Map<String, String>> expiredToken = RefreshToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedExpiredToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testRefreshTokenWithCommonSecretAndTimeout() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test that refresh token uses common secret when refresh secret is not set
        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
    }

    @Test
    void testRefreshTokenWithCustomizer() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setRefreshTokenSecretKey(REFRESH_SECRET);
                impl.setRefreshTokenTimeoutSeconds(REFRESH_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with customizer
        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with customizer
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
            assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with customizer
        long shortTimeout = 1;
        RefreshToken<Map<String, String>> expiredToken = RefreshToken.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedExpiredToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    void testRefreshTokenWithCustomizerCommonSecret() {
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

        // Test that refresh token uses common secret from customizer when refresh secret is not set
        RefreshToken<Map<String, String>> createdToken = RefreshToken.create(subject);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        RefreshToken<Map<String, String>> parsedToken = (RefreshToken<Map<String, String>>) (RefreshToken<?>) RefreshToken.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
    }
}

