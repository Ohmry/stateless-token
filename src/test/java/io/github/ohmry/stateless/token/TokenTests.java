package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.config.*;
import io.github.ohmry.stateless.token.domain.Token;
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

class TokenTests {
    private static final String TOKEN_SECRET = "A".repeat(64);
    private static final SecretKey TOKEN_SECRET_KEY = Keys.hmacShaKeyFor(TOKEN_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long TOKEN_TIMEOUT = 3600;

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
    void testBasicTokenCreation() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        Token<Map<String, String>> token = Token.create(subject, TOKEN_TIMEOUT);

        assertThat(token).isNotNull();
        assertThat(token.getValue()).isNotNull();
        assertThat(token.getSubject()).isNotNull();
        assertThat(token.getSubject().get("userId")).isEqualTo("123");
        assertThat(token.getSubject().get("username")).isEqualTo("testuser");
        assertThat(token.isInvalidate()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testTokenParse() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        Token<Map<String, String>> createdToken = Token.create(subject, TOKEN_TIMEOUT);
        String tokenValue = createdToken.getValue();

        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedToken = (Token<Map<String, String>>) (Token<?>) Token.parse(tokenValue, Map.class);

        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.getSubject().get("username")).isEqualTo("testuser");
        assertThat(parsedToken.isInvalidate()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testTokenTimeout() throws InterruptedException {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        long shortTimeout = 1; // 1 second
        Token<Map<String, String>> token = Token.create(subject, shortTimeout);
        String tokenValue = token.getValue();

        Thread.sleep(1100); // Wait for token to expire

        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedToken = (Token<Map<String, String>>) (Token<?>) Token.parse(tokenValue, Map.class);

        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
        assertThat(parsedToken.getSubject()).isNull();
        assertThat(parsedToken.isInvalidate()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testTokenWithProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        Map<String, String> subject = new HashMap<>();
        subject.put("userId", "123");
        subject.put("username", "testuser");

        // Test creation with properties
        Token<Map<String, String>> createdToken = Token.create(subject, TOKEN_TIMEOUT);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with properties
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedToken = (Token<Map<String, String>>) (Token<?>) Token.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with properties
        long shortTimeout = 1;
        Token<Map<String, String>> expiredToken = Token.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedExpiredToken = (Token<Map<String, String>>) (Token<?>) Token.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void testTokenWithCustomizer() {
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

        // Test creation with customizer
        Token<Map<String, String>> createdToken = Token.create(subject, TOKEN_TIMEOUT);
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getSubject()).isNotNull();
        assertThat(createdToken.isInvalidate()).isFalse();

        // Test parse with customizer
        String tokenValue = createdToken.getValue();
        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedToken = (Token<Map<String, String>>) (Token<?>) Token.parse(tokenValue, Map.class);
        assertThat(parsedToken).isNotNull();
        assertThat(parsedToken.getSubject()).isNotNull();
        assertThat(parsedToken.getSubject().get("userId")).isEqualTo("123");
        assertThat(parsedToken.isInvalidate()).isFalse();

        // Test expiration with customizer
        long shortTimeout = 1;
        Token<Map<String, String>> expiredToken = Token.create(subject, shortTimeout);
        String expiredTokenValue = expiredToken.getValue();
        
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        @SuppressWarnings("unchecked")
        Token<Map<String, String>> parsedExpiredToken = (Token<Map<String, String>>) (Token<?>) Token.parse(expiredTokenValue, Map.class);
        assertThat(parsedExpiredToken).isNotNull();
        assertThat(parsedExpiredToken.getSubject()).isNull();
        assertThat(parsedExpiredToken.isInvalidate()).isTrue();
    }
}

