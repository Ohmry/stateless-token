package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.config.*;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class StatelessTokenPolicyTests {
    private static final String TOKEN_SECRET = "A".repeat(64);
    private static final String ACCESS_SECRET = "B".repeat(64);
    private static final String REFRESH_SECRET = "C".repeat(64);
    private static final SecretKey TOKEN_SECRET_KEY = Keys.hmacShaKeyFor(TOKEN_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final SecretKey ACCESS_SECRET_KEY = Keys.hmacShaKeyFor(ACCESS_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final SecretKey REFRESH_SECRET_KEY = Keys.hmacShaKeyFor(REFRESH_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long TOKEN_TIMEOUT = 3600;
    private static final long ACCESS_TIMEOUT = 300;
    private static final long REFRESH_TIMEOUT = 43200;
    private static final long DEFAULT_ACCESS_TIMEOUT = 60 * 5; // 5 minutes
    private static final long DEFAULT_REFRESH_TIMEOUT = 60 * 60 * 12; // 12 hours

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
    void testPolicyHolderValueTransmission() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        StatelessTokenPolicy retrievedPolicy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        assertThat(retrievedPolicy).isNotNull();
        assertThat(retrievedPolicy.getTokenSecretKey()).isEqualTo(TOKEN_SECRET_KEY);
        assertThat(retrievedPolicy.getTokenTimoutSeconds()).isEqualTo(TOKEN_TIMEOUT);
    }

    @Test
    void testPropertiesReflection() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(environment.getProperty("stateless.token.timeout")).thenReturn(String.valueOf(TOKEN_TIMEOUT));
        when(environment.getProperty("stateless.token.access.secret")).thenReturn(ACCESS_SECRET);
        when(environment.getProperty("stateless.token.access.timeout")).thenReturn(String.valueOf(ACCESS_TIMEOUT));
        when(environment.getProperty("stateless.token.refresh.secret")).thenReturn(REFRESH_SECRET);
        when(environment.getProperty("stateless.token.refresh.timeout")).thenReturn(String.valueOf(REFRESH_TIMEOUT));
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getTokenSecretKey()).isEqualTo(TOKEN_SECRET_KEY);
        assertThat(policy.getTokenTimoutSeconds()).isEqualTo(TOKEN_TIMEOUT);
        assertThat(policy.getAccessTokenSecretKey()).isEqualTo(ACCESS_SECRET_KEY);
        assertThat(policy.getAccessTokenTimeoutSeconds()).isEqualTo(ACCESS_TIMEOUT);
        assertThat(policy.getRefreshTokenSecretKey()).isEqualTo(REFRESH_SECRET_KEY);
        assertThat(policy.getRefreshTokenTimeoutSeconds()).isEqualTo(REFRESH_TIMEOUT);
    }

    @Test
    void testDefaultTimeoutValues() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        when(customizerProvider.orderedStream()).thenReturn(Stream.empty());

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getAccessTokenTimeoutSeconds()).isEqualTo(DEFAULT_ACCESS_TIMEOUT);
        assertThat(policy.getRefreshTokenTimeoutSeconds()).isEqualTo(DEFAULT_REFRESH_TIMEOUT);
    }

    @Test
    void testCustomizerTokenSecretKey() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setTokenSecretKey(ACCESS_SECRET);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getTokenSecretKey()).isEqualTo(ACCESS_SECRET_KEY);
    }

    @Test
    void testCustomizerAccessTokenSecretKey() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setAccessTokenSecretKey(ACCESS_SECRET);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getAccessTokenSecretKey()).isEqualTo(ACCESS_SECRET_KEY);
    }

    @Test
    void testCustomizerRefreshTokenSecretKey() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setRefreshTokenSecretKey(REFRESH_SECRET);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getRefreshTokenSecretKey()).isEqualTo(REFRESH_SECRET_KEY);
    }

    @Test
    void testCustomizerTokenTimeoutSeconds() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setTokenTimeoutSeconds(TOKEN_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getTokenTimoutSeconds()).isEqualTo(TOKEN_TIMEOUT);
    }

    @Test
    void testCustomizerAccessTokenTimeoutSeconds() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setAccessTokenTimeoutSeconds(ACCESS_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getAccessTokenTimeoutSeconds()).isEqualTo(ACCESS_TIMEOUT);
    }

    @Test
    void testCustomizerRefreshTokenTimeoutSeconds() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setRefreshTokenTimeoutSeconds(REFRESH_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getRefreshTokenTimeoutSeconds()).isEqualTo(REFRESH_TIMEOUT);
    }

    @Test
    void testCustomizerAllProperties() {
        when(environment.getProperty("stateless.token.secret")).thenReturn(TOKEN_SECRET);
        StatelessTokenPolicyCustomizer customizer = policy -> {
            if (policy instanceof StatelessTokenPolicyImpl impl) {
                impl.setTokenSecretKey(TOKEN_SECRET);
                impl.setAccessTokenSecretKey(ACCESS_SECRET);
                impl.setRefreshTokenSecretKey(REFRESH_SECRET);
                impl.setTokenTimeoutSeconds(TOKEN_TIMEOUT);
                impl.setAccessTokenTimeoutSeconds(ACCESS_TIMEOUT);
                impl.setRefreshTokenTimeoutSeconds(REFRESH_TIMEOUT);
            }
        };
        when(customizerProvider.orderedStream()).thenReturn(Stream.of(customizer));

        StatelessTokenPolicy policy = configuration.statelessTokenPolicy(environment, customizerProvider, awareList);

        assertThat(policy.getTokenSecretKey()).isEqualTo(TOKEN_SECRET_KEY);
        assertThat(policy.getAccessTokenSecretKey()).isEqualTo(ACCESS_SECRET_KEY);
        assertThat(policy.getRefreshTokenSecretKey()).isEqualTo(REFRESH_SECRET_KEY);
        assertThat(policy.getTokenTimoutSeconds()).isEqualTo(TOKEN_TIMEOUT);
        assertThat(policy.getAccessTokenTimeoutSeconds()).isEqualTo(ACCESS_TIMEOUT);
        assertThat(policy.getRefreshTokenTimeoutSeconds()).isEqualTo(REFRESH_TIMEOUT);
    }
}

