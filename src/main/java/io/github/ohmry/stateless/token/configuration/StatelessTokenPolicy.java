package io.github.ohmry.stateless.token.configuration;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class StatelessTokenPolicy {
    private final SecretKey tokenSecretKey;
    private final SecretKey accessTokenSecretKey;
    private final SecretKey refreshTokenSecretKey;
    private final long tokenTimeoutSeconds;
    private final long accessTokenTimeoutSeconds;
    private final long refreshTokenTimeoutSeconds;

    public SecretKey getTokenSecretKey() {
        return tokenSecretKey;
    }

    public SecretKey getAccessTokenSecretKey() {
        return accessTokenSecretKey;
    }

    public SecretKey getRefreshTokenSecretKey() {
        return refreshTokenSecretKey;
    }

    public long getTokenTimeoutSeconds() {
        return tokenTimeoutSeconds;
    }

    public long getAccessTokenTimeoutSeconds() {
        return accessTokenTimeoutSeconds;
    }

    public long getRefreshTokenTimeoutSeconds() {
        return refreshTokenTimeoutSeconds;
    }

    private StatelessTokenPolicy(SecretKey tokenSecretKey,
                                 SecretKey accessTokenSecretKey,
                                 SecretKey refreshTokenSecretKey,
                                 Long tokenTimeoutSeconds,
                                 Long accessTokenTimeoutSeconds,
                                 Long refreshTokenTimeoutSeconds) {
        if (tokenSecretKey == null) {
            throw new IllegalArgumentException("tokenSecretKey must be not null.");
        } else {
            this.tokenSecretKey = tokenSecretKey;
        }
        this.accessTokenSecretKey = Objects.requireNonNullElse(accessTokenSecretKey, tokenSecretKey);
        this.refreshTokenSecretKey = Objects.requireNonNullElse(refreshTokenSecretKey, tokenSecretKey);

        if (tokenTimeoutSeconds == null) {
            throw new IllegalArgumentException("tokenTimeoutSeconds must be not null.");
        } else {
            this.tokenTimeoutSeconds = tokenTimeoutSeconds;
        }

        // default timeout is 30 minute.
        this.accessTokenTimeoutSeconds = Objects.requireNonNullElse(accessTokenTimeoutSeconds, 60 * 30L);

        // default timeout value is 12 hours.
        this.refreshTokenTimeoutSeconds = Objects.requireNonNullElse(refreshTokenTimeoutSeconds, 60 * 60 * 12L);
    }

    public static StatelessTokenPolicyBuilder builder() {
        return new StatelessTokenPolicyBuilder();
    }

    public static class StatelessTokenPolicyBuilder {
        private SecretKey tokenSecretKey;
        private SecretKey accessTokenSecretKey;
        private SecretKey refreshTokenSecretKey;
        private Long tokenTimeoutSeconds;
        private Long accessTokenTimeoutSeconds;
        private Long refreshTokenTimeoutSeconds;

        private StatelessTokenPolicyBuilder() {
            this.tokenSecretKey = null;
            this.accessTokenSecretKey = null;
            this.refreshTokenSecretKey = null;
            this.tokenTimeoutSeconds = null;
            this.accessTokenTimeoutSeconds = null;
            this.refreshTokenTimeoutSeconds = null;
        }

        public StatelessTokenPolicyBuilder tokenSecret(String secret) {
            this.tokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        public StatelessTokenPolicyBuilder accessTokenSecret(String secret) {
            this.accessTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        public StatelessTokenPolicyBuilder refreshTokenSecret(String secret) {
            this.refreshTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        public StatelessTokenPolicyBuilder tokenTimeout(Long timeoutSeconds) {
            this.tokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        public StatelessTokenPolicyBuilder accessTokenTimeout(Long timeoutSeconds) {
            this.accessTokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        public StatelessTokenPolicyBuilder refreshTokenTimeout(Long timeoutSeconds) {
            this.refreshTokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        public StatelessTokenPolicy build() {
            return new StatelessTokenPolicy(
                    this.tokenSecretKey,
                    this.accessTokenSecretKey,
                    this.refreshTokenSecretKey,
                    this.tokenTimeoutSeconds,
                    this.accessTokenTimeoutSeconds,
                    this.refreshTokenTimeoutSeconds);
        }
    }
}
