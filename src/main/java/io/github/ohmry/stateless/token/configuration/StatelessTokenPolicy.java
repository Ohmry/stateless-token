package io.github.ohmry.stateless.token.configuration;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Configuration policy for stateless tokens.
 * This class holds the secret keys and timeout settings for tokens, access tokens, and refresh tokens.
 *
 * @author ohmry
 */
public class StatelessTokenPolicy {
    private final SecretKey tokenSecretKey;
    private final SecretKey accessTokenSecretKey;
    private final SecretKey refreshTokenSecretKey;
    private final long tokenTimeoutSeconds;
    private final long accessTokenTimeoutSeconds;
    private final long refreshTokenTimeoutSeconds;

    /**
     * Returns the secret key for general tokens.
     *
     * @return the token secret key
     */
    public SecretKey getTokenSecretKey() {
        return tokenSecretKey;
    }

    /**
     * Returns the secret key for access tokens.
     *
     * @return the access token secret key
     */
    public SecretKey getAccessTokenSecretKey() {
        return accessTokenSecretKey;
    }

    /**
     * Returns the secret key for refresh tokens.
     *
     * @return the refresh token secret key
     */
    public SecretKey getRefreshTokenSecretKey() {
        return refreshTokenSecretKey;
    }

    /**
     * Returns the timeout in seconds for general tokens.
     *
     * @return the token timeout in seconds
     */
    public long getTokenTimeoutSeconds() {
        return tokenTimeoutSeconds;
    }

    /**
     * Returns the timeout in seconds for access tokens.
     *
     * @return the access token timeout in seconds
     */
    public long getAccessTokenTimeoutSeconds() {
        return accessTokenTimeoutSeconds;
    }

    /**
     * Returns the timeout in seconds for refresh tokens.
     *
     * @return the refresh token timeout in seconds
     */
    public long getRefreshTokenTimeoutSeconds() {
        return refreshTokenTimeoutSeconds;
    }

    /**
     * Creates a new StatelessTokenPolicy with the specified configuration.
     *
     * @param tokenSecretKey the secret key for general tokens (required)
     * @param accessTokenSecretKey the secret key for access tokens (optional, defaults to tokenSecretKey)
     * @param refreshTokenSecretKey the secret key for refresh tokens (optional, defaults to tokenSecretKey)
     * @param tokenTimeoutSeconds the timeout in seconds for general tokens (required)
     * @param accessTokenTimeoutSeconds the timeout in seconds for access tokens (optional, defaults to 30 minutes)
     * @param refreshTokenTimeoutSeconds the timeout in seconds for refresh tokens (optional, defaults to 12 hours)
     * @throws IllegalArgumentException if tokenSecretKey or tokenTimeoutSeconds is null
     */
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

    /**
     * Creates a new builder for constructing a StatelessTokenPolicy.
     *
     * @return a new StatelessTokenPolicyBuilder instance
     */
    public static StatelessTokenPolicyBuilder builder() {
        return new StatelessTokenPolicyBuilder();
    }

    /**
     * Builder class for constructing StatelessTokenPolicy instances.
     */
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

        /**
         * Sets the secret key for general tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder tokenSecret(String secret) {
            this.tokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        /**
         * Sets the secret key for access tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder accessTokenSecret(String secret) {
            this.accessTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        /**
         * Sets the secret key for refresh tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder refreshTokenSecret(String secret) {
            this.refreshTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        /**
         * Sets the timeout in seconds for general tokens.
         *
         * @param timeoutSeconds the timeout in seconds
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder tokenTimeout(Long timeoutSeconds) {
            this.tokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        /**
         * Sets the timeout in seconds for access tokens.
         *
         * @param timeoutSeconds the timeout in seconds
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder accessTokenTimeout(Long timeoutSeconds) {
            this.accessTokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        /**
         * Sets the timeout in seconds for refresh tokens.
         *
         * @param timeoutSeconds the timeout in seconds
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder refreshTokenTimeout(Long timeoutSeconds) {
            this.refreshTokenTimeoutSeconds = timeoutSeconds;
            return this;
        }

        /**
         * Builds a new StatelessTokenPolicy instance with the configured values.
         *
         * @return a new StatelessTokenPolicy instance
         * @throws IllegalArgumentException if required fields are not set
         */
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
