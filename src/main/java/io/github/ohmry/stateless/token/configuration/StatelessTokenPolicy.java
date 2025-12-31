package io.github.ohmry.stateless.token.configuration;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import static java.util.Base64.getEncoder;

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

        private void handleWeakKeyException(String secretName) {
            SecureRandom secureRandom = new SecureRandom();
            byte[] key = new byte[64];
            secureRandom.nextBytes(key);
            String randomSecret = Base64.getEncoder().encodeToString(key);

            String stringBuilder = "The " + secretName + "string is too weak to be used as a secret key. You must use a string that is at least 64 bytes long" +
                    "\n\n" +
                    "You can create a secret key by using the random value below." + "\n\n\t" +
                    randomSecret + "\n";
            Logger logger = LoggerFactory.getLogger(this.getClass());
            logger.error(stringBuilder);
        }

        /**
         * Sets the secret key for general tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder tokenSecret(String secret) {
            try {
                this.tokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            } catch (WeakKeyException e) {
                this.tokenSecretKey = null;
                this.handleWeakKeyException("tokenSecret");
                throw e;
            }
            return this;
        }

        /**
         * Sets the secret key for access tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder accessTokenSecret(String secret) {
            try {
                this.accessTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            } catch (WeakKeyException e) {
                this.accessTokenSecretKey = null;
                this.handleWeakKeyException("accessTokenSecret");
                throw e;
            }
            return this;
        }

        /**
         * Sets the secret key for refresh tokens.
         *
         * @param secret the secret string used to generate the secret key
         * @return this builder instance
         */
        public StatelessTokenPolicyBuilder refreshTokenSecret(String secret) {
            try {
                this.refreshTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            } catch (WeakKeyException e) {
                this.refreshTokenSecretKey = null;
                this.handleWeakKeyException("refreshTokenSecret");
                throw e;
            }
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
