package io.github.ohmry.stateless.token.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * Spring Boot auto-configuration for StatelessTokenPolicy.
 * This configuration reads token policy settings from application properties and creates
 * a StatelessTokenPolicy bean if one is not already defined.
 *
 * @author ohmry
 */
@Configuration
public class StatelessTokenPolicyConfiguration {
    /**
     * Default constructor.
     */
    public StatelessTokenPolicyConfiguration() {
    }

    /**
     * Creates a StatelessTokenPolicy bean from application properties.
     * Required properties:
     * <ul>
     *   <li>stateless.token.secret - Secret key for general tokens</li>
     *   <li>stateless.token.timeout - Timeout in seconds for general tokens</li>
     * </ul>
     * Optional properties:
     * <ul>
     *   <li>stateless.accessToken.secret - Secret key for access tokens (defaults to token.secret)</li>
     *   <li>stateless.accessToken.timeout - Timeout in seconds for access tokens (defaults to 30 minutes)</li>
     *   <li>stateless.refreshToken.secret - Secret key for refresh tokens (defaults to token.secret)</li>
     *   <li>stateless.refreshToken.timeout - Timeout in seconds for refresh tokens (defaults to 12 hours)</li>
     * </ul>
     *
     * @param environment the Spring environment containing application properties
     * @return a configured StatelessTokenPolicy instance
     * @throws IllegalArgumentException if required properties are missing
     */
    @Bean
    @ConditionalOnMissingBean
    public StatelessTokenPolicy statelessTokenPolicy(Environment environment) {
        String tokenSecret = environment.getProperty("stateless.token.secret");
        String accessTokenSecret = environment.getProperty("stateless.accessToken.secret");
        String refreshTokenSecret = environment.getProperty("stateless.refreshToken.secret");
        String tokenTimeoutValue = environment.getProperty("stateless.token.timeout");
        String accessTokenTimeoutValue = environment.getProperty("stateless.accessToken.timeout");
        String refreshTokenTimeoutValue = environment.getProperty("stateless.refreshToken.timeout");
        long tokenTimeout;
        Long accessTokenTimeout = null;
        Long refreshTokenTimeout = null;

        if (!StringUtils.hasText(tokenSecret)) {
            throw new IllegalArgumentException("stateless.token.secret is required.");
        }

        if (!StringUtils.hasText(tokenTimeoutValue)) {
            throw new IllegalArgumentException("stateless.token.timeout is required.");
        } else {
            tokenTimeout = Long.parseLong(tokenTimeoutValue);
        }

        if (!StringUtils.hasText(accessTokenSecret)) {
            accessTokenSecret = tokenSecret;
        }

        if (!StringUtils.hasText(refreshTokenSecret)) {
            refreshTokenSecret = tokenSecret;
        }

        if (StringUtils.hasText(accessTokenTimeoutValue)) {
            accessTokenTimeout = Long.parseLong(accessTokenTimeoutValue);
        }

        if (StringUtils.hasText(refreshTokenTimeoutValue)) {
            refreshTokenTimeout = Long.parseLong(refreshTokenTimeoutValue);
        }

        StatelessTokenPolicy.StatelessTokenPolicyBuilder builder = StatelessTokenPolicy.builder();
        builder.tokenSecret(tokenSecret)
                .accessTokenSecret(accessTokenSecret)
                .refreshTokenSecret(refreshTokenSecret)
                .tokenTimeout(tokenTimeout);

        if (accessTokenTimeout != null) {
            builder.accessTokenTimeout(accessTokenTimeout);
        }

        if (refreshTokenTimeout != null) {
            builder.refreshTokenTimeout(refreshTokenTimeout);
        }

        return builder.build();
    }
}
