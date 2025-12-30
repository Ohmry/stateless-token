package io.github.ohmry.stateless.token.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

@Configuration
public class StatelessTokenPolicyConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public StatelessTokenPolicy statelessTokenPolicy(Environment environment) {
        String tokenSecret = environment.getProperty("stateless.token.secret");
        String accessTokenSecret = environment.getProperty("stateless.accessToken.secret");
        String refreshTokenSecret = environment.getProperty("stateless.refreshToken.secret");
        String tokenTimeoutValue = environment.getProperty("stateless.token.timeout");
        String accessTokenTimeoutValue = environment.getProperty("stateless.accessToken.timeout");
        String refreshTokenTimeoutValue = environment.getProperty("stateless.refreshToken.timeout");
        Long tokenTimeout = null;
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
