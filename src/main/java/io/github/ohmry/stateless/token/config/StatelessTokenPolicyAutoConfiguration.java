package io.github.ohmry.stateless.token.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.List;

@Configuration
public class StatelessTokenPolicyAutoConfiguration {
    @Bean
    public StatelessTokenPolicy statelessTokenPolicy(
        Environment environment,
        ObjectProvider<StatelessTokenPolicyCustomizer> customizers,
        List<StatelessTokenPolicyAware> statelessTokenPolicyAwareList) {
        StatelessTokenPolicyImpl policy = new StatelessTokenPolicyImpl();
        
        // Environment
        String tokenSecret = environment.getProperty("stateless.token.secret");
        if (StringUtils.hasText(tokenSecret)) {
            policy.setTokenSecretKey(tokenSecret);
        }
        
        String accessTokenSecret = environment.getProperty("stateless.token.access.secret");
        if (StringUtils.hasText(accessTokenSecret)) {
            policy.setAccessTokenSecretKey(accessTokenSecret);
        }
        
        String refreshTokenSecret = environment.getProperty("stateless.token.refresh.secret");
        if (StringUtils.hasText(refreshTokenSecret)) {
            policy.setRefreshTokenSecretKey(refreshTokenSecret);
        }

        String tokenTimeout = environment.getProperty("stateless.token.timeout");
        if (StringUtils.hasText(tokenTimeout)) {
            policy.setTokenTimeoutSeconds(Long.parseLong(tokenTimeout));
        }
        
        String accessTokenTimeout = environment.getProperty("stateless.token.access.timeout");
        if (StringUtils.hasText(accessTokenTimeout)) {
            policy.setAccessTokenTimeoutSeconds(Long.parseLong(accessTokenTimeout));
        }
        
        String refreshTokenTimeout = environment.getProperty("stateless.token.refresh.timeout");
        if (StringUtils.hasText(refreshTokenTimeout)) {
            policy.setRefreshTokenTimeoutSeconds(Long.parseLong(refreshTokenTimeout));
        }

        if (!StringUtils.hasText(tokenTimeout) && !StringUtils.hasText(accessTokenTimeout) && !StringUtils.hasText(refreshTokenTimeout)) {
            // Default 5 Minute
            policy.setAccessTokenTimeoutSeconds(60 * 5);
            // Default 12 Hours
            policy.setRefreshTokenTimeoutSeconds(60 * 60 * 12);
        }
        
        customizers.orderedStream().forEach(customizer -> customizer.customize(policy));
        
        statelessTokenPolicyAwareList.forEach(aware -> aware.setStatelessTokenPolicy(policy));
        return policy;
    }
}
