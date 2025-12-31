package io.github.ohmry.stateless.token.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
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
    private static final Logger logger = LoggerFactory.getLogger(StatelessTokenPolicyConfiguration.class);

    /**
     * Default constructor.
     */
    public StatelessTokenPolicyConfiguration() {}

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
            logger.debug("stateless.accessToken.secret not provided. Using stateless.token.secret as default.");
            accessTokenSecret = tokenSecret;
        }

        if (!StringUtils.hasText(refreshTokenSecret)) {
            logger.debug("stateless.refreshToken.secret not provided. Using stateless.token.secret as default.");
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
        } else {
            logger.debug("stateless.accessToken.timeout not provided. Using stateless.token.timeout as default.");
        }

        if (refreshTokenTimeout != null) {
            builder.refreshTokenTimeout(refreshTokenTimeout);
        } else {
            logger.debug("stateless.refreshToken.timeout not provided. Using stateless.token.timeout as default.");
        }

        logger.info("Initialized StatelessTokenPolicyConfiguration.");
        return builder.build();
    }

    /**
     * Creates a StatelessTokenPolicyHolder bean.
     * This bean maintains a static reference to the StatelessTokenPolicy.
     *
     * @return a StatelessTokenPolicyHolder instance
     */
    @Bean
    @ConditionalOnMissingBean
    public StatelessTokenPolicyHolder statelessTokenPolicyHolder() {
        logger.debug("Creating StatelessTokenPolicyHolder bean.");
        return new StatelessTokenPolicyHolder();
    }

    /**
     * Creates a BeanPostProcessor that injects StatelessTokenPolicy into all beans
     * that implement StatelessTokenPolicyAware.
     *
     * @return a BeanPostProcessor instance
     */
    @Bean
    public BeanPostProcessor statelessTokenPolicyAwareProcessor() {
        return new StatelessTokenPolicyAwareBeanPostProcessor();
    }

    /**
     * BeanPostProcessor implementation that injects StatelessTokenPolicy into beans
     * implementing StatelessTokenPolicyAware.
     */
    private static class StatelessTokenPolicyAwareBeanPostProcessor implements BeanPostProcessor, ApplicationContextAware {
        private ApplicationContext applicationContext;
        private static final Logger logger = LoggerFactory.getLogger(StatelessTokenPolicyAwareBeanPostProcessor.class);

        @Override
        public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
            this.applicationContext = applicationContext;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
            if (bean instanceof StatelessTokenPolicyAware) {
                try {
                    StatelessTokenPolicy policy = applicationContext.getBean(StatelessTokenPolicy.class);
                    ((StatelessTokenPolicyAware) bean).setStatelessTokenPolicy(policy);
                    logger.debug("Injected StatelessTokenPolicy into bean: {}", beanName);
                } catch (BeansException e) {
                    logger.warn("Could not inject StatelessTokenPolicy into bean: {}. StatelessTokenPolicy bean may not be available yet.", beanName);
                }
            }
            return bean;
        }
    }
}
