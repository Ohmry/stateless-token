package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for @ConditionalOnMissingBean behavior in StatelessTokenPolicyConfiguration.
 */
class StatelessTokenPolicyConfigurationConditionalTests {

    @Test
    void should_create_bean_when_no_existing_bean() {
        // Given
        ConfigurableEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(
                new org.springframework.core.env.MapPropertySource("test",
                        java.util.Map.of(
                                "stateless.token.secret", "ABCDEFGH".repeat(8),
                                "stateless.token.timeout", "300"
                        )
                )
        );

        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.setEnvironment(environment);
        context.register(StatelessTokenPolicyConfiguration.class);
        context.refresh();

        // When
        StatelessTokenPolicy policy = context.getBean(StatelessTokenPolicy.class);

        // Then
        assertThat(policy).isNotNull();
        assertThat(policy.getTokenTimeoutSeconds()).isEqualTo(300);
        
        context.close();
    }

    @Test
    void should_not_create_auto_configured_bean_when_custom_bean_exists() {
        // Given
        ConfigurableEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(
                new org.springframework.core.env.MapPropertySource("test",
                        java.util.Map.of(
                                "stateless.token.secret", "ABCDEFGH".repeat(8),
                                "stateless.token.timeout", "300"
                        )
                )
        );

        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.setEnvironment(environment);
        context.register(StatelessTokenPolicyConfiguration.class, CustomBeanConfiguration.class);
        context.refresh();

        // When
        StatelessTokenPolicy customPolicy = context.getBean(StatelessTokenPolicy.class);

        // Then - 커스텀 Bean이 사용되어야 함 (자동 설정된 Bean이 아닌)
        assertThat(customPolicy).isNotNull();
        assertThat(customPolicy.getTokenTimeoutSeconds()).isEqualTo(999); // 커스텀 값
        
        context.close();
    }

    @Configuration
    static class CustomBeanConfiguration {
        @Bean
        public StatelessTokenPolicy statelessTokenPolicy() {
            return StatelessTokenPolicy.builder()
                    .tokenSecret("CUSTOMSECRET".repeat(8))
                    .tokenTimeout(999L)
                    .build();
        }
    }
}

