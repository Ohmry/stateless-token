package io.github.ohmry.stateless.token;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;
import io.github.ohmry.stateless.token.domain.Token;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

public class TokenTests {
    @Test
    void token_create_and_parse() {
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(300L)
                .build();

        try (MockedStatic<StatelessTokenPolicyHolder> statelessTokenPolicyHolder = mockStatic(StatelessTokenPolicyHolder.class)) {
            statelessTokenPolicyHolder
                    .when(StatelessTokenPolicyHolder::getStatelessTokenPolicy)
                    .thenReturn(statelessTokenPolicy);

            // When - Create
            TestUser user = new TestUser(1, "Administrator");
            Token<TestUser> token = Token.create(user);

            // Then - Create
            assertThat(token).isNotNull();
            assertThat(token.getValue()).isNotNull();
            assertThat(token.getSubject()).isEqualTo(user);
            assertThat(token.isInvalidate()).isFalse();

            // When - Parse
            String tokenValue = token.getValue();
            Token<TestUser> parsedToken = Token.parse(tokenValue, TestUser.class);

            // Then - Parse
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getValue()).isEqualTo(tokenValue);

            TestUser parsedUser = parsedToken.getSubject();
            assertThat(parsedUser.id).isEqualTo(user.id);
            assertThat(parsedUser.name).isEqualTo(user.name);
            assertThat(parsedToken.isInvalidate()).isFalse();
        }
    }

    @Test
    void expired_token() throws InterruptedException {
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(1L)
                .build();

        try (MockedStatic<StatelessTokenPolicyHolder> statelessTokenPolicyHolder = mockStatic(StatelessTokenPolicyHolder.class)) {
            statelessTokenPolicyHolder
                    .when(StatelessTokenPolicyHolder::getStatelessTokenPolicy)
                    .thenReturn(statelessTokenPolicy);

            // When - Create
            TestUser user = new TestUser(1, "Administrator");
            Token<TestUser> token = Token.create(user);

            // Then - Create
            assertThat(token).isNotNull();
            assertThat(token.getValue()).isNotNull();
            assertThat(token.getSubject()).isEqualTo(user);
            assertThat(token.isInvalidate()).isFalse();

            Thread.sleep(1100);

            // When - Parse
            String tokenValue = token.getValue();
            Token<TestUser> parsedToken = Token.parse(tokenValue, TestUser.class);

            // Then - Parse
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getValue()).isEqualTo(tokenValue);
            assertThat(parsedToken.getSubject()).isNull();
            assertThat(parsedToken.isInvalidate()).isTrue();
        }
    }

    @Test
    void token_map_class_subject() {
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(300L)
                .build();

        try (MockedStatic<StatelessTokenPolicyHolder> statelessTokenPolicyHolder = mockStatic(StatelessTokenPolicyHolder.class)) {
            statelessTokenPolicyHolder
                    .when(StatelessTokenPolicyHolder::getStatelessTokenPolicy)
                    .thenReturn(statelessTokenPolicy);

            // When - Create
            Map<String, Object> subject = Map.of(
                    "id", 1,
                    "name", "Administrator"
            );
            Token<Map<String, Object>> token = Token.create(subject);

            // Then - Create
            assertThat(token).isNotNull();
            assertThat(token.getValue()).isNotNull();
            assertThat(token.getSubject()).isEqualTo(subject);
            assertThat(token.isInvalidate()).isFalse();

            // When - Parse
            String tokenValue = token.getValue();
            Token<Map<String, Object>> parsedToken = Token.parse(tokenValue, new TypeReference<>() {});

            // Then - Parse
            assertThat(parsedToken).isNotNull();
            assertThat(parsedToken.getValue()).isEqualTo(tokenValue);

            Map<String, Object> parsedSubject = parsedToken.getSubject();
            assertThat(parsedSubject.get("id")).isEqualTo(subject.get("id"));
            assertThat(parsedSubject.get("name")).isEqualTo(subject.get("name"));
            assertThat(parsedToken.isInvalidate()).isFalse();
        }
    }
}
