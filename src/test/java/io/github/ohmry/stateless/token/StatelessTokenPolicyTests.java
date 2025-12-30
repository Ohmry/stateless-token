package io.github.ohmry.stateless.token;

import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class StatelessTokenPolicyTests {
    @Test
    void stateless_token_secret_key_is_required() {
        assertThatThrownBy(() -> {
            StatelessTokenPolicy.builder().build();
        })
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("tokenSecretKey must be not null.");
    }

    @Test
    void stateless_token_secret_timeout_is_required() {
        assertThatThrownBy(() -> {
            StatelessTokenPolicy.builder()
                    .tokenSecret("ABCDEFGH".repeat(8))
                    .build();
        })
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("tokenTimeoutSeconds must be not null.");
    }

    @Test
    void stateless_token_policy_default() {
        SecretKey targetSecretKey = Keys.hmacShaKeyFor("ABCDEFGH".repeat(8).getBytes(StandardCharsets.UTF_8));
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(300L)
                .build();

        assertThat(statelessTokenPolicy.getTokenSecretKey()).isEqualTo(targetSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(targetSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(targetSecretKey);

        assertThat(statelessTokenPolicy.getTokenTimeoutSeconds()).isEqualTo(300);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }

    @Test
    void stateless_access_token_default() {
        SecretKey accessTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(300L)
                .accessTokenSecret("12345678".repeat(8))
                .build();

        assertThat(statelessTokenPolicy.getAccessTokenSecretKey()).isEqualTo(accessTokenSecretKey);
        assertThat(statelessTokenPolicy.getAccessTokenTimeoutSeconds()).isEqualTo(60 * 30);
    }

    @Test
    void stateless_refresh_token_default() {
        SecretKey refreshTokenSecretKey = Keys.hmacShaKeyFor("12345678".repeat(8).getBytes(StandardCharsets.UTF_8));
        StatelessTokenPolicy statelessTokenPolicy = StatelessTokenPolicy.builder()
                .tokenSecret("ABCDEFGH".repeat(8))
                .tokenTimeout(300L)
                .refreshTokenSecret("12345678".repeat(8))
                .build();

        assertThat(statelessTokenPolicy.getRefreshTokenSecretKey()).isEqualTo(refreshTokenSecretKey);
        assertThat(statelessTokenPolicy.getRefreshTokenTimeoutSeconds()).isEqualTo(60 * 60 * 12);
    }
}
