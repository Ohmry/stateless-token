package io.github.ohmry.stateless.token.domain;

import io.github.ohmry.stateless.token.config.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.config.StatelessTokenPolicyHolder;

import javax.crypto.SecretKey;

public class RefreshToken<T> extends Token<T> {
    private RefreshToken(SecretKey secretKey, T subject, long timeout) {
        super(secretKey, subject, timeout);
    }

    private RefreshToken(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }
    
    public static <T> RefreshToken<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), subject, policy.getRefreshTokenTimeoutSeconds());
    }
    
    public static <T> RefreshToken<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), subject, timeoutSeconds);
    }

    public static<T> RefreshToken<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), tokenValue, subjectType);
    }
}