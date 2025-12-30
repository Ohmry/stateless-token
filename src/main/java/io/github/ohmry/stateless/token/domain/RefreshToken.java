package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;

import javax.crypto.SecretKey;
import java.lang.reflect.Type;

public class RefreshToken<T> extends Token<T> {
    private RefreshToken(SecretKey secretKey, T subject, long timeout) {
        super(secretKey, subject, timeout);
    }

    private RefreshToken(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }

    private RefreshToken(SecretKey secretKey, String tokenValue, TypeReference<T> subjectType) {
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

    public static<T> RefreshToken<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), tokenValue, subjectType);
    }
}