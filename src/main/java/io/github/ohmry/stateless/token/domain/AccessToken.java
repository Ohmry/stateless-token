package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;

import javax.crypto.SecretKey;
import java.lang.reflect.Type;

public class AccessToken<T> extends Token<T> {
    public AccessToken(SecretKey secretKey, T subject, long timeout) {
        super(secretKey, subject, timeout);
    }
    
    public AccessToken(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }

    public AccessToken(SecretKey secretKey, String tokenValue, TypeReference<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }
    
    public static <T> AccessToken<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), subject, policy.getAccessTokenTimeoutSeconds());
    }
    
    public static <T> AccessToken<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), subject, timeoutSeconds);
    }
    
    public static<T> AccessToken<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), tokenValue, subjectType);
    }

    public static<T> AccessToken<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), tokenValue, subjectType);
    }
}
