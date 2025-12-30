package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;

import javax.crypto.SecretKey;

/**
 * Represents an access token that extends the base Token class.
 * Access tokens are used for authenticating API requests and have a shorter expiration time.
 *
 * @param <T> the type of the subject contained in the token
 * @author ohmry
 */
public class AccessToken<T> extends Token<T> {
    /**
     * Creates a new access token with the specified secret key, subject, and timeout.
     *
     * @param secretKey the secret key used to sign the token
     * @param subject the subject to be encoded in the token
     * @param timeout the token expiration time in seconds
     */
    public AccessToken(SecretKey secretKey, T subject, long timeout) {
        super(secretKey, subject, timeout);
    }
    
    /**
     * Parses an access token string and extracts the subject using the specified class type.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     */
    public AccessToken(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }

    /**
     * Parses an access token string and extracts the subject using the specified type reference.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param subjectType the type reference for the subject type
     */
    public AccessToken(SecretKey secretKey, String tokenValue, TypeReference<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }
    
    /**
     * Creates a new access token with the default policy settings.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @return a new AccessToken instance
     */
    public static <T> AccessToken<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), subject, policy.getAccessTokenTimeoutSeconds());
    }
    
    /**
     * Creates a new access token with the specified timeout.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @param timeoutSeconds the token expiration time in seconds
     * @return a new AccessToken instance
     */
    public static <T> AccessToken<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), subject, timeoutSeconds);
    }
    
    /**
     * Parses an access token string and extracts the subject using the specified class type.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     * @return an AccessToken instance with the parsed subject, or an invalid token if parsing fails
     */
    public static<T> AccessToken<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), tokenValue, subjectType);
    }

    /**
     * Parses an access token string and extracts the subject using the specified type reference.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the type reference for the subject type
     * @return an AccessToken instance with the parsed subject, or an invalid token if parsing fails
     */
    public static<T> AccessToken<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new AccessToken<>(policy.getAccessTokenSecretKey(), tokenValue, subjectType);
    }
}
