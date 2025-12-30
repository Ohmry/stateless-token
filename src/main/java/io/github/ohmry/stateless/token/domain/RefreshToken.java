package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;

import javax.crypto.SecretKey;

/**
 * Represents a refresh token that extends the base Token class.
 * Refresh tokens are used to obtain new access tokens and typically have a longer expiration time.
 *
 * @param <T> the type of the subject contained in the token
 * @author ohmry
 */
public class RefreshToken<T> extends Token<T> {
    /**
     * Creates a new refresh token with the specified secret key, subject, and timeout.
     *
     * @param secretKey the secret key used to sign the token
     * @param subject the subject to be encoded in the token
     * @param timeout the token expiration time in seconds
     */
    private RefreshToken(SecretKey secretKey, T subject, long timeout) {
        super(secretKey, subject, timeout);
    }

    /**
     * Parses a refresh token string and extracts the subject using the specified class type.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     */
    private RefreshToken(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }

    /**
     * Parses a refresh token string and extracts the subject using the specified type reference.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param subjectType the type reference for the subject type
     */
    private RefreshToken(SecretKey secretKey, String tokenValue, TypeReference<T> subjectType) {
        super(secretKey, tokenValue, subjectType);
    }
    
    /**
     * Creates a new refresh token with the default policy settings.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @return a new RefreshToken instance
     */
    public static <T> RefreshToken<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), subject, policy.getRefreshTokenTimeoutSeconds());
    }
    
    /**
     * Creates a new refresh token with the specified timeout.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @param timeoutSeconds the token expiration time in seconds
     * @return a new RefreshToken instance
     */
    public static <T> RefreshToken<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), subject, timeoutSeconds);
    }

    /**
     * Parses a refresh token string and extracts the subject using the specified class type.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     * @return a RefreshToken instance with the parsed subject, or an invalid token if parsing fails
     */
    public static<T> RefreshToken<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), tokenValue, subjectType);
    }

    /**
     * Parses a refresh token string and extracts the subject using the specified type reference.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the type reference for the subject type
     * @return a RefreshToken instance with the parsed subject, or an invalid token if parsing fails
     */
    public static<T> RefreshToken<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new RefreshToken<>(policy.getRefreshTokenSecretKey(), tokenValue, subjectType);
    }
}