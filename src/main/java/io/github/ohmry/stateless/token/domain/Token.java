package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class for stateless tokens that can contain a subject of any type.
 * This class provides functionality to create and parse JWT tokens with a generic subject type.
 *
 * @param <T> the type of the subject contained in the token
 * @author ohmry
 */
public class Token<T> {
    /**
     * The token string value.
     */
    protected String value;
    
    /**
     * The subject extracted from the token.
     */
    protected T subject;
    
    /**
     * Indicates whether the token is invalid or expired.
     */
    protected boolean isInvalidate;
    
    /**
     * Creates a new token with the specified secret key, subject, and timeout.
     *
     * @param secretKey the secret key used to sign the token
     * @param subject the subject to be encoded in the token
     * @param timeout the token expiration time in seconds (negative value creates an invalid token)
     */
    protected Token(SecretKey secretKey, T subject, long timeout) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            this.value = Jwts.builder()
                             .subject(objectMapper.writeValueAsString(subject))
                             .signWith(secretKey, Jwts.SIG.HS512)
                             .issuedAt(new Date())
                             .expiration(new Date(System.currentTimeMillis() + timeout * 1000))
                             .compact();
            this.isInvalidate = timeout < 0;
            this.subject = timeout < 0 ? null : subject;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
    /**
     * Parses a token string and extracts the subject using the specified class type.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     */
    protected Token(SecretKey secretKey, String tokenValue, Class<T> subjectType) {
        this.value = tokenValue;
        try {
            Jws<Claims> claims = Jwts.parser()
                                     .verifyWith(secretKey)
                                     .build()
                                     .parseSignedClaims(tokenValue);
            String subjectValue = claims.getPayload().getSubject();
            
            ObjectMapper objectMapper = new ObjectMapper();
            this.subject = objectMapper.readValue(subjectValue, subjectType);
            this.isInvalidate = false;
        } catch (JsonProcessingException e) {
            Logger logger = Logger.getLogger(Token.class.getName());
            logger.log(Level.WARNING, "Failed to parse Token", e);
            this.subject = null;
            this.isInvalidate = true;
        } catch (ExpiredJwtException e) {
            this.subject = null;
            this.isInvalidate = true;
        }
    }

    /**
     * Parses a token string and extracts the subject using the specified type reference.
     *
     * @param secretKey the secret key used to verify the token signature
     * @param tokenValue the token string to parse
     * @param typeReference the type reference for the subject type
     */
    protected Token(SecretKey secretKey, String tokenValue, TypeReference<?> typeReference) {
        this.value = tokenValue;
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(tokenValue);
            String subjectValue = claims.getPayload().getSubject();

            ObjectMapper objectMapper = new ObjectMapper();
            JavaType subjectJavaType = objectMapper.getTypeFactory().constructType(typeReference);
            this.subject = objectMapper.readValue(subjectValue, subjectJavaType);
            this.isInvalidate = false;
        } catch (JsonProcessingException e) {
            Logger logger = Logger.getLogger(Token.class.getName());
            logger.log(Level.WARNING, "Failed to parse Token", e);
            this.subject = null;
            this.isInvalidate = true;
        } catch (ExpiredJwtException e) {
            this.subject = null;
            this.isInvalidate = true;
        }
    }

    /**
     * Creates a new token with the default policy settings.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @return a new Token instance
     */
    public static <T> Token<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), subject, policy.getTokenTimeoutSeconds());
    }

    /**
     * Creates a new token with the specified timeout.
     *
     * @param <T> the type of the subject
     * @param subject the subject to be encoded in the token
     * @param timeoutSeconds the token expiration time in seconds
     * @return a new Token instance
     */
    public static <T> Token<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), subject, timeoutSeconds);
    }

    /**
     * Parses a token string and extracts the subject using the specified class type.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the class type of the subject
     * @return a Token instance with the parsed subject, or an invalid token if parsing fails
     */
    public static <T> Token<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), tokenValue, subjectType);
    }

    /**
     * Parses a token string and extracts the subject using the specified type reference.
     *
     * @param <T> the type of the subject
     * @param tokenValue the token string to parse
     * @param subjectType the type reference for the subject type
     * @return a Token instance with the parsed subject, or an invalid token if parsing fails
     */
    public static <T> Token<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), tokenValue, subjectType);
    }

    /**
     * Returns the token string value.
     *
     * @return the token string value
     */
    public String getValue() {
        return value;
    }
    
    /**
     * Returns the subject extracted from the token.
     *
     * @return the subject, or null if the token is invalid or expired
     */
    public T getSubject() {
        return subject;
    }
    
    /**
     * Checks if the token is invalid or expired.
     *
     * @return true if the token is invalid or expired, false otherwise
     */
    public boolean isInvalidate() {
        return isInvalidate;
    }
}
