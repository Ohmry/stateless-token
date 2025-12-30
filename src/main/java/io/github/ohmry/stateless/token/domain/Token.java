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
import java.lang.reflect.Type;
import java.util.Date;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Token<T> {
    protected String value;
    protected T subject;
    protected boolean isInvalidate;
    
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

    public static <T> Token<T> create(T subject) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), subject, policy.getTokenTimeoutSeconds());
    }

    public static <T> Token<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), subject, timeoutSeconds);
    }

    public static <T> Token<T> parse(String tokenValue, Class<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), tokenValue, subjectType);
    }

    public static <T> Token<T> parse(String tokenValue, TypeReference<T> subjectType) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getTokenSecretKey(), tokenValue, subjectType);
    }

    public String getValue() {
        return value;
    }
    
    public T getSubject() {
        return subject;
    }
    
    public boolean isInvalidate() {
        return isInvalidate;
    }
}
