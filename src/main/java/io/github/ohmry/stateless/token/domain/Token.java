package io.github.ohmry.stateless.token.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ohmry.stateless.token.config.StatelessTokenPolicy;
import io.github.ohmry.stateless.token.config.StatelessTokenPolicyHolder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;

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
        } catch (JsonProcessingException | ExpiredJwtException e) {
            this.subject = null;
            this.isInvalidate = true;
        }
    }

    public static <T> Token<T> create(T subject, long timeoutSeconds) {
        StatelessTokenPolicy policy = StatelessTokenPolicyHolder.getStatelessTokenPolicy();
        return new Token<>(policy.getRefreshTokenSecretKey(), subject, timeoutSeconds);
    }

    public static <T> Token<T> parse(String tokenValue, Class<T> subjectType) {
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
