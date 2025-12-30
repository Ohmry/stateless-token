package io.github.ohmry.stateless.token.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class StatelessTokenPolicyImpl implements StatelessTokenPolicy {
    private SecretKey tokenSecretKey;
    private SecretKey accessTokenSecretKey;
    private SecretKey refreshTokenSecretKey;
    private long tokenTimeoutSeconds;
    private long accessTokenTimeoutSeconds;
    private long refreshTokenTimeoutSeconds;
    
    public StatelessTokenPolicyImpl() {
        this.tokenSecretKey = null;
        this.accessTokenSecretKey = null;
        this.refreshTokenSecretKey = null;
        this.tokenTimeoutSeconds = Long.MIN_VALUE;
        this.accessTokenTimeoutSeconds = Long.MIN_VALUE;
        this.refreshTokenTimeoutSeconds = Long.MIN_VALUE;
    }

    public void setTokenSecretKey(String secret) {
        this.tokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public void setAccessTokenSecretKey(String secret) {
        this.accessTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public void setRefreshTokenSecretKey(String secret) {
        this.refreshTokenSecretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public void setTokenTimeoutSeconds(long tokenTimeoutSeconds) {
        this.tokenTimeoutSeconds = tokenTimeoutSeconds;
    }
    
    public void setAccessTokenTimeoutSeconds(long accessTokenTimeoutSeconds) {
        this.accessTokenTimeoutSeconds = accessTokenTimeoutSeconds;
    }
    
    public void setRefreshTokenTimeoutSeconds(long refreshTokenTimeoutSeconds) {
        this.refreshTokenTimeoutSeconds = refreshTokenTimeoutSeconds;
    }

    @Override
    public SecretKey getTokenSecretKey() {
        return this.tokenSecretKey;
    }

    @Override
    public SecretKey getAccessTokenSecretKey() {
        return this.accessTokenSecretKey != null ? this.accessTokenSecretKey : this.tokenSecretKey;
    }
    
    @Override
    public SecretKey getRefreshTokenSecretKey() {
        return this.refreshTokenSecretKey != null ? this.refreshTokenSecretKey : this.tokenSecretKey;
    }

    @Override
    public long getTokenTimoutSeconds() {
        return this.tokenTimeoutSeconds;
    }

    @Override
    public long getAccessTokenTimeoutSeconds() {
        return this.accessTokenTimeoutSeconds != Long.MIN_VALUE ? this.accessTokenTimeoutSeconds : this.tokenTimeoutSeconds;
    }
    
    @Override
    public long getRefreshTokenTimeoutSeconds() {
        return this.refreshTokenTimeoutSeconds != Long.MIN_VALUE ? this.refreshTokenTimeoutSeconds : this.tokenTimeoutSeconds;
    }
}
