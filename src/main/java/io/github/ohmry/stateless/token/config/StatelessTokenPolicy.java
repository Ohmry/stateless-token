package io.github.ohmry.stateless.token.config;

import javax.crypto.SecretKey;

public interface StatelessTokenPolicy {
    SecretKey getTokenSecretKey();
    SecretKey getAccessTokenSecretKey();
    SecretKey getRefreshTokenSecretKey();
    long getTokenTimoutSeconds();
    long getAccessTokenTimeoutSeconds();
    long getRefreshTokenTimeoutSeconds();
}
