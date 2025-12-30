package io.github.ohmry.stateless.token.config;

@FunctionalInterface
public interface StatelessTokenPolicyCustomizer {
    void customize(StatelessTokenPolicy policy);
}
