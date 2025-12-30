package io.github.ohmry.stateless.token.config;

public class StatelessTokenPolicyHolder implements StatelessTokenPolicyAware{
    private static StatelessTokenPolicy policy;
    
    @Override
    public void setStatelessTokenPolicy(StatelessTokenPolicy statelessTokenPolicy) {
        StatelessTokenPolicyHolder.policy = statelessTokenPolicy;
    }
    
    public static StatelessTokenPolicy getStatelessTokenPolicy() {
        return policy;
    }
}
