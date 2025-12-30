package io.github.ohmry.stateless.token.configuration;

public class StatelessTokenPolicyHolder implements StatelessTokenPolicyAware {
    private static StatelessTokenPolicy statelessTokenPolicy;

    @Override
    public void setStatelessTokenPolicy(StatelessTokenPolicy statelessTokenPolicy) {
        StatelessTokenPolicyHolder.statelessTokenPolicy = statelessTokenPolicy;
    }

    public static StatelessTokenPolicy getStatelessTokenPolicy() {
        return StatelessTokenPolicyHolder.statelessTokenPolicy;
    }
}
