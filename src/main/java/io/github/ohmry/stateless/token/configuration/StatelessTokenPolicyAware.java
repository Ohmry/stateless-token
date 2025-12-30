package io.github.ohmry.stateless.token.configuration;

/**
 * Interface for classes that need to be aware of the StatelessTokenPolicy.
 * Implementing classes can receive the policy instance through dependency injection.
 *
 * @author ohmry
 */
public interface StatelessTokenPolicyAware {
    /**
     * Sets the StatelessTokenPolicy instance.
     *
     * @param statelessTokenPolicy the StatelessTokenPolicy instance to set
     */
    void setStatelessTokenPolicy(StatelessTokenPolicy statelessTokenPolicy);
}
