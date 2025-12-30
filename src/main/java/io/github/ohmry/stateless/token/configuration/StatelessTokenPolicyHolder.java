package io.github.ohmry.stateless.token.configuration;

/**
 * Holder class that maintains a static reference to the StatelessTokenPolicy.
 * This class implements StatelessTokenPolicyAware to allow Spring to inject the policy.
 *
 * @author ohmry
 */
public class StatelessTokenPolicyHolder implements StatelessTokenPolicyAware {
    private static StatelessTokenPolicy statelessTokenPolicy;

    /**
     * Default constructor.
     */
    public StatelessTokenPolicyHolder() {
    }

    /**
     * Sets the StatelessTokenPolicy instance.
     * This method is typically called by Spring when the policy bean is created.
     *
     * @param statelessTokenPolicy the StatelessTokenPolicy instance to set
     */
    @Override
    public void setStatelessTokenPolicy(StatelessTokenPolicy statelessTokenPolicy) {
        StatelessTokenPolicyHolder.statelessTokenPolicy = statelessTokenPolicy;
    }

    /**
     * Returns the current StatelessTokenPolicy instance.
     *
     * @return the StatelessTokenPolicy instance, or null if not set
     */
    public static StatelessTokenPolicy getStatelessTokenPolicy() {
        return StatelessTokenPolicyHolder.statelessTokenPolicy;
    }
}
