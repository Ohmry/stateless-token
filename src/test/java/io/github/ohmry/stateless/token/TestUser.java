package io.github.ohmry.stateless.token;

public class TestUser {
    public Long id;
    public String name;

    public TestUser() {
        this.id = null;
        this.name = null;
    }

    public TestUser(long id, String name) {
        this.id = id;
        this.name = name;
    }
}
