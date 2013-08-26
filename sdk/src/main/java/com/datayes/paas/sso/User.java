package com.datayes.paas.sso;

/**
 * User: changhai
 * Date: 13-8-26
 * Time: 下午4:54
 * DataYes
 */
public class User {
    private String name;

    public User() {
    }

    public User(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
