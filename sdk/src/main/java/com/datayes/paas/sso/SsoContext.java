package com.datayes.paas.sso;

/**
 * User: changhai
 * Date: 13-8-22
 * Time: 下午3:55
 * DataYes
 */
public class SsoContext {
    private static final ThreadLocal<User> userHolder = new ThreadLocal<User>();

    public static User getUser() {
        return userHolder.get();
    }

    public static void setUser(User user) {
        userHolder.set(user);
    }
    public static void removeUser() {
        userHolder.remove();
    }
}
