package com.fatdog.reverse;

public class SecretVault {
    private static String s_hiddenKey = "Fatdog_xp40_secret";
    private SecretVault() {}

    public static String getKey() { return s_hiddenKey; }
}
