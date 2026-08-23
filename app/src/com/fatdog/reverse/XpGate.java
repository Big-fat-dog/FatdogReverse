package com.fatdog.reverse;

// L38 的被 Hook 目标：Xposed 模块把此方法改为返回 true 即通关
public class XpGate {
    private XpGate() {}
    public static boolean check() {
        return false;
    }
}
