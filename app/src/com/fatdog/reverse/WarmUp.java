package com.fatdog.reverse;

/**
 * 启动预热：大厅进入时调用一次，加载后续关卡需要的原生库。
 * 无状态、无返回值，供 MainActivity 调用。
 */
final class WarmUp {

    static {
        System.loadLibrary("banking");
        System.loadLibrary("dingo");
        System.loadLibrary("eagle");
        System.loadLibrary("finch");
        System.loadLibrary("fund");
        System.loadLibrary("registry");
        System.loadLibrary("retail");
        System.loadLibrary("tender");
        System.loadLibrary("cobra");
        System.loadLibrary("moose");
        System.loadLibrary("customs");
        System.loadLibrary("lemur");
        System.loadLibrary("panda");
        System.loadLibrary("quail");
        System.loadLibrary("rebate");
        System.loadLibrary("robin");
        System.loadLibrary("seal");
        System.loadLibrary("zebra");
        System.loadLibrary("viper");
        System.loadLibrary("tapir");
    }

    static void load() {
    }

    private WarmUp() {
    }
}
