package com.fatdog.reverse;

/**
 * 应用级装载点（由 FatdogApp 在 Application.onCreate 阶段触发，早于任何 Activity）。
 * 各关 JNI 桥类只声明 native 方法。
 */
final class AppInit {

    static {
        System.loadLibrary("beetle");
        System.loadLibrary("cobalt");
        System.loadLibrary("heron");
        System.loadLibrary("ledger");
        System.loadLibrary("magpie");
        System.loadLibrary("pelican");
        System.loadLibrary("tariff");
        System.loadLibrary("voucher");
        System.loadLibrary("walrus");
        System.loadLibrary("badger");
        System.loadLibrary("cargo");
        System.loadLibrary("dispatch");
        System.loadLibrary("escrow");
        System.loadLibrary("falcon");
        System.loadLibrary("gecko");
        System.loadLibrary("hornet");
        System.loadLibrary("lynx");
        System.loadLibrary("payroll");
        System.loadLibrary("quartz");
        System.loadLibrary("otter");
    }

    /** 触发本类的静态初始化（即上面的装载），方法体本身无副作用。 */
    static void load() {
    }

    private AppInit() {
    }
}
