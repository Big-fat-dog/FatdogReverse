package com.fatdog.reverse;

import com.fatdog.reverse.v.Chime;

/**
 * Native大陆 L53 焚天火域：JNI 桥（有状态版 · native 侧 NewObject）。
 *
 * 与 L52 的 Bk52 是两种做法（和 L50/L51 的对照一脉相承）：
 *   L52 —— Java 反射把取件器实例造好，再交给 native 缓存（Java 造对象）；
 *   L53 —— Java 只把 Chime 的 **Class 常量** 递给 native，
 *          native 侧用 NewObject 直接调私有构造函数造实例（native 造对象）。
 *
 * 跨层拼装（签名密钥）：
 *   头段 12B ← libviper.so 的 vp_mark()；尾段 4B ← Chime.chip(int) 回调取 byte[]。
 *
 * 改造后导出表只剩 JNI_OnLoad（RegisterNatives 动态注册），
 * .dynsym 里没有 Java_* 供你对号入座 —— 必须跟 JNI_OnLoad 才看得见绑定关系。
 *
 * 真正干活的方法（全部实例 native，实现在 libtapir.so）：
 *   nativeSign(String)        — HMAC-MD5 签名（返回 hex）
 *   nativeEnc(String, int)    — algo=1 Feistel，algo=2 魔改 AES（返回 hex）
 *   nativeRc4Decrypt(String)  — 响应流解密
 *
 * Flag: FLAG_18_L53{scorched_fireland}
 */
public final class Bk53 {

    /** 实例字段：递给 native 的类常量（R8 改名后 Java 侧仍对得上） */
    private final Class<?> src;

    public Bk53() {
        this.src = Chime.class;   // 编译期类常量 → 抗 R8 改名
        bindKeys(this.src);       // 把 Class 递给 native 缓存
    }

    /* ---- 实例 native：JNI 第二参数已是 jobject（tapir.cpp 已同步改） ---- */

    public native String nativeSign(String data);

    public native String nativeEnc(String data, int algo);

    public native String nativeRc4Decrypt(String hex);

    /** 跨层桥的入口：native 缓存住 Chime 的 jclass、构造与回调 methodID */
    private static native void bindKeys(Class<?> holder);

    /* ---- 以下诱饵 native 保持 static，实现在其它 so，勿动 ---- */
    public static native String nativeGetServiceInfo();

    public static native int nativeBusinessOp(int op, int arg);

    public static native String nativeClear(String a0);  // customs
    public static native String nativeStripe(int a0);  // zebra
    public static native String nativeMunch(String a0);  // panda
    public static native String nativeTail(int a0, long a1);  // lemur
    public static native String nativeCovey(int a0);  // quail
    public static native String nativeWarbler(String a0);  // robin
    public static native String nativeStamp(String a0, int a1);  // seal
    public static native int nativeCredit(int a0, int a1);  // rebate

}
