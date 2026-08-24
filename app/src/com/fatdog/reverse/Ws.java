package com.fatdog.reverse;

// 天地秘境·流沙河收官卷 JNI 桥：libm5.so 双层叠加签名。
// 第一层 SHA256 变体：K 表/压缩轮全标准，但初始 IV 整组换血、消息填充边界从 56 前移到 48；
// 第二层 AES-128：S 盒全标准，但 MixColumns 系数 {2,3} 对调为 {3,2}。
// 两层骨架都能认出——找改动点才是本题。
public class Ws {
    static {
        System.loadLibrary("m5");
    }

    private Ws() {
    }

    // 第一层：魔改 SHA256("page=N&ts=T")
    public static native String nativeDigest(int page, long ts);

    // 第二层：魔改 AES-128-ECB(aes_key, digest)
    public static native String nativeSign(String digest);
}
