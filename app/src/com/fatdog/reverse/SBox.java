package com.fatdog.reverse;

// Frida 关卡 3 的工具类：密钥不再 static final——构造函数里从异或数组派生。
// Frida 训练点：$init hook（构造函数拦截）。
// 错误打法：直接 Hook decryptVault() 返回值——看不到密钥还原过程。
// 正确打法：Hook $init 拿 this.key，或 Hook 构造函数观察还原后的字节。
public class SBox {
    // 密钥素材：每字节 ^0x3C 还原
    private static final int[] SEED = {82, 89, 83, 82, 99, 91, 89, 73, 85, 81, 99, 14, 12, 14, 10, 59};

    static final byte[] IV = "0001020304050607".getBytes();
    static final String VAULT = "Grg3J5v8Lh0r9KyE0Py0zw==";

    /** 实例字段：只有 new SBox() 之后才能拿到。Frida hook $init 可拦截 this.key。 */
    final byte[] key;

    /** 构造函数：Frida 的 $init hook 就在这里。 */
    SBox() {
        this.key = new byte[SEED.length];
        for (int i = 0; i < SEED.length; i++) {
            this.key[i] = (byte) (SEED[i] ^ 0x3C);
        }
    }

    /** 解密 vault：内部 new SBox() 取密钥。实例方法，调用方需先创建实例。 */
    String decryptVault() throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(this.key, "AES"),
                new javax.crypto.spec.IvParameterSpec(IV));
        byte[] raw = android.util.Base64.decode(VAULT, android.util.Base64.DEFAULT);
        return new String(c.doFinal(raw), "UTF-8");
    }
}