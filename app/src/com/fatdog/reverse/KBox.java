package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 4 的工具类之二：令牌的 AES 解密校验在这，密钥和密文也藏在这里。
// 真实写法：密钥通过构造器/配置注入，实例方法做解密，Cipher 实例可复用避免线程不安全。
public class KBox {
    private final byte[] tokenKey;
    private final String tokenEnc;
    private volatile String cachedToken;

    private static volatile KBox INSTANCE;

    private KBox() {
        this.tokenKey = "NEON_TOKEN_KEY16".getBytes();
        this.tokenEnc = "WG2qYEkmVR5yFwooXN1VSw==";
    }

    public static KBox getInstance() {
        if (INSTANCE == null) {
            synchronized (KBox.class) {
                if (INSTANCE == null) INSTANCE = new KBox();
            }
        }
        return INSTANCE;
    }

    /** 供测试/Frida 观察的实例方法：解密并返回明文 token。 */
    public String decryptToken() throws Exception {
        if (cachedToken != null) return cachedToken;
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tokenKey, "AES"));
        byte[] raw = android.util.Base64.decode(tokenEnc, android.util.Base64.DEFAULT);
        String plain = new String(c.doFinal(raw), "UTF-8");
        cachedToken = plain;
        return plain;
    }

    /** 校验输入 token 是否匹配。 */
    public boolean checkToken(String token) {
        try {
            return decryptToken().equals(token);
        } catch (Exception e) {
            return false;
        }
    }
}