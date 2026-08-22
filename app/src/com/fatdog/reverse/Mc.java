package com.fatdog.reverse;

import java.io.InputStream;
import java.security.KeyStore;

// 关卡 26：客户端证书保险库。assets/mt_client.p12 里装着 mTLS 握手要出示的客户端证书+私钥，
// 打开它的密码拆成两半——前半在 Zt（^0x37），后半在本类（^0x5B），运行时才拼出来。
// 代码里搜不到完整密码；jadx 看到的是两段互不相干的神秘数字。
public class Mc {
    static final String P12 = "mt_client.p12";
    static final String ALIAS = "fatdog-client";

    // 密码后半段 "mt26"（^0x5B）
    static final int[] PXB = {54, 47, 105, 109};

    static String decodePXB() {
        byte[] out = new byte[PXB.length];
        for (int i = 0; i < PXB.length; i++) {
            out[i] = (byte) (PXB[i] ^ 0x5B);
        }
        return new String(out);
    }

    static String buildPassword() {
        return Zt.pxa() + decodePXB();
    }

    /** 载入 PKCS12：KeyManagerFactory 用它产出 KeyManager，握手时自动出示客户端证书链。 */
    static KeyStore loadP12(InputStream in) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, buildPassword().toCharArray());
            return ks;
        } finally {
            if (in != null) in.close();
        }
    }
}
