package com.fatdog.reverse;

import java.io.InputStream;
import java.security.KeyStore;

// 看起来很像关卡 26 的证书工具类：假密码、假别名、假校验，名字里全是 mtls 关键词。
// 没有任何真实类调用它——拿这串密码去开 mt_client.p12 只会得到 IOException。
public class MtlsKit {
    static final String FAKE_PASS = "client_secret_26";
    static final String FAKE_ALIAS = "my_client_cert";

    public static KeyStore open(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(in, FAKE_PASS.toCharArray());
        return ks;
    }

    public static boolean verifyAlias(String alias) {
        return FAKE_ALIAS.equals(alias);
    }
}
