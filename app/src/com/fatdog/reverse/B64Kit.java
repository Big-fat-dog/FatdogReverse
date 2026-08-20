package com.fatdog.reverse;

import android.util.Base64;

// 诱饵工具类：长得很像"Base64 加解密马甲"，但整个类没有任何调用者。
// 关卡 16 真正用的是 RC4（见 Rc4Core/C16），别被名字带偏。
public class B64Kit {
    static String encode(String s) {
        return Base64.encodeToString(s.getBytes(), Base64.NO_WRAP);
    }

    static String decode(String s) {
        return new String(Base64.decode(s, Base64.NO_WRAP));
    }
}
