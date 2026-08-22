package com.fatdog.reverse.p;

// 关卡 27 诱饵（藏在被混淆的包里更逼真）：假密钥假 pin，无人调用。
// 别费劲解这里的数组——Gate/Wire 从不引用我，拿去复刻只会签名错误。
public class Gh {
    // ^0x3C：fatdemo_ghost
    static final int[] FAKE_KEY = {90, 93, 72, 88, 89, 81, 83, 99, 91, 84, 83, 79, 72};
    // ^0x27：一串假 SPKI pin
    static final int[] FAKE_PIN = {84, 79, 70, 21, 18, 17, 8, 97, 102, 108, 98, 65, 70, 66, 76, 97, 102, 108, 98, 65, 70, 66, 76, 97, 102, 108, 98, 65, 70, 66, 76, 97, 102, 108, 98, 65, 70, 66, 76, 22, 21, 20, 26};

    static String fakeKey() {
        return Cpt.decodeStr(FAKE_KEY, 0x3C);
    }

    static String fakePin() {
        return Cpt.decodeStr(FAKE_PIN, 0x27);
    }
}
