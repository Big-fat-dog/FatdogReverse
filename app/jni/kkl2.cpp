/*
 * 太玄之初 KKL2：万剑冢——真 DEX 内存加载 + JNI 动态注册（教学版）。
 *
 * 业务 DEX（com.fatdog.reverse.kkl2.GateKeeper2）构建期被加密成
 * assets/kkl2/echoes_of_blades.bin 埋进 APK；本 so 只干两件事：
 *
 *   1) nativeUnseal(enc)   —— 流式 XOR + 镜像交换还原出明文 dex 字节，
 *                            由 Java 侧用 InMemoryDexClassLoader 内存加载
 *                            （不落盘，adb pull / 常规 dump 全部失效）。
 *   2) nativeDeriveKey()   —— 返回 HMAC-SHA256 密钥（32B）。密钥 = SHA-256(
 *                            真标记 Fatdog_tense + "|kkl2_swordfield")，
 *                            真标记以 UTF-16 码元藏在 .data（strings 哑火，
 *                            strings -el 才见）；明文 Fatdog_timid 是诱饵，
 *                            用它派生的密钥解不开密文、验签 403。
 *
 * 解密链故意走 STL（教学点：容器逆向 / lambda 捕获 / std::swap）：
 *   dk = SHA-256(marker|salt) → keystream（32B 循环加性流）→ vector 流式 XOR
 *   → 偶数下标与镜像位交换还原。
 *
 * 玩家需：① 认清 assets 里 classes_decoy.dex 是假壳 → 找到真密文 bin；
 *         ② 还原解密链（或 Frida hook nativeUnseal 出口抓明文 dex）；
 *         ③ dump/加载出 dex → 看到 GateKeeper2.sign(key,page,ts) 取数逻辑；
 *         ④ nativeDeriveKey 拿密钥 → HMAC 取数求和通关。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

/* ================= 真标记（UTF-16 藏匿）/ 诱饵（明文） ================= */
static const jchar MARKER[] = {
    0x0046,
    0x0061,
    0x0074,
    0x0064,
    0x006F,
    0x0067,
    0x005F,
    0x0074,
    0x0065,
    0x006E,
    0x0073,
    0x0065
};
static const char DECOY[] = "Fatdog_timid";     /* 明文诱饵：strings 可见 */

/* ================= salt 两段拼装（std::string 教学点） ================= */
static const char SALT_HEAD[] = "|kkl2_";
static const char SALT_TAIL[] = "swordfield";

/* ================= SHA-256（手写，与 libkkl1.so 同源） ================= */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]) {
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    size_t n = l + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    std::vector<uint8_t> buf(n, 0);
    memcpy(buf.data(), m, l);
    buf[l] = 0x80;
    uint64_t bits = (uint64_t)l * 8;
    for (int i = 0; i < 8; i++) buf[n - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i*4] << 24) | ((uint32_t)buf[off + i*4+1] << 16)
                 | ((uint32_t)buf[off + i*4+2] << 8) |  (uint32_t)buf[off + i*4+3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t t = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];
            w[i] = t;
        }
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K256[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;
    }
    uint32_t hs[8] = {h0,h1,h2,h3,h4,h5,h6,h7};
    for (int i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(hs[i] >> 24);
        o[i*4+1] = (uint8_t)(hs[i] >> 16);
        o[i*4+2] = (uint8_t)(hs[i] >> 8);
        o[i*4+3] = (uint8_t)hs[i];
    }
}

/* ================= 密钥派生：真标记(UTF-16 降 ASCII) + 两段 salt ================= */
static std::vector<uint8_t> derive_key() {
    std::string tag;
    for (size_t i = 0; i < sizeof(MARKER)/sizeof(jchar); i++) {
        tag.push_back((char)(MARKER[i] & 0xFF));      /* ASCII 码元 */
    }
    std::string salt = std::string(SALT_HEAD) + std::string(SALT_TAIL);  /* std::string 拼装 */
    std::string input = tag + salt;
    std::vector<uint8_t> dk(32);
    sha256((const uint8_t*)input.data(), input.size(), dk.data());
    return dk;
}

/* ================= 解密：keystream 流式 XOR + 镜像交换还原 ================= */
static std::vector<uint8_t> unseal_bytes(const uint8_t *in, size_t n) {
    std::vector<uint8_t> dk = derive_key();
    /* 1) 偶数下标与镜像位交换还原（std::swap） */
    std::vector<uint8_t> v(in, in + n);
    for (size_t i = 0; i < n / 2; i++) {
        if ((i & 1) == 0) {
            std::swap(v[i], v[n - 1 - i]);
        }
    }
    /* 2) 加性 keystream：acc = dk[0]^0x5A；acc += dk[i%32] */
    std::vector<uint8_t> ks(n);
    uint8_t acc = (uint8_t)(dk[0] ^ 0x5A);
    for (size_t i = 0; i < n; i++) {
        acc = (uint8_t)(acc + dk[i % 32]);
        ks[i] = acc;
    }
    /* 3) 流式 XOR：std::transform + lambda（捕获索引 idx） */
    size_t idx = 0;
    std::transform(v.begin(), v.end(), v.begin(),
                   [&](uint8_t x) { return (uint8_t)(x ^ ks[idx++]); });
    return v;
}

/* ================= JNI 动态注册（导出表无 Java_ 符号） ================= */
static jbyteArray JNICALL nativeUnseal(JNIEnv *env, jclass, jbyteArray enc) {
    jsize n = env->GetArrayLength(enc);
    std::vector<uint8_t> raw((size_t)n);
    env->GetByteArrayRegion(enc, 0, n, reinterpret_cast<jbyte *>(raw.data()));
    std::vector<uint8_t> plain = unseal_bytes(raw.data(), (size_t)n);
    jbyteArray out = env->NewByteArray((jsize)plain.size());
    if (out) {
        env->SetByteArrayRegion(out, 0, (jsize)plain.size(),
                                reinterpret_cast<const jbyte *>(plain.data()));
    }
    return out;
}

static jbyteArray JNICALL nativeDeriveKey(JNIEnv *env, jclass) {
    std::vector<uint8_t> dk = derive_key();
    jbyteArray out = env->NewByteArray(32);
    if (out) {
        env->SetByteArrayRegion(out, 0, 32, reinterpret_cast<const jbyte *>(dk.data()));
    }
    return out;
}

static const JNINativeMethod METHODS[] = {
    {"nativeUnseal",    "([B)[B", (void *) &nativeUnseal},
    {"nativeDeriveKey", "()[B",   (void *) &nativeDeriveKey},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/fatdog/reverse/Kkl2Native");
    if (cls == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, METHODS, 2) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
