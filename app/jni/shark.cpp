/*
 * libshark.so — L51 雷霆山巅（Native大陆第 4 关）
 *
 * 主入口 · 3DES-EDE-ECB · 跨 so（dlopen libturtle）+ 跨层（回调 Java）双拼装
 *
 * 静态分析视角：
 *   - 导出表只有 JNI_OnLoad（动态注册；类名/方法名/签名全是运行时解出的密文）；
 *   - dlopen 的库名、dlsym 的符号名也全是密文 → 看不到 libturtle.so / tt_seed 之类。
 *
 * 跨 so + 跨层密钥拼装：
 *   密钥体      ← libturtle.so 的 tt_seed()（24 字节）
 *   盐 = 头段   ← libturtle.so 的 tt_salt()（12 字节）
 *      + 尾段   ← Java（native 侧 NewObject 造实例 → 回调 tail(int) 取件）
 *   → sig = SM3(盐 + enc)；少任何一段 → 服务端 403。
 *
 * 协议：GET /api/l51?enc=3DES密文&sig=SM3摘要&ts=T（秒 ts）
 * flag：FLAG_18_L51{thunder_peak}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <vector>

/* ============================================================
 * 字符串密文化（掩码走 volatile，防 -O2 常量折叠成明文）
 * ============================================================ */
static std::string decloak(const unsigned char* enc, size_t n, unsigned char mk) {
    std::string out(n, '\0');
    volatile unsigned char m = mk;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ m);
    return out;
}
#define DK(ARR, MK) decloak((ARR), sizeof(ARR), (unsigned char)(MK))

/* 类名 / 方法名 / 签名 / 回调锚点 / 库名 / dlsym 名 —— 构建期 XOR ^0x6D 密文化 */
static const unsigned char B_CLS[] = { 0x0E,0x02,0x00,0x42,0x0B,0x0C,0x19,0x09,0x02,0x0A,0x42,0x1F,0x08,0x1B,0x08,0x1F,0x1E,0x08,0x42,0x2F,0x06,0x58,0x5C };  // com/fatdog/reverse/Bk51
static const unsigned char B_M1[] = { 0x03,0x0C,0x19,0x04,0x1B,0x08,0x28,0x03,0x0E };  // nativeEnc
static const unsigned char B_G1[] = { 0x45,0x24,0x27,0x44,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x3E,0x19,0x1F,0x04,0x03,0x0A,0x56 };  // (IJ)Ljava/lang/String;
static const unsigned char B_M2[] = { 0x03,0x0C,0x19,0x04,0x1B,0x08,0x3E,0x04,0x0A,0x03 };  // nativeSign
static const unsigned char B_G2[] = { 0x45,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x3E,0x19,0x1F,0x04,0x03,0x0A,0x56,0x44,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x3E,0x19,0x1F,0x04,0x03,0x0A,0x56 };  // (Ljava/lang/String;)Ljava/lang/String;
static const unsigned char B_M3[] = { 0x0A,0x08,0x19,0x26,0x08,0x14,0x25,0x04,0x03,0x19 };  // getKeyHint
static const unsigned char B_G3[] = { 0x45,0x44,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x3E,0x19,0x1F,0x04,0x03,0x0A,0x56 };  // ()Ljava/lang/String;
static const unsigned char B_M4[] = { 0x0F,0x04,0x03,0x09,0x26,0x08,0x14,0x1E };  // bindKeys
static const unsigned char B_G4[] = { 0x45,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x2E,0x01,0x0C,0x1E,0x1E,0x56,0x44,0x3B };  // (Ljava/lang/Class;)V
static const unsigned char B_CB[] = { 0x19,0x0C,0x04,0x01 };  // tail
static const unsigned char B_GB[] = { 0x45,0x24,0x44,0x21,0x07,0x0C,0x1B,0x0C,0x42,0x01,0x0C,0x03,0x0A,0x42,0x3E,0x19,0x1F,0x04,0x03,0x0A,0x56 };  // (I)Ljava/lang/String;
static const unsigned char B_LIB[] = { 0x01,0x04,0x0F,0x19,0x18,0x1F,0x19,0x01,0x08,0x43,0x1E,0x02 };  // libturtle.so
static const unsigned char B_LIBQ[] = { 0x01,0x04,0x0F,0x1C,0x18,0x02,0x19,0x0C,0x43,0x1E,0x02 };  // libquota.so
static const unsigned char B_D1[] = { 0x19,0x19,0x32,0x1E,0x08,0x08,0x09 };  // tt_seed
static const unsigned char B_D2[] = { 0x19,0x19,0x32,0x1E,0x0C,0x01,0x19 };  // tt_salt
static const unsigned char B_D3[] = { 0x19,0x19,0x32,0x1E,0x01,0x08,0x03 };  // tt_slen
static const unsigned char B_D4[] = { 0x19,0x19,0x32,0x00,0x0C,0x1F,0x06 };  // tt_mark
static const unsigned char B_HINT[] = { 0x06,0x08,0x14,0x1E,0x32,0x04,0x03,0x32,0x19,0x18,0x1F,0x19,0x01,0x08 };  // keys_in_turtle

/* 诱饵标记（明文可见，strings 可抓） */
static const char FAKE_MARK[] = "Fatdog_bolt";

/* ============================================================
 * 从 libturtle.so 取 密钥体 / 盐头段 / 盐长 / 摘要 的函数指针
 * 库名与符号名都从密文表解出 → 静态看不出依赖关系
 * ============================================================ */
static const unsigned char* (*p_seed)() = nullptr;
static const unsigned char* (*p_salt)() = nullptr;
static int (*p_slen)() = nullptr;
static const char* (*p_mark)(const unsigned char*, int) = nullptr;

static void* h_aux = nullptr;

static bool load_aux() {
    if (h_aux) return true;
    std::string lib = DK(B_LIB, 0x6D);
    h_aux = dlopen(lib.c_str(), RTLD_NOW);
    if (!h_aux) return false;
    std::string d1 = DK(B_D1, 0x6D);
    std::string d2 = DK(B_D2, 0x6D);
    std::string d3 = DK(B_D3, 0x6D);
    std::string d4 = DK(B_D4, 0x6D);
    p_seed = (const unsigned char*(*)())dlsym(h_aux, d1.c_str());
    p_salt = (const unsigned char*(*)())dlsym(h_aux, d2.c_str());
    p_slen = (int(*)())dlsym(h_aux, d3.c_str());
    p_mark = (const char*(*)(const unsigned char*, int))dlsym(h_aux, d4.c_str());
    return p_seed && p_salt && p_slen && p_mark;
}

/* ============================================================
 * 3DES-EDE-ECB — 手写实现
 * ============================================================ */

/* DES S-Boxes */
static const uint8_t DES_SBOX1[64] = {
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
};
static const uint8_t DES_SBOX2[64] = {
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
};
static const uint8_t DES_SBOX3[64] = {
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
};
static const uint8_t DES_SBOX4[64] = {
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
};
static const uint8_t DES_SBOX5[64] = {
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
};
static const uint8_t DES_SBOX6[64] = {
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
};
static const uint8_t DES_SBOX7[64] = {
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
};
static const uint8_t DES_SBOX8[64] = {
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};

static const uint8_t DES_IP[64] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};
static const uint8_t DES_FP[64] = {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};
static const uint8_t DES_E[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
};
static const uint8_t DES_P[32] = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};
static const uint8_t DES_PC1[56] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
};
static const uint8_t DES_PC2[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
};
static const int DES_SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static void des_bits_from_bytes(const uint8_t in[8], uint8_t bits[64]) {
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            bits[i * 8 + j] = (uint8_t)((in[i] >> (7 - j)) & 1);
}

static void des_bits_to_bytes(const uint8_t bits[64], uint8_t out[8]) {
    memset(out, 0, 8);
    for (int i = 0; i < 64; i++)
        if (bits[i]) out[i / 8] |= (uint8_t)(0x80 >> (i & 7));
}

static void des_key_schedule(const uint8_t key[8], uint8_t subkeys[16][48]) {
    uint8_t bits[64], pc1[56], c[28], d[28], cd[56];
    des_bits_from_bytes(key, bits);
    for (int i = 0; i < 56; i++) pc1[i] = bits[DES_PC1[i] - 1];
    memcpy(c, pc1, 28);
    memcpy(d, pc1 + 28, 28);
    for (int r = 0; r < 16; r++) {
        int shift = DES_SHIFTS[r];
        for (int s = 0; s < shift; s++) {
            uint8_t t = c[0];
            for (int i = 0; i < 27; i++) c[i] = c[i + 1];
            c[27] = t;
            t = d[0];
            for (int i = 0; i < 27; i++) d[i] = d[i + 1];
            d[27] = t;
        }
        memcpy(cd, c, 28);
        memcpy(cd + 28, d, 28);
        for (int i = 0; i < 48; i++) subkeys[r][i] = cd[DES_PC2[i] - 1];
    }
}

static void des_f(const uint8_t r[32], const uint8_t subkey[48], uint8_t out[32]) {
    uint8_t e[48], x[48], sb[32];
    const uint8_t* sboxes[8] = {DES_SBOX1,DES_SBOX2,DES_SBOX3,DES_SBOX4,DES_SBOX5,DES_SBOX6,DES_SBOX7,DES_SBOX8};
    for (int i = 0; i < 48; i++) {
        e[i] = r[DES_E[i] - 1];
        x[i] = (uint8_t)(e[i] ^ subkey[i]);
    }
    for (int i = 0; i < 8; i++) {
        int row = x[i * 6] * 2 + x[i * 6 + 5];
        int col = x[i * 6 + 1] * 8 + x[i * 6 + 2] * 4 + x[i * 6 + 3] * 2 + x[i * 6 + 4];
        int val = sboxes[i][row * 16 + col];
        for (int j = 0; j < 4; j++) sb[i * 4 + j] = (uint8_t)((val >> (3 - j)) & 1);
    }
    for (int i = 0; i < 32; i++) out[i] = sb[DES_P[i] - 1];
}

static void des_crypt_block(const uint8_t in[8], uint8_t out[8], uint8_t subkeys[16][48]) {
    uint8_t bits[64], state[64], l[32], r[32], nr[32], fout[32];
    des_bits_from_bytes(in, bits);
    for (int i = 0; i < 64; i++) state[i] = bits[DES_IP[i] - 1];
    memcpy(l, state, 32);
    memcpy(r, state + 32, 32);
    for (int round = 0; round < 16; round++) {
        des_f(r, subkeys[round], fout);
        for (int i = 0; i < 32; i++) nr[i] = (uint8_t)(l[i] ^ fout[i]);
        memcpy(l, r, 32);
        memcpy(r, nr, 32);
    }
    memcpy(state, r, 32);
    memcpy(state + 32, l, 32);
    for (int i = 0; i < 64; i++) bits[i] = state[DES_FP[i] - 1];
    des_bits_to_bytes(bits, out);
}

static void des3_ecb_encrypt(const uint8_t key24[24], const uint8_t* data, size_t len, uint8_t* out) {
    uint8_t k1[16][48], k2[16][48], k3[16][48], rev[16][48];
    des_key_schedule(key24, k1);
    des_key_schedule(key24 + 8, k2);
    des_key_schedule(key24 + 16, k3);
    for (size_t i = 0; i < len; i += 8) {
        uint8_t block[8], tmp[8];
        des_crypt_block(data + i, tmp, k1);
        for (int r = 0; r < 16; r++)
            for (int j = 0; j < 48; j++) rev[r][j] = k2[15 - r][j];
        des_crypt_block(tmp, block, rev);
        des_crypt_block(block, out + i, k3);
    }
}


static std::string des3_ecb_encrypt_hex(const uint8_t key24[24], const std::string& data) {
    size_t padLen = 8 - (data.size() % 8);
    std::string padded = data + std::string(padLen, (char)padLen);
    std::vector<uint8_t> out(padded.size());
    des3_ecb_encrypt(key24, (const uint8_t*)padded.data(), padded.size(), out.data());
    std::string hex;
    hex.reserve(out.size() * 2);
    for (uint8_t b : out) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", b); hex += buf; }
    return hex;
}

/* ============================================================
 * 跨层回调：盐尾段由 Java 侧供给
 *   Java 递进 Spool 的 Class → 本 so NewObject 直接调私有构造造实例
 *   → 按方法名回调 tail(int mask) 取尾段；盐在 Java、掩码在 so
 * ============================================================ */
static JavaVM* g_vm = NULL;
static jclass g_cls = NULL;
static jmethodID g_ctor = NULL;
static jmethodID g_tail = NULL;

/* Java 构造用盐 + so 侧回调掩码 */
static const jint SALT_SPOOL = 0x3A5C;
static const jint MASK_TAIL  = 0x71E9B4D5;

static JNIEnv* cur_env() {
    if (g_vm == NULL) return NULL;
    JNIEnv* env = NULL;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return NULL;
    return env;
}

/* native 侧自己造 Java 对象（JNI 不看访问修饰符 → 可直接调私有构造） */
static std::string fetch_tail(JNIEnv* env) {
    if (env == NULL) env = cur_env();
    if (env == NULL || g_cls == NULL || g_ctor == NULL || g_tail == NULL) return std::string();
    jobject obj = env->NewObject(g_cls, g_ctor, SALT_SPOOL);
    if (obj == NULL) return std::string();
    jstring js = (jstring) env->CallObjectMethod(obj, g_tail, MASK_TAIL);
    env->DeleteLocalRef(obj);
    if (js == NULL) return std::string();
    const char* cs = env->GetStringUTFChars(js, NULL);
    std::string out;
    if (cs != NULL) { out.assign(cs); env->ReleaseStringUTFChars(js, cs); }
    env->DeleteLocalRef(js);
    if (out == "ERR_JAVA") out.clear();
    return out;
}

/* 拼齐 17 字节盐：so 头段(12) + Java 尾段(5) */
static std::string full_salt(JNIEnv* env) {
    if (!load_aux()) return std::string();
    std::string head(reinterpret_cast<const char*>(p_salt()), p_slen());
    std::string tail = fetch_tail(env);
    if (tail.empty()) return std::string();
    return head + tail;
}

/* ============================================================
 * JNI 实现（静态命名一律取消；由 JNI_OnLoad 动态注册）
 * ============================================================ */
static jstring implEnc(JNIEnv* env, jobject, jint page, jlong ts) {
    if (!load_aux()) return env->NewStringUTF("");
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    uint8_t key24[24];
    memcpy(key24, p_seed(), 24);
    std::string enc = des3_ecb_encrypt_hex(key24, payload);
    return env->NewStringUTF(enc.c_str());
}

static jstring implSign(JNIEnv* env, jobject, jstring encHex) {
    if (!load_aux()) return env->NewStringUTF("");
    const char* hex = env->GetStringUTFChars(encHex, nullptr);
    std::string encStr = (hex != nullptr) ? std::string(hex) : std::string();
    if (hex != nullptr) env->ReleaseStringUTFChars(encHex, hex);
    /* sig = SM3(盐 + enc)，盐的头段在 libturtle、尾段在 Java */
    std::string salt = full_salt(env);
    if (salt.empty()) return env->NewStringUTF("");
    std::string toHash = salt + encStr;
    const char* sig = p_mark(reinterpret_cast<const unsigned char*>(toHash.data()), (int) toHash.size());
    return env->NewStringUTF(sig != nullptr ? sig : "");
}

static jstring implHint(JNIEnv* env, jobject) {
    return env->NewStringUTF(DK(B_HINT, 0x6D).c_str());
}

static void implBind(JNIEnv* env, jclass, jclass holder) {
    if (g_cls != NULL) { env->DeleteGlobalRef(g_cls); g_cls = NULL; }
    g_ctor = g_tail = NULL;
    if (holder == NULL) return;
    g_cls = (jclass) env->NewGlobalRef(holder);
    if (g_cls == NULL) return;
    std::string ct = DK(B_CB, 0x6D);
    std::string gb = DK(B_GB, 0x6D);
    g_ctor = env->GetMethodID(g_cls, "<init>", "(I)V");
    g_tail = env->GetMethodID(g_cls, ct.c_str(), gb.c_str());
}

/* 诱饵导出：Java 侧根本没声明这个方法 —— 纯误导 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk51_nativeShark(JNIEnv* env, jclass) {
    return env->NewStringUTF(FAKE_MARK);
}

/* ============================================================
 * JNI_OnLoad — 运行时构造 JNINativeMethod 表并 RegisterNatives
 * ============================================================ */
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    JNIEnv* env = cur_env();
    if (env != NULL) {
        std::string cls = DK(B_CLS, 0x6D);
        jclass c = env->FindClass(cls.c_str());
        if (c != NULL) {
            std::string n1 = DK(B_M1, 0x6D), g1 = DK(B_G1, 0x6D);
            std::string n2 = DK(B_M2, 0x6D), g2 = DK(B_G2, 0x6D);
            std::string n3 = DK(B_M3, 0x6D), g3 = DK(B_G3, 0x6D);
            std::string n4 = DK(B_M4, 0x6D), g4 = DK(B_G4, 0x6D);
            JNINativeMethod m[4];
            m[0].name = const_cast<char*>(n1.c_str()); m[0].signature = const_cast<char*>(g1.c_str()); m[0].fnPtr = (void*)implEnc;
            m[1].name = const_cast<char*>(n2.c_str()); m[1].signature = const_cast<char*>(g2.c_str()); m[1].fnPtr = (void*)implSign;
            m[2].name = const_cast<char*>(n3.c_str()); m[2].signature = const_cast<char*>(g3.c_str()); m[2].fnPtr = (void*)implHint;
            m[3].name = const_cast<char*>(n4.c_str()); m[3].signature = const_cast<char*>(g4.c_str()); m[3].fnPtr = (void*)implBind;
            if (env->RegisterNatives(c, m, 4) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    /* 干扰 so：仅 dlopen 进进程（出现于 /proc/self/maps、可被 dlopen-trace 捕获），
     * 不 dlsym、不调用其中任何符号（纯诱饵，不影响通关逻辑） */
    std::string q = DK(B_LIBQ, 0x6D);
    (void)dlopen(q.c_str(), RTLD_NOW);
    return JNI_VERSION_1_6;
}
