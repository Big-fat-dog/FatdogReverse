/*
 * libnative51.so — L51 雷霆山巅（Native大陆第4关）
 *
 * 主入口 + 3DES-EDE-ECB + JNI
 * 密钥从 libnative51h.so 获取
 * 业务代码在 libnative51b.so
 *
 * 协议：GET /api/l51?enc=3DES密文&sig=SM3摘要&ts=T
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
 * 从 libnative51h.so 获取密钥的函数指针
 * ============================================================ */
static const unsigned char* (*getDesKey_fn)() = nullptr;
static const unsigned char* (*getSm3Salt_fn)() = nullptr;
static int (*getSm3SaltLen_fn)() = nullptr;

static void* hHash = nullptr;

static bool loadHashLib() {
    if (hHash) return true;
    hHash = dlopen("libnative51h.so", RTLD_NOW);
    if (!hHash) return false;
    getDesKey_fn = (const unsigned char*(*)())dlsym(hHash, "getDesKey");
    getSm3Salt_fn = (const unsigned char*(*)())dlsym(hHash, "getSm3Salt");
    getSm3SaltLen_fn = (int(*)())dlsym(hHash, "getSm3SaltLen");
    return getDesKey_fn && getSm3Salt_fn && getSm3SaltLen_fn;
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
    1,15,13,8,10,3,7,4,12,5,6,2,0,14,9,11,
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

static uint64_t des_permute(uint64_t input, const uint8_t* table, int n) {
    uint64_t result = 0;
    for (int i = 0; i < n; i++) {
        int bit = (int)((input >> (64 - table[i])) & 1);
        result |= (uint64_t)bit << (n - 1 - i);
    }
    return result;
}

static uint32_t des_f(uint32_t R, const uint8_t key[7]) {
    uint64_t eR = 0;
    for (int i = 0; i < 48; i++) {
        int bit = (R >> (32 - DES_E[i])) & 1;
        eR |= (uint64_t)bit << (47 - i);
    }
    uint8_t k6[6] = {0};
    for (int i = 0; i < 48; i++) {
        int byteIdx = DES_PC2[i] <= 28 ? (DES_PC2[i] - 1) / 7 : (DES_PC2[i] - 29) / 7 + 4;
        int bitIdx = DES_PC2[i] <= 28 ? (DES_PC2[i] - 1) % 7 : (DES_PC2[i] - 29) % 7;
        if ((key[byteIdx] >> (6 - bitIdx)) & 1)
            k6[i / 8] |= (1 << (7 - i % 8));
    }
    uint64_t xored = eR;
    for (int i = 0; i < 6; i++) ((uint8_t*)&xored)[i] ^= k6[i];
    uint32_t result = 0;
    const uint8_t* sboxes[8] = {DES_SBOX1,DES_SBOX2,DES_SBOX3,DES_SBOX4,DES_SBOX5,DES_SBOX6,DES_SBOX7,DES_SBOX8};
    for (int i = 0; i < 8; i++) {
        int b = (xored >> (42 - i * 6)) & 0x3F;
        int row = ((b >> 5) & 1) * 2 + (b & 1);
        int col = (b >> 1) & 0xF;
        uint8_t val = sboxes[i][row * 16 + col];
        result |= (uint32_t)val << (28 - i * 4);
    }
    uint32_t pResult = 0;
    for (int i = 0; i < 32; i++) {
        int bit = (result >> (32 - DES_P[i])) & 1;
        pResult |= (uint32_t)bit << (31 - i);
    }
    return pResult;
}

static void des_key_schedule(const uint8_t key[8], uint8_t subkeys[16][7]) {
    uint64_t pc1 = des_permute(*(uint64_t*)key, DES_PC1, 56);
    uint32_t C = (uint32_t)(pc1 >> 28) & 0x0FFFFFFF;
    uint32_t D = (uint32_t)pc1 & 0x0FFFFFFF;
    for (int i = 0; i < 16; i++) {
        C = ((C << DES_SHIFTS[i]) | (C >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        D = ((D << DES_SHIFTS[i]) | (D >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        uint64_t cd = ((uint64_t)C << 28) | D;
        uint64_t pc2 = des_permute(cd, DES_PC2, 48);
        memset(subkeys[i], 0, 7);
        for (int j = 0; j < 48; j++) {
            int bit = (pc2 >> (47 - j)) & 1;
            subkeys[i][j / 8] |= (uint8_t)(bit << (7 - j % 8));
        }
    }
}

static void des_encrypt_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[8]) {
    uint64_t block = des_permute(*(uint64_t*)in, DES_IP, 64);
    uint32_t L = (uint32_t)(block >> 32);
    uint32_t R = (uint32_t)block;
    uint8_t subkeys[16][7];
    des_key_schedule(key, subkeys);
    for (int i = 0; i < 16; i++) {
        uint32_t f = des_f(R, subkeys[i]);
        uint32_t newR = L ^ f;
        L = R;
        R = newR;
    }
    uint64_t combined = ((uint64_t)R << 32) | L;
    *(uint64_t*)out = des_permute(combined, DES_FP, 64);
}

static void des3_ecb_encrypt(const uint8_t key24[24], const uint8_t* data, size_t len, uint8_t* out) {
    uint8_t k1[8], k2[8], k3[8];
    memcpy(k1, key24, 8);
    memcpy(k2, key24 + 8, 8);
    memcpy(k3, key24 + 16, 8);
    for (size_t i = 0; i < len; i += 8) {
        uint8_t block[8], tmp[8];
        memcpy(block, data + i, 8);
        des_encrypt_block(block, tmp, k1);
        des_encrypt_block(tmp, block, k2);
        des_encrypt_block(block, out + i, k3);
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
 * JNI 入口
 * ============================================================ */

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk51_nativeEnc(JNIEnv* env, jobject, jint page, jlong ts) {
    if (!loadHashLib()) return env->NewStringUTF("");
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    const unsigned char* desKey = getDesKey_fn();
    uint8_t key24[24];
    memcpy(key24, desKey, 24);
    std::string enc = des3_ecb_encrypt_hex(key24, payload);
    return env->NewStringUTF(enc.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk51_nativeSign(JNIEnv* env, jobject, jstring encHex) {
    if (!loadHashLib()) return env->NewStringUTF("");
    const char* hex = env->GetStringUTFChars(encHex, nullptr);
    std::string encStr(hex);
    env->ReleaseStringUTFChars(encHex, hex);
    // sig = SM3(salt + enc)
    const unsigned char* salt = getSm3Salt_fn();
    int saltLen = getSm3SaltLen_fn();
    // 调用 libnative51h 的 sm3Compute
    static const char* (*sm3Compute_fn)(const unsigned char*, int) = nullptr;
    if (!sm3Compute_fn) sm3Compute_fn = (const char*(*)(const unsigned char*, int))dlsym(hHash, "sm3Compute");
    if (!sm3Compute_fn) return env->NewStringUTF("");
    std::string saltStr(reinterpret_cast<const char*>(salt), saltLen);
    std::string toHash = saltStr + encStr;
    const char* sig = sm3Compute_fn((const unsigned char*)toHash.data(), toHash.size());
    return env->NewStringUTF(sig);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk51_getKeyHint(JNIEnv* env, jobject) {
    return env->NewStringUTF("keys_in_native51h");
}

} /* extern "C" */
