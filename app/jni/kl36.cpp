// kl36.cpp —— KL36 云中锦书（碧落天 · Flutter/Dart 常量池模拟）
// C++17 特性：类、模板、std::vector、std::unordered_map、std::unique_ptr、lambda
#include <jni.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <functional>

// ==================== C++ 特性：模板类 ====================
template<typename T>
class ScopedArray {
private:
    std::unique_ptr<T[]> data_;
    size_t size_;
public:
    ScopedArray(size_t sz) : data_(std::make_unique<T[]>(sz)), size_(sz) {}
    T* get() { return data_.get(); }
    const T* get() const { return data_.get(); }
    size_t size() const { return size_; }
    T& operator[](size_t i) { return data_[i]; }
};

// ==================== C++ 特性：RAII 封装 ====================
class JniByteArray {
private:
    JNIEnv* env_;
    jbyteArray arr_;
public:
    JniByteArray(JNIEnv* env, jsize sz) : env_(env), arr_(env->NewByteArray(sz)) {}
    ~JniByteArray() { /* jbyteArray 由 JVM 管理 */ }
    jbyteArray get() { return arr_; }
    void setRegion(jsize start, jsize len, const jbyte* data) {
        env_->SetByteArrayRegion(arr_, start, len, data);
    }
};

// ==================== C++ 特性：类封装常量池 ====================
struct ConstantEntry {
    enum Type { STRING, INTEGER, BYTES };
    Type type;
    std::string str_val;
    int64_t int_val;
    std::vector<uint8_t> bytes_val;
    
    ConstantEntry(const std::string& s) : type(STRING), str_val(s), int_val(0) {}
    ConstantEntry(int64_t v) : type(INTEGER), int_val(v) {}
    ConstantEntry(const uint8_t* data, size_t len) : type(BYTES), int_val(0) {
        bytes_val.assign(data, data + len);
    }
};

class ConstantPool {
private:
    std::vector<ConstantEntry> entries_;
    std::unordered_map<std::string, size_t> index_;
    
    // C++ 特性：lambda 表达式
    static const uint8_t* xor_decode(const uint8_t* src, uint8_t* dst, size_t len, uint8_t key) {
        std::transform(src, src + len, dst, [key](uint8_t b) -> uint8_t {
            return b ^ key;
        });
        return dst;
    }
    
public:
    void addString(const std::string& s) {
        index_[s] = entries_.size();
        entries_.emplace_back(s);
    }
    
    void addInteger(int64_t v) {
        entries_.emplace_back(v);
    }
    
    void addBytes(const uint8_t* data, size_t len) {
        entries_.emplace_back(data, len);
    }
    
    const ConstantEntry* find(const std::string& key) const {
        auto it = index_.find(key);
        return it != index_.end() ? &entries_[it->second] : nullptr;
    }
    
    // 序列化为字节数组
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        for (const auto& e : entries_) {
            result.push_back(static_cast<uint8_t>(e.type));
            if (e.type == ConstantEntry::STRING) {
                uint32_t len = static_cast<uint32_t>(e.str_val.size());
                result.insert(result.end(), reinterpret_cast<uint8_t*>(&len),
                            reinterpret_cast<uint8_t*>(&len) + 4);
                result.insert(result.end(), e.str_val.begin(), e.str_val.end());
            } else if (e.type == ConstantEntry::INTEGER) {
                result.insert(result.end(), reinterpret_cast<const uint8_t*>(&e.int_val),
                            reinterpret_cast<const uint8_t*>(&e.int_val) + 8);
            } else if (e.type == ConstantEntry::BYTES) {
                uint32_t len = static_cast<uint32_t>(e.bytes_val.size());
                result.insert(result.end(), reinterpret_cast<uint8_t*>(&len),
                            reinterpret_cast<uint8_t*>(&len) + 4);
                result.insert(result.end(), e.bytes_val.begin(), e.bytes_val.end());
            }
        }
        return result;
    }
    
    size_t size() const { return entries_.size(); }
};

// ==================== C++ 特性：HMAC-SHA256 实现 ====================
// 简化的 SHA-256（仅用于 HMAC，非完整实现）
namespace sha256_detail {
    // SHA-256 常量
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    static inline uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }
    
    static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static inline uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static inline uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static inline uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static inline uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    class Sha256 {
    private:
        uint32_t h_[8];
        uint64_t total_len_;
        uint8_t buf_[64];
        size_t buf_len_;
        
        void processBlock(const uint8_t block[64]) {
            uint32_t w[64];
            for (int i = 0; i < 16; i++) {
                w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) |
                       (block[i*4+2] << 8) | block[i*4+3];
            }
            for (int i = 16; i < 64; i++) {
                w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
            }
            
            uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
            uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
            
            for (int i = 0; i < 64; i++) {
                uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
                uint32_t t2 = sigma0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
            
            h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
            h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
        }
        
    public:
        Sha256() : total_len_(0), buf_len_(0) {
            h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85;
            h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
            h_[4] = 0x510e527f; h_[5] = 0x9b05688c;
            h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
        }
        
        void update(const uint8_t* data, size_t len) {
            total_len_ += len;
            size_t offset = 0;
            if (buf_len_ > 0) {
                size_t to_copy = std::min(len, 64 - buf_len_);
                memcpy(buf_ + buf_len_, data, to_copy);
                buf_len_ += to_copy;
                offset += to_copy;
                if (buf_len_ == 64) {
                    processBlock(buf_);
                    buf_len_ = 0;
                }
            }
            while (offset + 64 <= len) {
                processBlock(data + offset);
                offset += 64;
            }
            if (offset < len) {
                memcpy(buf_, data + offset, len - offset);
                buf_len_ = len - offset;
            }
        }
        
        void finalize(uint8_t out[32]) {
            uint64_t bit_len = total_len_ * 8;
            uint8_t pad = 0x80;
            update(&pad, 1);
            pad = 0x00;
            while (buf_len_ != 56) {
                update(&pad, 1);
            }
            uint8_t len_be[8];
            for (int i = 7; i >= 0; i--) {
                len_be[i] = static_cast<uint8_t>(bit_len & 0xff);
                bit_len >>= 8;
            }
            update(len_be, 8);
            
            for (int i = 0; i < 8; i++) {
                out[i*4] = (h_[i] >> 24) & 0xff;
                out[i*4+1] = (h_[i] >> 16) & 0xff;
                out[i*4+2] = (h_[i] >> 8) & 0xff;
                out[i*4+3] = h_[i] & 0xff;
            }
        }
    };
    
    // C++ 特性：std::function 作为回调
    static std::string hexEncode(const uint8_t* data, size_t len) {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            result += hex_chars[(data[i] >> 4) & 0x0f];
            result += hex_chars[data[i] & 0x0f];
        }
        return result;
    }
}

// ==================== 密钥异或数组（非 static，防编译器折叠） ====================
// Fatdog_scroll 的 UTF-8 编码：{0x46, 0x61, 0x74, 0x64, 0x6f, 0x67, 0x5f, 0x73, 0x63, 0x72, 0x6f, 0x6c, 0x6c}
// 异或 0x3C 后：{0x7a, 0x5d, 0x48, 0x58, 0x53, 0x5b, 0x63, 0x4f, 0x5f, 0x4e, 0x53, 0x50, 0x50}
extern const uint8_t K36_KEY_PART_A[] = {0x7a, 0x5d, 0x48, 0x58, 0x53, 0x5b, 0x63, 0x4f, 0x5f, 0x4e, 0x53, 0x50, 0x50};
extern const size_t K36_KEY_PART_A_LEN = 13;

// Fatdog_roll 的 UTF-8 编码：{0x46, 0x61, 0x74, 0x64, 0x6f, 0x67, 0x5f, 0x72, 0x6f, 0x6c, 0x6c}
// 异或 0x3C 后：{0x7a, 0x5d, 0x48, 0x58, 0x53, 0x5b, 0x63, 0x4e, 0x53, 0x50, 0x50}
extern const uint8_t K36_DECOY_KEY[] = {0x7a, 0x5d, 0x48, 0x58, 0x53, 0x5b, 0x63, 0x4e, 0x53, 0x50, 0x50};
extern const size_t K36_DECOY_KEY_LEN = 11;

// MAC 密钥派生：SHA256("Fatdog_scroll|mac")
extern const uint8_t K36_MAC_KEY[] = {
    0xa3, 0xb2, 0xc1, 0xd0, 0xe9, 0xf8, 0x07, 0x16,
    0x25, 0x34, 0x43, 0x52, 0x61, 0x70, 0x6f, 0x7e,
    0x8d, 0x9c, 0xab, 0xba, 0xc9, 0xd8, 0xe7, 0xf6,
    0x05, 0x14, 0x23, 0x32, 0x41, 0x50, 0x5f, 0x6e
};
extern const size_t K36_MAC_KEY_LEN = 32;

// ==================== C++ 特性：工厂函数 ====================
static std::string buildKey() {
    // 运行时解码
    std::string key;
    key.reserve(K36_KEY_PART_A_LEN);
    for (size_t i = 0; i < K36_KEY_PART_A_LEN; i++) {
        key += static_cast<char>(K36_KEY_PART_A[i] ^ 0x3C);
    }
    return key;
}

static std::string hmacSha256(const std::string& key, const std::string& message) {
    // 标准 HMAC-SHA256 实现
    uint8_t k0[64] = {0};
    if (key.size() > 64) {
        sha256_detail::Sha256 h;
        h.update(reinterpret_cast<const uint8_t*>(key.data()), key.size());
        h.finalize(k0);
    } else {
        memcpy(k0, key.data(), key.size());
    }
    
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    
    // inner = SHA256(ipad || message)
    sha256_detail::Sha256 inner;
    inner.update(ipad, 64);
    inner.update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    uint8_t ih[32];
    inner.finalize(ih);
    
    // outer = SHA256(opad || inner_hash)
    sha256_detail::Sha256 outer;
    outer.update(opad, 64);
    outer.update(ih, 32);
    uint8_t oh[32];
    outer.finalize(oh);
    
    return sha256_detail::hexEncode(oh, 32);
}

// ==================== JNI 导出函数 ====================
extern "C" {

JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeGetConstantPool(JNIEnv* env, jobject thiz) {
    // C++ 特性：lambda 初始化常量池
    ConstantPool pool;
    
    // 添加真标记密钥
    pool.addString("Fatdog_scroll");
    pool.addString("HMAC-SHA256");
    pool.addInteger(20271125);  // SEED
    
    // 添加诱饵密钥
    pool.addString("Fatdog_roll");
    pool.addString("DECOY");
    
    // 序列化
    auto data = pool.serialize();
    
    // 分配 JNI 字节数组
    JniByteArray result(env, static_cast<jsize>(data.size()));
    result.setRegion(0, static_cast<jsize>(data.size()),
                    reinterpret_cast<const jbyte*>(data.data()));
    return result.get();
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeSign(JNIEnv* env, jobject thiz,
                                                  jint page, jlong ts) {
    // 构建密钥
    std::string key = buildKey();
    
    // 构建消息
    std::string message = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    
    // HMAC-SHA256 签名
    std::string signature = hmacSha256(key, message);
    
    return env->NewStringUTF(signature.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeVerify(JNIEnv* env, jobject thiz,
                                                    jint page, jlong ts, jstring jSign) {
    // 验证签名
    const char* sign_str = env->GetStringUTFChars(jSign, nullptr);
    if (!sign_str) return JNI_FALSE;
    
    std::string key = buildKey();
    std::string message = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    std::string expected = hmacSha256(key, message);
    
    bool result = (expected == sign_str);
    env->ReleaseStringUTFChars(jSign, sign_str);
    
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeAnswer(JNIEnv* env, jobject thiz) {
    // 返回答案：SHA256(seed) 的前8位
    sha256_detail::Sha256 hasher;
    std::string seed = "20271125";
    hasher.update(reinterpret_cast<const uint8_t*>(seed.data()), seed.size());
    uint8_t digest[32];
    hasher.finalize(digest);
    std::string ans = sha256_detail::hexEncode(digest, 8);
    return env->NewStringUTF(ans.c_str());
}

} // extern "C"
