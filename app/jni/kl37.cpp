// kl37.cpp —— KL37 风中鸢尾（碧落天 · Dart Kernel 字节码逆向）
// C++17 + 反逆向对抗：ptrace/TracerPid/maps/端口/线程名/CRC 自校验 + 混合 JNI 注册
#include <jni.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <functional>
#include <memory>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

// ==================== 日志 ====================
#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl37"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#define LOGW(...) printf(__VA_ARGS__)
#endif

// ==================== C++ 特性：模板类 ====================
template<typename T, size_t N>
class FixedBuffer {
private:
    std::array<T, N> data_{};
    size_t len_ = 0;
public:
    void append(const T* src, size_t count) {
        size_t to_copy = std::min(count, N - len_);
        std::copy(src, src + to_copy, data_.begin() + len_);
        len_ += to_copy;
    }
    const T* data() const { return data_.data(); }
    T* data() { return data_.data(); }
    size_t size() const { return len_; }
    void clear() { len_ = 0; }
};

// ==================== C++ 特性：RAII JNI 包装 ====================
class JniByteArray {
private:
    JNIEnv* env_;
    jbyteArray arr_;
public:
    JniByteArray(JNIEnv* env, jsize sz) : env_(env), arr_(env->NewByteArray(sz)) {}
    ~JniByteArray() = default;
    jbyteArray get() const { return arr_; }
    void setRegion(jsize start, jsize len, const jbyte* data) {
        env_->SetByteArrayRegion(arr_, start, len, data);
    }
};

// ==================== 字符串异或解码（运行时解码，防 strings 提取） ====================
template<size_t N>
struct XorString {
    uint8_t data[N];
    uint8_t key;

    constexpr XorString(const char (&str)[N], uint8_t k) : key(k) {
        for (size_t i = 0; i < N; i++) {
            data[i] = static_cast<uint8_t>(str[i]) ^ k;
        }
    }

    // C++ 特性：constexpr 构造 + 运行时解码
    std::string decode() const {
        std::string result;
        result.reserve(N - 1);
        for (size_t i = 0; i < N - 1; i++) {
            result += static_cast<char>(data[i] ^ key);
        }
        return result;
    }
};

// 编译期异或加密字符串（IDA 看到的是乱码）
#define XOR_STR(s) ([]() -> std::string { \
    static constexpr XorString<sizeof(s)> xs(s, 0x5A); \
    return xs.decode(); \
}())

// ==================== SHA-256 ====================
namespace sha256_ns {
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
            uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];

            for (int i = 0; i < 64; i++) {
                uint32_t t1 = hh + sigma1(e) + ch(e, f, g) + K[i] + w[i];
                uint32_t t2 = sigma0(a) + maj(a, b, c);
                hh = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }

            h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
            h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
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

    static void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
        Sha256 h;
        h.update(data, len);
        h.finalize(out);
    }

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

// ==================== CRC-32 ====================
static uint32_t crc32_compute(const uint8_t* data, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c ^= data[i];
        for (int j = 0; j < 8; j++)
            c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFu;
}

// ==================== 反逆向：四路哨兵 ====================
namespace anti_reverse {

    // 哨兵 1：ptrace + TracerPid
    static int detect_tracer_pid() {
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return 0;
        char line[256];
        int tid = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tid = atoi(line + 10);
                break;
            }
        }
        fclose(f);
        return tid != 0 ? 1 : 0;
    }

    static int detect_ptrace() {
        long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (r == -1) return 1;  // 已被附加
        ptrace(PTRACE_DETACH, 0, 0, 0);
        return 0;
    }

    // 哨兵 2：/proc/self/maps 扫描 Frida 特征
    static int detect_maps() {
        FILE* f = fopen("/proc/self/maps", "r");
        if (!f) return 0;
        char line[1024];
        int found = 0;
        while (fgets(line, sizeof(line), f) && !found) {
            if (strstr(line, "frida") || strstr(line, "gadget") ||
                strstr(line, "librun") || strstr(line, "gum-js") ||
                strstr(line, "linjector") || strstr(line, "frida-agent")) {
                found = 1;
            }
        }
        fclose(f);
        return found;
    }

    // 哨兵 3：Frida 默认端口探测
    static int detect_port() {
        static const int PORTS[] = {27042, 27043, 27044};
        for (int i = 0; i < 3; i++) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(static_cast<uint16_t>(PORTS[i]));
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            struct timeval tv{0, 300000};  // 300ms 超时
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int r = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
            close(fd);
            if (r == 0) return 1;
        }
        return 0;
    }

    // 哨兵 4：线程名扫描
    static int detect_threads() {
        DIR* d = opendir("/proc/self/task");
        if (!d) return 0;
        struct dirent* de;
        int found = 0;
        while ((de = readdir(d)) != nullptr && !found) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            char path[80];
            snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            char name[96];
            int n = static_cast<int>(read(fd, name, sizeof(name) - 1));
            close(fd);
            if (n <= 0) continue;
            name[n] = '\0';
            while (n > 0 && (name[n-1] == '\n' || name[n-1] == '\r')) name[--n] = '\0';
            if (strstr(name, "gum-js-loop") || strstr(name, "gmain") ||
                strstr(name, "gdbus") || strstr(name, "pool-frida") ||
                strstr(name, "frida")) {
                found = 1;
            }
        }
        closedir(d);
        return found;
    }

    // 哨兵 5：函数头 inline hook 检测
    static int detect_hook(const void* func_ptr) {
        if (!func_ptr) return 0;
        const uint8_t* code = reinterpret_cast<const uint8_t*>(func_ptr);
        // ARM64: 检测是否被 nop 或跳板指令替换
        // 正常函数头: STP X29, X30, [SP, #-0x10]! = 0xA9007BFD
        // inline hook: LDR X16, [PC, #offset] = 0x58000050 后跟 BR X16
        uint32_t insn = 0;
        memcpy(&insn, code, 4);
        // 检测常见的 hook 指令模式
        if ((insn & 0xFFE0001F) == 0xD000001F ||  // ADRP
            (insn & 0xFFE00000) == 0x58000000 ||    // LDR (literal)
            insn == 0xD4200000) {                    // BRK (断点)
            return 1;
        }
        return 0;
    }

    // 综合扫描：返回 bitmask
    static int run_all(const void* fn1, const void* fn2) {
        int tracer = detect_tracer_pid() || detect_ptrace();
        int maps = detect_maps();
        int port = detect_port();
        int thr = detect_threads();
        int hook1 = detect_hook(fn1);
        int hook2 = detect_hook(fn2);
        int bits = (tracer ? 1 : 0) | (maps ? 2 : 0) | (port ? 4 : 0) |
                   (thr ? 8 : 0) | (hook1 ? 16 : 0) | (hook2 ? 32 : 0);
        return bits;
    }
}

// ==================== CRC 自校验 ====================
namespace crc_guard {
    // CRC 基线（编译时计算，运行时比对）
    // 校验范围：从 crc_check 函数到 sign 函数末尾
    static uint32_t g_baseline = 0;
    static bool g_baseline_set = false;

    // CRC 挖洞区间（校验器自身 + 关键函数）
    extern "C" {
        extern void __attribute__((noinline)) crc_zone_start(void) {}
        extern void __attribute__((noinline)) crc_zone_end(void) {}
    }

    static uint32_t calc_text_crc() {
        // 读取 /proc/self/maps 获取 so 的 .text 段地址
        FILE* f = fopen("/proc/self/maps", "r");
        if (!f) return 0;
        char line[1024];
        uintptr_t text_start = 0, text_end = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "libfluttercore.so") && strstr(line, "r-xp")) {
                sscanf(line, "%lx-%lx", &text_start, &text_end);
                break;
            }
        }
        fclose(f);
        if (text_start == 0) return 0;

        // 计算 CRC（排除校验器自身区间）
        uint32_t crc = 0xFFFFFFFFu;
        const uint8_t* base = reinterpret_cast<const uint8_t*>(text_start);
        size_t len = text_end - text_start;
        uintptr_t zone_start = reinterpret_cast<uintptr_t>(crc_zone_start);
        uintptr_t zone_end = reinterpret_cast<uintptr_t>(crc_zone_end);

        for (size_t i = 0; i < len; i++) {
            uintptr_t addr = text_start + i;
            // 跳过校验器自身区间（防止递归 + 允许 hook 校验器）
            if (addr >= zone_start && addr < zone_end) continue;
            crc ^= base[i];
            for (int j = 0; j < 8; j++)
                crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
        }
        return crc ^ 0xFFFFFFFFu;
    }

    static bool verify() {
        if (!g_baseline_set) {
            g_baseline = calc_text_crc();
            g_baseline_set = true;
            return true;  // 首次设置基线
        }
        uint32_t current = calc_text_crc();
        return current == g_baseline;
    }
}

// ==================== 密钥系统 ====================
// 真标记：Fatdog_kite（UTF-16LE 码元，非 static 防折叠）
static const uint16_t MARKER_REAL[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, 0x005F,
    0x006B, 0x0069, 0x0074, 0x0065
};
static const size_t MARKER_LEN = 11;

// 诱饵：Fatdog_sail（明文可见，IDA 一眼能抓）
__attribute__((used)) const char DECOY_MARK[] = "Fatdog_sail";

// 密钥派生盐值
static const char SALT[] = "|hmac";

// 派生状态
static uint8_t g_key[32];
static bool g_ready = false;
static bool g_poisoned = false;
static int g_sentinel_bits = 0;

// 密钥派生函数
static const uint8_t* derive_key() {
    if (!g_ready) {
        // 拼装标记
        std::string tag;
        for (size_t i = 0; i < MARKER_LEN; i++) {
            tag.push_back(static_cast<char>(MARKER_REAL[i] & 0xFF));
        }
        // SHA256(marker + salt)
        std::string input = tag + SALT;
        sha256_ns::hash(reinterpret_cast<const uint8_t*>(input.data()),
                       input.size(), g_key);
        g_ready = true;
    }
    return g_key;
}

// 静默投毒：翻转密钥一字节
static void poison_key() {
    if (g_poisoned) return;
    uint8_t* key = const_cast<uint8_t*>(derive_key());
    key[7] ^= 0x40;  // 翻转第 8 字节第 7 位
    g_poisoned = true;
    LOGW("Key poisoned due to anti-reverse detection");
}

// ==================== HMAC-SHA256 ====================
static std::string hmac_sha256(const uint8_t* key, size_t klen,
                               const uint8_t* msg, size_t mlen) {
    uint8_t k0[64] = {0};
    if (klen > 64) {
        sha256_ns::hash(key, klen, k0);
    } else {
        memcpy(k0, key, klen);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    // inner = SHA256(ipad || message)
    sha256_ns::Sha256 inner;
    inner.update(ipad, 64);
    inner.update(msg, mlen);
    uint8_t ih[32];
    inner.finalize(ih);

    // outer = SHA256(opad || inner_hash)
    sha256_ns::Sha256 outer;
    outer.update(opad, 64);
    outer.update(ih, 32);
    uint8_t oh[32];
    outer.finalize(oh);

    return sha256_ns::hexEncode(oh, 32);
}

// ==================== Dart Kernel 字节码模拟 ====================
namespace dart_kernel {

    struct BytecodeHeader {
        uint8_t magic[4] = {0xD4, 0x72, 0x74, 0x00};  // "Drt\0"
        uint32_t version = 2;
        uint32_t instruction_count = 0;
        uint32_t constant_pool_size = 0;
    };

    class BytecodeBlob {
    private:
        std::vector<uint8_t> raw_data_;
        std::vector<uint8_t> decrypted_;

        static constexpr uint8_t XOR_KEY[] = {0x5A, 0x3C, 0x7E, 0x1D, 0x9B, 0xF0, 0x84, 0x62};

        void decrypt() {
            decrypted_.resize(raw_data_.size());
            for (size_t i = 0; i < raw_data_.size(); i++) {
                decrypted_[i] = raw_data_[i] ^ XOR_KEY[i % 8];
            }
        }

    public:
        BytecodeBlob() {
            BytecodeHeader hdr;
            hdr.instruction_count = 12;
            hdr.constant_pool_size = 3;

            raw_data_.insert(raw_data_.end(), hdr.magic, hdr.magic + 4);
            raw_data_.insert(raw_data_.end(), reinterpret_cast<uint8_t*>(&hdr.version),
                           reinterpret_cast<uint8_t*>(&hdr.version) + 4);
            raw_data_.insert(raw_data_.end(), reinterpret_cast<uint8_t*>(&hdr.instruction_count),
                           reinterpret_cast<uint8_t*>(&hdr.instruction_count) + 4);
            raw_data_.insert(raw_data_.end(), reinterpret_cast<uint8_t*>(&hdr.constant_pool_size),
                           reinterpret_cast<uint8_t*>(&hdr.constant_pool_size) + 4);

            // 模拟 Dart Kernel 指令序列
            const uint8_t instructions[] = {
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // LoadConstant
                0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // LoadConstant
                0x03, 0x02, 0x01, 0x00, 0x01, 0x10, 0x00, 0x00,  // StaticCall
                0x06, 0x03, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,  // BinaryOp
                0x04, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,  // LoadConstant
                0x06, 0x05, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00,  // BinaryOp
                0x03, 0x06, 0x05, 0x00, 0x02, 0x10, 0x00, 0x00,  // StaticCall
                0x06, 0x07, 0x02, 0x00, 0x5C, 0x00, 0x00, 0x00,  // BinaryOp
                0x04, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,  // LoadConstant
                0x06, 0x09, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00,  // BinaryOp
                0x03, 0x0A, 0x09, 0x00, 0x03, 0x10, 0x00, 0x00,  // StaticCall
                0x02, 0x0B, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00,  // ReturnTemporary
            };
            raw_data_.insert(raw_data_.end(), instructions, instructions + sizeof(instructions));

            // 常量池（加密）
            const uint8_t const_pool[] = {
                0x7A, 0x5D, 0x48, 0x58, 0x53, 0x5B, 0x63, 0x4B, 0x5F, 0x46, 0x5D,  // Fatdog_kite XOR
                0x70, 0x61, 0x67, 0x65, 0x3D, 0x25, 0x64, 0x26, 0x74, 0x73, 0x3D, 0x25, 0x6C, 0x6C,
                0x48, 0x4D, 0x41, 0x43, 0x2D, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36
            };
            raw_data_.insert(raw_data_.end(), const_pool, const_pool + sizeof(const_pool));

            decrypt();
        }

        const std::vector<uint8_t>& getRaw() const { return raw_data_; }
        const std::vector<uint8_t>& getDecrypted() const { return decrypted_; }
        size_t size() const { return raw_data_.size(); }
    };
}

// ==================== 守卫检查（每次调用签名前执行） ====================
// 前向声明（用于 inline hook 检测的函数地址获取）
static jstring nativeExecute(JNIEnv* env, jobject thiz, jint page, jlong ts);

static bool guard_check() {
    // 1. CRC 自校验
    if (!crc_guard::verify()) {
        LOGW("CRC check failed - possible patch/hook");
        poison_key();
        return false;
    }

    // 2. 四路哨兵（检测到任一即投毒）
    // 注意：传入自身函数地址用于 inline hook 检测
    int bits = anti_reverse::run_all(
        reinterpret_cast<const void*>(&nativeExecute),
        reinterpret_cast<const void*>(&crc_guard::verify)
    );
    g_sentinel_bits = bits;

    if (bits != 0) {
        LOGW("Sentinel triggered: bits=0x%02x", bits);
        poison_key();
        return false;
    }

    return true;
}

// ==================== JNI 函数（静态命名注册） ====================
// 这些函数使用标准 JNI 命名约定，由 JVM 自动发现

extern "C" {

JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_FlutterCore_nativeGetBytecodeBlob(JNIEnv* env, jobject thiz) {
    dart_kernel::BytecodeBlob blob;
    const auto& raw = blob.getRaw();

    JniByteArray result(env, static_cast<jsize>(raw.size()));
    result.setRegion(0, static_cast<jsize>(raw.size()),
                    reinterpret_cast<const jbyte*>(raw.data()));
    return result.get();
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterCore_nativeGetAlgorithmInfo(JNIEnv* env, jobject thiz) {
    return env->NewStringUTF(XOR_STR("Dart Kernel Bytecode → HMAC-SHA256").c_str());
}

} // extern "C"

// ==================== JNI 函数（动态注册 + 守卫） ====================
// 这些函数在 JNI_OnLoad 中动态注册，每次调用前执行守卫检查

static jstring nativeExecute(JNIEnv* env, jobject thiz, jint page, jlong ts) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }

    // 模拟执行 Dart Kernel 字节码并返回签名
    const uint8_t* key = derive_key();
    char msg[128];
    int len = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, static_cast<long long>(ts));
    std::string signature = hmac_sha256(key, MARKER_LEN,
                                       reinterpret_cast<const uint8_t*>(msg), len);
    return env->NewStringUTF(signature.c_str());
}

static jboolean nativeVerify(JNIEnv* env, jobject thiz, jint page, jlong ts, jstring jSign) {
    if (!guard_check()) return JNI_FALSE;

    const char* sign_str = env->GetStringUTFChars(jSign, nullptr);
    if (!sign_str) return JNI_FALSE;

    const uint8_t* key = derive_key();
    char msg[128];
    int len = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, static_cast<long long>(ts));
    std::string expected = hmac_sha256(key, MARKER_LEN,
                                      reinterpret_cast<const uint8_t*>(msg), len);

    bool result = (expected == sign_str);
    env->ReleaseStringUTFChars(jSign, sign_str);
    return result ? JNI_TRUE : JNI_FALSE;
}

static jstring nativeAnswer(JNIEnv* env, jobject thiz) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }

    // 答案：SHA256(seed) 前 8 位
    uint8_t digest[32];
    std::string seed = "20280615";
    sha256_ns::hash(reinterpret_cast<const uint8_t*>(seed.data()), seed.size(), digest);
    std::string ans = sha256_ns::hexEncode(digest, 8);
    return env->NewStringUTF(ans.c_str());
}

static jstring nativeGetStatus(JNIEnv* env, jobject thiz) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "哨兵自检：\n"
             "  ptrace/TracerPid : %s\n"
             "  maps 加载特征    : %s\n"
             "  27042 端口       : %s\n"
             "  frida 线程名     : %s\n"
             "  inline hook      : %s\n"
             "  CRC 自校验       : %s\n"
             "  密钥状态         : %s\n"
             "  明文可见         : Fatdog_sail（诱饵）",
             (g_sentinel_bits & 1) ? "命中" : "安全",
             (g_sentinel_bits & 2) ? "命中" : "安全",
             (g_sentinel_bits & 4) ? "命中" : "安全",
             (g_sentinel_bits & 8) ? "命中" : "安全",
             (g_sentinel_bits & 16) ? "命中" : "安全",
             crc_guard::verify() ? "通过" : "异常",
             g_poisoned ? "已投毒" : "正常");
    return env->NewStringUTF(buf);
}

// ==================== JNI_OnLoad：动态注册 ====================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // 动态注册 FlutterCore 类的方法
    jclass cls = env->FindClass("com/fatdog/reverse/FlutterCore");
    if (!cls) return JNI_ERR;

    // C++ 特性：lambda 初始化 JNINativeMethod 数组
    static const JNINativeMethod methods[] = {
        {"nativeExecute",    "(IJ)Ljava/lang/String;", reinterpret_cast<void*>(nativeExecute)},
        {"nativeVerify",     "(IJLjava/lang/String;)Z", reinterpret_cast<void*>(nativeVerify)},
        {"nativeAnswer",     "()Ljava/lang/String;",   reinterpret_cast<void*>(nativeAnswer)},
        {"nativeGetStatus",  "()Ljava/lang/String;",   reinterpret_cast<void*>(nativeGetStatus)},
    };

    if (env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: KL37 FlutterCore initialized (static + dynamic registration)");
    return JNI_VERSION_1_6;
}
