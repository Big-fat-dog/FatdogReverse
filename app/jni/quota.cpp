/*
 * libquota.so — L51 雷霆山巅（业务代码干扰）
 *
 * 全部是真实的业务函数名，无人调用
 * 被 JNI_OnLoad 通过 dlopen 加载但不调用
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <functional>
#include <ctime>
#include <mutex>
#include <thread>
#include <algorithm>

/* ============================================================
 * ThreadPool — 线程池管理
 * ============================================================ */
class ThreadPool {
    std::vector<std::thread> workers;
    std::vector<std::function<void()>> tasks;
    std::mutex queueMutex;
    bool stop;
public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; i++)
            workers.emplace_back([this] { while (true) { std::function<void()> task; { std::lock_guard<std::mutex> lock(queueMutex); if (stop && tasks.empty()) return; if (!tasks.empty()) { task = tasks.front(); tasks.erase(tasks.begin()); } } if (task) task(); } });
    }
    void submit(std::function<void()> task) { std::lock_guard<std::mutex> lock(queueMutex); tasks.push_back(task); }
    void waitForAll() { for (auto& w : workers) if (w.joinable()) w.join(); }
    int getQueueSize() { std::lock_guard<std::mutex> lock(queueMutex); return (int)tasks.size(); }
    void shutdown() { std::lock_guard<std::mutex> lock(queueMutex); stop = true; }
    ~ThreadPool() { shutdown(); }
};

/* ============================================================
 * EventBus — 事件总线
 * ============================================================ */
class EventBus {
    std::map<std::string, std::vector<std::function<void(const std::string&)>>> listeners;
public:
    void subscribe(const std::string& event, std::function<void(const std::string&)> callback) {
        listeners[event].push_back(callback);
    }
    void unsubscribe(const std::string& event) { listeners.erase(event); }
    void publish(const std::string& event, const std::string& data) {
        auto it = listeners.find(event);
        if (it != listeners.end())
            for (auto& cb : it->second) cb(data);
    }
    int getListenerCount(const std::string& event) {
        auto it = listeners.find(event);
        return it != listeners.end() ? (int)it->second.size() : 0;
    }
    void clear() { listeners.clear(); }
};

/* ============================================================
 * MetricsCollector — 指标采集
 * ============================================================ */
class MetricsCollector {
    std::map<std::string, std::vector<double>> latencyMap;
    std::map<std::string, int> counterMap;
    int flushCount;
public:
    MetricsCollector() : flushCount(0) {}
    void recordLatency(const std::string& name, double ms) { latencyMap[name].push_back(ms); }
    void recordCounter(const std::string& name, int delta = 1) { counterMap[name] += delta; }
    void flush() { latencyMap.clear(); counterMap.clear(); flushCount++; }
    double getAvgLatency(const std::string& name) {
        auto it = latencyMap.find(name);
        if (it == latencyMap.end() || it->second.empty()) return 0;
        double sum = 0;
        for (double v : it->second) sum += v;
        return sum / it->second.size();
    }
    int getCounter(const std::string& name) { return counterMap[name]; }
    int getFlushCount() const { return flushCount; }
};

/* ============================================================
 * CircuitBreaker — 熔断器
 * ============================================================ */
class CircuitBreaker {
    int successCount;
    int failureCount;
    int failureThreshold;
    bool blocked;
    time_t blockedUntil;
public:
    CircuitBreaker(int threshold = 5) : successCount(0), failureCount(0), failureThreshold(threshold), blocked(false), blockedUntil(0) {}
    bool allow() { return !blocked || time(nullptr) >= blockedUntil; }
    bool reject() { return !allow(); }
    void cooldown(int seconds = 30) { blocked = true; blockedUntil = time(nullptr) + seconds; }
    void recordSuccess() { successCount++; failureCount = 0; }
    void recordFailure() { failureCount++; if (failureCount >= failureThreshold) cooldown(); }
    bool isBlocked() const { return blocked; }
    void reset() { successCount = 0; failureCount = 0; blocked = false; }
    int getSuccessCount() const { return successCount; }
    int getFailureCount() const { return failureCount; }
};

/* ============================================================
 * RateLimiter — 限流器
 * ============================================================ */
class RateLimiter {
    std::map<std::string, std::vector<time_t>> history;
    int maxRequests;
    int windowSeconds;
public:
    RateLimiter(int max = 60, int window = 60) : maxRequests(max), windowSeconds(window) {}
    bool allow(const std::string& clientId) {
        time_t now = time(nullptr);
        auto& h = history[clientId];
        h.erase(std::remove_if(h.begin(), h.end(), [now, this](time_t t) { return now - t > windowSeconds; }), h.end());
        if ((int)h.size() >= maxRequests) return false;
        h.push_back(now);
        return true;
    }
    bool reject(const std::string& clientId) { return !allow(clientId); }
    int getRequestCount(const std::string& clientId) { return (int)history[clientId].size(); }
    void reset() { history.clear(); }
    std::map<std::string, int> getAllCounts() {
        std::map<std::string, int> result;
        for (auto& p : history) result[p.first] = (int)p.second.size();
        return result;
    }
};

/* ==================== JNI 绑定（RegisterNatives 动态注册） ==================== */
#include <jni.h>
#include <cstdio>
#include <string>
#include <cstdint>

__attribute__((unused)) static std::string quota_j2s(JNIEnv* env, jstring s) {
    if (s == nullptr) return std::string();
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = (c != nullptr) ? std::string(c) : std::string();
    if (c != nullptr) env->ReleaseStringUTFChars(s, c);
    return out;
}

__attribute__((unused)) static std::string quota_mix(const std::string& in, uint32_t salt, int words) {
    uint32_t a = 0x811C9DC5u ^ salt;
    uint32_t b = a ^ 0x9E3779B9u;
    std::string out;
    char buf[16];
    for (int i = 0; i < words; ++i) {
        b = (b << 5 | b >> 27) ^ (a + (uint32_t)(i * 0x27D4EB2Du));
        a = (a << 13 | a >> 19) + (b ^ 0x165667B1u);
        snprintf(buf, sizeof(buf), "%08x", b);
        out += buf;
    }
    return out;
}

static jstring j_nBucket(JNIEnv* env, jobject, jint a0) {
    std::string in;
    in += std::to_string((long long)a0);
    return env->NewStringUTF(quota_mix(in, 2928178571u, 8).c_str());
}

static const JNINativeMethod gMethods_quota[] = {
    {"nativeBucket", "(I)Ljava/lang/String;", (void*)j_nBucket},
};

static void register_quota_methods(JavaVM* vm) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return;
    jclass cls = env->FindClass("com/fatdog/reverse/Bk51");
    if (cls != nullptr) {
        if (env->RegisterNatives(cls, gMethods_quota, 1) != JNI_OK && env->ExceptionCheck())
            env->ExceptionClear();
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    register_quota_methods(vm);
    return JNI_VERSION_1_6;
}
