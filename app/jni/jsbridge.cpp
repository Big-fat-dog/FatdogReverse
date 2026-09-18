/**
 * jsbridge.cpp — KL43 桥上听风（须弥界 · JSBridge 协议逆向 + JS 侧消息签名 + 重放）
 *
 * 考点：
 *   1. bridge 消息 = { cmd, page, ts, sign }；**sign 在 JS 侧计算**（密钥在混淆后的前端脚本里，不在本 so）
 *   2. native 侧持有一张 dispatch 表：cmd → handler；`nativeHandle` 按表分发
 *   3. 本 so 的角色是「协议分发器」——篡改了 cmd，本地分发就认不出来
 *
 * 说明：真正要还原的密钥（Fatdog_coral）在 assets/h5/bridge_kl43.html 内被混淆的 JS 里；
 *       本 so 只暴露 dispatch 表与分发逻辑。
 *
 * 宿主自测：g++ -DJSBRIDGE_HOST_TEST 编译后打印表与分发结果。
 */

#include <string>
#include <cstring>
#include <cstdio>

#ifdef JSBRIDGE_HOST_TEST
  #define LOGI(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
#else
  #include <jni.h>
  #include <android/log.h>
  #define LOG_TAG "JSBRIDGE"
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#endif

/* ==================== dispatch 表（cmd → handler） ==================== */
static const char* kDispatchTable = "{\"q\":\"query\",\"v\":\"version\",\"p\":\"ping\"}";

static std::string dispatchName(const std::string& cmd) {
    if (cmd == "q") return "query";
    if (cmd == "v") return "version";
    if (cmd == "p") return "ping";
    return "unknown";
}

/* 从 JSON 消息里取一个简单字符串字段：找到 "key":"..." 的值部分 */
static std::string jstr(const std::string& msg, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = msg.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = msg.find('"', p);
    if (e == std::string::npos) return "";
    return msg.substr(p, e - p);
}

/* ==================== 宿主自测 ==================== */
#ifdef JSBRIDGE_HOST_TEST

int main() {
    printf("dispatch table = %s\n", kDispatchTable);
    const char* probes[] = {"q", "v", "p", "x"};
    for (int i = 0; i < 4; i++) {
        printf("  %s -> %s\n", probes[i], dispatchName(probes[i]).c_str());
    }
    std::string msg = "{\"cmd\":\"q\",\"page\":3,\"ts\":1787013761,\"sign\":\"deadbeef\"}";
    printf("parse cmd from msg = %s -> %s\n",
           jstr(msg, "cmd").c_str(), dispatchName(jstr(msg, "cmd")).c_str());
    return 0;
}

#else

/* ==================== JNI 导出 ==================== */
extern "C" {

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_JsBridge_nativeGetDispatchTable
        (JNIEnv* env, jclass) {
    return env->NewStringUTF(kDispatchTable);
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_JsBridge_nativeHandle
        (JNIEnv* env, jclass, jstring msg) {
    if (msg == nullptr) return env->NewStringUTF("unknown");
    const char* m = env->GetStringUTFChars(msg, nullptr);
    std::string s = m ? m : "";
    env->ReleaseStringUTFChars(msg, m);
    std::string cmd = jstr(s, "cmd");
    std::string handler = cmd.empty() ? "unknown" : dispatchName(cmd);
    LOGI("handle cmd=%s -> %s", cmd.c_str(), handler.c_str());
    return env->NewStringUTF(handler.c_str());
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    LOGI("jsbridge loaded");
    return JNI_VERSION_1_6;
}

} /* extern "C" */
#endif
