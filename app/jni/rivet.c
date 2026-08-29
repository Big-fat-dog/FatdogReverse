#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================================
 * 昆仑 KL4：冰裂缝 —— 反模拟检测（文件系统哨兵）
 *   读 /proc/self/maps 搜 unidbg/unicorn 特征；
 *   读 /proc/self/status 查 TracerPid；
 *   任一命中 → 返回 ERR_EMULATED（冰面碎裂，无路可走）。
 *   全部通过 → 返回 Fatdog_glacier_unlocked（冰面安全通过）。
 *
 *   unidbg 玩家需用 IOResolver 喂假的 maps 和 status——把特征洗掉。
 * ==========================================================================*/

static int k4_check_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "unidbg") || strstr(line, "unicorn") || strstr(line, "gum-js-loop"))
            { fclose(f); return 1; }     /* 命中模拟器特征 */
    }
    fclose(f);
    return 0;
}

static int k4_detect_tracer(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            fclose(f);
            return atoi(line + 10) != 0 ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku4_nativeProbe(JNIEnv *env, jclass clazz) {
    int maps = k4_check_maps();
    int tracer = k4_detect_tracer();
    if (maps == 1 || tracer == 1)
        return (*env)->NewStringUTF(env, "ERR_EMULATED");
    if (maps == -1 || tracer == -1)
        return (*env)->NewStringUTF(env, "ERR_IO_FAIL");
    /* 环境干净 */
    return (*env)->NewStringUTF(env, "Fatdog_glacier_unlocked");
}
