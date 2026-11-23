/*
 * kl23_kl24_probe.c — 扶桑树 KL23 / KL24 真机验证探针
 *
 * 直接 #include 关卡源码（app/jni/sun.c、app/jni/ice.c），不复制检测逻辑，
 * 因此探针跑出来的结果就是关卡 so 里的真实行为（零漂移）。
 * 由 tools/verify_kl23_kl24_guard.py 交叉编译、推送、执行并断言。
 *
 * 用法（设备上）：
 *   KL_PROBE_SO=/data/local/tmp/libfrida_probe.so /data/local/tmp/kl_probe
 *   KL_PROBE_SO 指向一个名字/路径含 "frida" 的 .so，用来模拟注入后 maps 里的
 *   r-xp 映射（真实场景是 /memfd:frida-agent-64.so）。
 *   用环境变量而不是命令行参数，避免参数文本污染 KL24 的父进程链检查。
 *
 * 输出统一 KEY=VALUE，供脚本解析。
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "../app/jni/sun.c"
#include "../app/jni/ice.c"

/* KL24 运行期加权评分（在 ptrace 挂住的状态下跑一遍） */
static int ptrace_probe(void) {
    /* fork 会复制父进程未 flush 的 stdio 缓冲，子进程 flush 时会把整份旧输出
     * 再刷一遍 → 先清空，保证每行只出现一次。 */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(3);
        raise(SIGSTOP);
        int score = detect_score();
        printf("KL24_TRACED_TRACERPID=%d\n", sig_tracer_pid());
        printf("KL24_TRACED_SCORE=%d\n", score);
        printf("KL24_TRACED_DETECT=%d\n", detect_frida());
        fflush(stdout);
        _exit(score >= KL24_THRESHOLD ? 0 : 1);
    }
    int ws = 0;
    waitpid(pid, &ws, 0);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &ws, 0);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : -1;
}

int main(void) {
    /* ---- KL23 三路（干净环境）---- */
    printf("KL23_MAPS=%d\n", detect_maps_hex());
    printf("KL23_DT=%d\n", detect_dt_debug());
    printf("KL23_AUXV=%d\n", detect_auxv());
    printf("KL23_COMBINED=%d\n", detect_frida_present());

    /* ---- KL23 模拟注入：dlopen 一个带 frida 名字的 r-xp 映射 ---- */
    const char *dir = getenv("KL_PROBE_DIR");
    if (dir && *dir) {
        char so[256];
        snprintf(so, sizeof(so), "%s/libfrida_probe.so", dir);
        void *h = dlopen(so, RTLD_NOW);
        printf("KL_PROBE_DLOPEN=%d\n", h != NULL);
        printf("KL23_MAPS_INJECTED=%d\n", detect_maps_hex());
        printf("KL23_COMBINED_INJECTED=%d\n", detect_frida_present());
    }

    /* ---- KL24 加载期（.init_array 已在 main 前跑完）---- */
    printf("KL24_PHASE=%d\n", (int)g_load_phase);
    printf("KL24_CLEAN_TRACERPID=%d\n", sig_tracer_pid());
    printf("KL24_CLEAN_SCORE=%d\n", detect_score());
    printf("KL24_CLEAN_DETECT=%d\n", detect_frida());

    /* ---- KL24 被 tracer 挂住时的运行期重算 ---- */
    printf("KL24_TRACED_EXIT=%d\n", ptrace_probe());
    return 0;
}
