// 验证 app/jni/mt_rng.h 在 C++ 下能否逐位复刻 Python random.Random
#include "../../app/jni/mt_rng.h"
#include <cstdio>

int main() {
    struct { uint32_t seed; uint64_t expect; const char* name; } cases[] = {
        {20271125, 49495, "KL36"},
        {20280615, 49958, "KL37"},
        {20280701, 50778, "KL38"},
        {20280715, 49978, "KL39"},
        {20280720, 52005, "KL40"},
    };
    int fails = 0;
    for (auto& c : cases) {
        uint64_t got = mt_rng::kl_server_sum(c.seed);
        bool ok = (got == c.expect);
        if (!ok) fails++;
        printf("%-5s seed=%-9u  sum=%llu  expected=%llu  %s\n",
               c.name, c.seed, (unsigned long long)got,
               (unsigned long long)c.expect, ok ? "OK" : "FAIL");
    }
    printf("\n%s\n", fails == 0 ? "ALL PASS" : "HAS FAILURES");
    return fails;
}
