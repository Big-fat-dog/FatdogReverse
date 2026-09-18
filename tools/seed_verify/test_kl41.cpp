#include <cstdio>
#include "mt_rng.h"
int main(){
    uint64_t s = mt_rng::kl_server_sum(20280801);
    printf("KL41_SUM=%llu\n", (unsigned long long)s);
    return 0;
}
