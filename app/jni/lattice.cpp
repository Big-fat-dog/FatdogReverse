/* 自动生成：python gen_kkl3.py —— 请勿手改。 */
/* 太玄之初 KKL3 断魂谷 · 五 so 编队（门面/虚拟机/国密/摘要/守卫）。 */

/*
 * lattice —— 太玄之初 KKL3 断魂谷的虚拟机内核。
 *
 * 只做一件事：把滚动异或加密的自定义字节码解密后，用 switch 解释器逐条执行，
 * 把结果寄存器回吐给上层。真标记不在本文件出现——它只以 VM 立即数的形式
 * 潜伏在（加密的）字节码里。
 *
 * 指令编码： word = (imm16 << 16) | (rd << 12) | (rs << 8) | op
 * 跳转语义： 绝对目标（JMP/JEQ/JNE 的 imm16 即目标下标）
 * 由 tools/gen_kkl3_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LT_VIS __attribute__((visibility("default")))

enum {
    VM_LDI = 0x01, VM_LDIH = 0x02, VM_MOV = 0x03, VM_ADD = 0x04, VM_ADDK = 0x05,
    VM_SUB = 0x06, VM_SUBK = 0x07, VM_EOR = 0x08, VM_EORK = 0x09, VM_AND = 0x0A,
    VM_ANDK = 0x0B, VM_ORR = 0x0C, VM_SHL = 0x0D, VM_SHR = 0x0E, VM_ROR = 0x0F,
    VM_MULK = 0x10, VM_CMP = 0x11, VM_JMP = 0x12, VM_JEQ = 0x13, VM_JNE = 0x14,
    VM_NOP = 0x15, VM_HALT = 0x16
};

/*
 * 解释执行。enc 为滚动异或密文，rolling 为其周期密钥。
 * 返回 true 表示正常 HALT；regs 为 16 个 32 位通用寄存器终值。
 */
extern "C" LT_VIS bool lt_vm_exec(const uint8_t *enc, size_t enc_len,
                                  const uint8_t *rolling, size_t roll_len,
                                  uint32_t regs[16], int *steps_out) {
    if (!enc || !rolling || roll_len == 0) return false;
    size_t n = enc_len / 4;
    if (n == 0) return false;
    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;
    for (size_t i = 0; i < enc_len; i++) {
        uint8_t b = (uint8_t)(enc[i] ^ rolling[i % roll_len]);
        words[i / 4] |= ((uint32_t)b) << ((i % 4) * 8);
    }
    memset(regs, 0, sizeof(uint32_t) * 16);
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < 500000) {
        uint32_t w = words[pc];
        uint32_t op = w & 0xFFu, rs = (w >> 8) & 0xFu, rd = (w >> 12) & 0xFu, imm = (w >> 16) & 0xFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case VM_LDI:  regs[rd] = (regs[rd] & 0xFFFF0000u) | imm; break;
        case VM_LDIH: regs[rd] = (regs[rd] & 0x0000FFFFu) | (imm << 16); break;
        case VM_MOV:  regs[rd] = regs[rs]; break;
        case VM_ADD:  regs[rd] += regs[rs]; break;
        case VM_ADDK: regs[rd] += imm; break;
        case VM_SUB:  regs[rd] -= regs[rs]; break;
        case VM_SUBK: regs[rd] -= imm; break;
        case VM_EOR:  regs[rd] ^= regs[rs]; break;
        case VM_EORK: regs[rd] ^= imm; break;
        case VM_AND:  regs[rd] &= regs[rs]; break;
        case VM_ANDK: regs[rd] &= imm; break;
        case VM_ORR:  regs[rd] |= regs[rs]; break;
        case VM_SHL:  regs[rd] <<= (imm & 0xFF); break;
        case VM_SHR:  regs[rd] >>= (imm & 0xFF); break;
        case VM_ROR: {
            uint32_t r = imm & 7, v = regs[rd] & 0xFF;
            regs[rd] = ((v >> r) | (v << (8 - r))) & 0xFF;
            break;
        }
        case VM_MULK: regs[rd] *= imm; break;
        case VM_CMP:  regs[0] = (regs[rd] == regs[rs]) ? 1u : 0u; break;
        case VM_JMP:  pc = (int)imm; jumped = true; break;
        case VM_JEQ:  if (regs[rd] == 0) { pc = (int)imm; jumped = true; } break;
        case VM_JNE:  if (regs[rd] != 0) { pc = (int)imm; jumped = true; } break;
        case VM_NOP:  break;
        case VM_HALT: halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    free(words);
    if (steps_out) *steps_out = steps;
    return halted;
}

/* 取 base_reg 起 nbytes 字节（小端拼装）作为派生结果。 */
extern "C" LT_VIS bool lt_vm_seed(const uint8_t *enc, size_t enc_len,
                                  const uint8_t *rolling, size_t roll_len,
                                  int base_reg, uint8_t *out, int nbytes) {
    uint32_t regs[16];
    if (!lt_vm_exec(enc, enc_len, rolling, roll_len, regs, 0)) return false;
    if (base_reg < 0 || base_reg * 4 + nbytes > 64) return false;
    for (int i = 0; i < nbytes; i++) {
        uint32_t v = regs[base_reg + (i / 4)];
        out[i] = (uint8_t)(v >> ((i % 4) * 8));
    }
    return true;
}

/* 诱饵：同一 VM 里程程序解出的另一组主钥（服务端不认）。 */
extern "C" LT_VIS void lt_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 16; i++) out[i] = (uint8_t)(0x5A ^ (i * 0x13));
}
