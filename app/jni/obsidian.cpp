/* 自动生成：python gen_kkl4.py —— 请勿手改。 */
/* 太玄之初 KKL4 锁妖塔 · 五 so 编队（门面/虚拟机/分组/摘要/守卫）。 */

/*
 * obsidian —— 太玄之初 KKL4 锁妖塔的虚拟机内核。
 *
 * 只做一件事：把**链式（CBC 式）**加密的自定义字节码逐条解密后，用栈式解释器执行，
 * 把结果数据栈回吐给上层。真标记不在本文件、也不在字节码里——程序只含 `GETM idx`，
 * 标记字节由门面在运行时从 .data 的 UTF-16 数组喂入。
 *
 * 指令编码： word = (op << 28) | imm28
 * 链式解码： dec[n] = enc[n] ^ key[n];  key[n+1] = rotl32(key[n], 9) ^ dec[n] ^ 0x7F4A7C15
 *            （逐条依赖前一条，无法一次性整段异或解密）
 * 架构：     数据栈 + 4 通用寄存器（混合栈机）；CALL/RET 用**独立返回栈**
 * 由 tools/gen_kkl4_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define OB_VIS __attribute__((visibility("default")))

enum {
    OB_PUSH = 0x0, OB_GETM = 0x1, OB_POPK = 0x2, OB_PUSHR = 0x3,
    OB_ADD = 0x4, OB_SUB = 0x5, OB_XOR = 0x6, OB_AND = 0x7,
    OB_MULK = 0x8, OB_ROL8 = 0x9, OB_SHL = 0xA, OB_SHR = 0xB,
    OB_CALL = 0xC, OB_RET = 0xD, OB_JZ = 0xE, OB_HALT = 0xF
};

#define OB_DSTACK 192
#define OB_RSTACK 32

static uint32_t ob_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * 解释执行。program 为链式密文（小端 32 位词），chain 为初始链钥（4 字节 LE），
 * in/in_len 为运行时输入缓冲（GETM 从中取字节）。
 * 返回 true 表示正常 HALT；栈内容写入 out（out_len 字节）。
 */
extern "C" OB_VIS bool ob_vm_seed(const uint8_t *program, size_t prog_len,
                                  const uint8_t *chain, size_t chain_len,
                                  const uint8_t *in, size_t in_len,
                                  uint8_t *out, int out_len) {
    if (!program || !out || out_len <= 0) return false;
    if (chain_len < 4) return false;
    size_t n = prog_len / 4;
    if (n == 0) return false;

    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;

    uint32_t k = (uint32_t)chain[0] | ((uint32_t)chain[1] << 8)
               | ((uint32_t)chain[2] << 16) | ((uint32_t)chain[3] << 24);
    for (size_t i = 0; i < n; i++) {
        uint32_t e = (uint32_t)program[i * 4] | ((uint32_t)program[i * 4 + 1] << 8)
                   | ((uint32_t)program[i * 4 + 2] << 16) | ((uint32_t)program[i * 4 + 3] << 24);
        uint32_t d = e ^ k;
        words[i] = d;
        k = ob_rotl32(k, 9) ^ d ^ 0x7F4A7C15u;
    }

    uint32_t regs[4] = {0, 0, 0, 0};
    uint32_t st[OB_DSTACK];
    uint32_t rstack[OB_RSTACK];
    int sp = 0, rp = 0;
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < 200000) {
        uint32_t w = words[pc];
        uint32_t op = (w >> 28) & 0xFu, imm = w & 0x0FFFFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case OB_PUSH:  if (sp < OB_DSTACK) st[sp++] = imm & 0xFFFFFu; break;
        case OB_GETM: {
            uint32_t idx = imm & 0xFFu;
            uint32_t v = (in && idx < in_len) ? in[idx] : 0u;
            if (sp < OB_DSTACK) st[sp++] = v;
            break;
        }
        case OB_POPK:  if (sp > 0) regs[imm & 0xFu] = st[--sp]; break;
        case OB_PUSHR: if (sp < OB_DSTACK) st[sp++] = regs[imm & 0xFu]; break;
        case OB_ADD:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a + b; } break;
        case OB_SUB:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a - b; } break;
        case OB_XOR:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a ^ b; } break;
        case OB_AND:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a & b; } break;
        case OB_MULK:  if (sp >= 1) { st[sp - 1] = st[sp - 1] * imm; } break;
        case OB_ROL8:  if (sp >= 1) {
            uint32_t v = st[sp - 1] & 0xFFu;
            uint32_t r = imm & 7u;
            st[sp - 1] = ((v << r) | (v >> (8 - r))) & 0xFFu;
        } break;
        case OB_SHL:   if (sp >= 1) { st[sp - 1] = st[sp - 1] << (imm & 0x1Fu); } break;
        case OB_SHR:   if (sp >= 1) { st[sp - 1] = st[sp - 1] >> (imm & 0x1Fu); } break;
        case OB_CALL:  if (rp < OB_RSTACK) rstack[rp++] = (uint32_t)(pc + 1);
                       pc = (int)imm; jumped = true; break;
        case OB_RET:   if (rp > 0) { pc = (int)rstack[--rp]; jumped = true; } break;
        case OB_JZ:    if (sp >= 1) { uint32_t v = st[--sp];
                           if (v == 0) { pc = (int)imm; jumped = true; } } break;
        case OB_HALT:  halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    bool ok = halted && sp >= out_len;
    if (ok) for (int i = 0; i < out_len; i++) out[i] = (uint8_t)(st[i] & 0xFFu);
    free(words);
    return ok;
}

/* 诱饵：另一组形状相同、值不同的"主钥"（服务端不认）。 */
extern "C" OB_VIS void ob_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 32; i++) out[i] = (uint8_t)(0x3C ^ (i * 0x17));
}
