/* 自动生成：python gen_kkl5.py —— 请勿手改。 */
/* 太玄之初 KKL5 诛仙台 · 五 so 编队（门面/虚拟机/复合分组/摘要/守卫）。 */

/*
 * vellum —— 太玄之初 KKL5 诛仙台的内存机内核。
 *
 * 只做一件事：把**差分反馈链**加密的自定义字节码逐条解密后，用内存机解释器执行，
 * 把结果内存单元回吐给上层。真标记不在本文件、也不在字节码里——程序只含 `GETM idx`，
 * 标记字节由门面在运行时从 .data 的 UTF-16 数组喂入。
 *
 * 指令编码： word = (op << 24) | (d << 20) | (s << 16) | imm16
 * 差分链：   dec[n] = enc[n] ^ key[n % L] ^ enc[n-1]；enc[-1] = IV
 *            （密文自反馈：每一条解密都依赖上一条密文，无法整段独立解）
 * 架构：     16 个内存单元 M[0..15] + 一个累加器 acc；输出单元 M8..M15 小端拼 32 字节。
 * 由 tools/gen_kkl5_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VL_VIS __attribute__((visibility("default")))

enum {
    VL_SET  = 0x01, VL_SETH = 0x02, VL_CPY  = 0x03, VL_GETA = 0x04,
    VL_PUTA = 0x05, VL_GETM = 0x06, VL_ADDI = 0x07, VL_MULK = 0x08,
    VL_XORR = 0x09, VL_ANDR = 0x0A, VL_ORR  = 0x0B, VL_ADDR = 0x0C,
    VL_SUBR = 0x0D, VL_SHL  = 0x0E, VL_SHR  = 0x0F, VL_ROL8 = 0x10,
    VL_ROR8 = 0x11, VL_XORI = 0x12, VL_ANDI = 0x13, VL_JMP  = 0x14,
    VL_JZ   = 0x15, VL_JNZ  = 0x16, VL_HALT = 0x17
};

#define VL_MCELLS 16
#define VL_STEPS  400000

/*
 * 解释执行。program 为差分链密文（小端 32 位词），key/iv 为链密钥流与初值，
 * in/in_len 为运行时输入缓冲（GETM 从中取字节）。
 * 返回 true 表示正常 HALT；输出单元小端拼出 out（out_len 字节）。
 */
extern "C" VL_VIS bool vl_derive(const uint8_t *program, size_t prog_len,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, int out_len) {
    if (!program || !out || out_len <= 0) return false;
    if (!key || key_len == 0 || !iv || iv_len < 4) return false;
    size_t n = prog_len / 4;
    if (n == 0) return false;

    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;

    uint32_t prev = (uint32_t)iv[0] | ((uint32_t)iv[1] << 8)
                  | ((uint32_t)iv[2] << 16) | ((uint32_t)iv[3] << 24);
    for (size_t i = 0; i < n; i++) {
        uint32_t e = (uint32_t)program[i * 4] | ((uint32_t)program[i * 4 + 1] << 8)
                   | ((uint32_t)program[i * 4 + 2] << 16) | ((uint32_t)program[i * 4 + 3] << 24);
        uint32_t d = e ^ (uint32_t)key[i % key_len] ^ prev;
        words[i] = d;
        prev = e;                                  /* 密文自反馈 */
    }

    uint32_t M[VL_MCELLS];
    memset(M, 0, sizeof(M));
    uint32_t acc = 0;
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < VL_STEPS) {
        uint32_t w = words[pc];
        uint32_t op = (w >> 24) & 0xFFu;
        uint32_t d = (w >> 20) & 0xFu;
        uint32_t s = (w >> 16) & 0xFu;
        uint32_t imm = w & 0xFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case VL_SET:  M[d] = imm; break;
        case VL_SETH: M[d] = (M[d] & 0x0000FFFFu) | (imm << 16); break;
        case VL_CPY:  M[d] = M[s]; break;
        case VL_GETA: acc = M[d]; break;
        case VL_PUTA: M[d] = acc; break;
        case VL_GETM: acc = (in && imm < in_len) ? in[imm] : 0u; break;
        case VL_ADDI: acc = acc + imm; break;
        case VL_MULK: acc = acc * imm; break;
        case VL_XORR: acc = acc ^ M[s]; break;
        case VL_ANDR: acc = acc & M[s]; break;
        case VL_ORR:  acc = acc | M[s]; break;
        case VL_ADDR: acc = acc + M[s]; break;
        case VL_SUBR: acc = acc - M[s]; break;
        case VL_SHL:  acc = acc << (imm & 0x1Fu); break;
        case VL_SHR:  acc = acc >> (imm & 0x1Fu); break;
        case VL_ROL8: {
            uint32_t v = acc & 0xFFu, r = imm & 7u;
            acc = ((v << r) | (v >> (8 - r))) & 0xFFu;
        } break;
        case VL_ROR8: {
            uint32_t v = acc & 0xFFu, r = imm & 7u;
            acc = ((v >> r) | (v << (8 - r))) & 0xFFu;
        } break;
        case VL_XORI: acc = acc ^ imm; break;
        case VL_ANDI: acc = acc & imm; break;
        case VL_JMP:  pc = (int)imm; jumped = true; break;
        case VL_JZ:   if (acc == 0) { pc = (int)imm; jumped = true; } break;
        case VL_JNZ:  if (acc != 0) { pc = (int)imm; jumped = true; } break;
        case VL_HALT: halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    bool ok = halted;
    if (ok) {
        for (int i = 0; i < out_len; i++)
            out[i] = (uint8_t)((M[8 + i / 4] >> (8 * (i % 4))) & 0xFFu);
    }
    free(words);
    return ok;
}

/* 诱饵：另一组形状相同、值不同的"主钥"（服务端不认）。 */
extern "C" VL_VIS void vl_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 32; i++) out[i] = (uint8_t)(0x27 ^ (i * 0x1B));
}
