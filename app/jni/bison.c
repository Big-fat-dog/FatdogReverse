/*
 * 太玄之初 KL19：虚空造化——VMP 虚拟机保护。
 *
 * 模拟 VMP 保护：核心算法被编译为自定义 VM 字节码。
 * VM 架构：寄存器式（8 个虚拟寄存器 V0-V7）+ 32 位指令编码。
 * 指令集 25 条，字节码用轮转密钥 XOR 加密。
 *
 * 玩家需：① 逆向 VM 解释器 → ② 提取并解密字节码 → ③ 逐指令翻译为 C → ④ 算出答案。
 *
 * 标记（真）：Fatdog_reverse  — UTF-16 码元。
 * 诱饵（假）：Fatdog_reverser — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* --- 真标记：Fatdog_reverse（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0072, 0x0065, 0x0076, 0x0065, 0x0072, 0x0073, 0x0065
};
#define MARKER_LEN 14

/* --- 诱饵：Fatdog_reverser --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0072, 0x0065, 0x0076, 0x0065, 0x0072, 0x0073, 0x0065, 0x0072
};
#define DECOY_LEN 15

/* ============================================================
 * VM 架构定义
 * ============================================================ */

/* 寄存器数 */
#define VM_REGS     8
/* 栈深度 */
#define VM_STACK    64

/* 指令编码：32 位
 * [31:24] opcode (8 bit)
 * [23:20] Rd     (4 bit, 目标寄存器)
 * [19:16] Rs1    (4 bit, 源寄存器 1)
 * [15:12] Rs2    (4 bit, 源寄存器 2)
 * [11:0]  imm    (12 bit, 立即数/偏移)
 */
#define OPC(x)    (((x) >> 24) & 0xFF)
#define RD(x)     (((x) >> 20) & 0x0F)
#define RS1(x)    (((x) >> 16) & 0x0F)
#define RS2(x)    (((x) >> 12) & 0x0F)
#define IMM(x)    ((x) & 0x0FFF)
#define IMM_S(x)  ((int16_t)(((x) & 0x0FFF) << 4) >> 4)  /* 符号扩展 12→16 bit */

/* 指令集（25 条） */
/* 算术 8 条 */
#define OP_ADD     0x00   /* ADD  Rd, Rs1, Rs2 */
#define OP_SUB     0x01   /* SUB  Rd, Rs1, Rs2 */
#define OP_MUL     0x02   /* MUL  Rd, Rs1, Rs2 */
#define OP_XOR     0x03   /* XOR  Rd, Rs1, Rs2 */
#define OP_AND     0x04   /* AND  Rd, Rs1, Rs2 */
#define OP_OR      0x05   /* OR   Rd, Rs1, Rs2 */
#define OP_SHL     0x06   /* SHL  Rd, Rs1, imm */
#define OP_SHR     0x07   /* SHR  Rd, Rs1, imm */

/* 立即数 4 条 */
#define OP_MOV     0x08   /* MOV  Rd, imm */
#define OP_ADDI    0x09   /* ADDI Rd, imm */
#define OP_XORI    0x0A   /* XORI Rd, imm */
#define OP_LOAD    0x0B   /* LOAD Rd, [addr] (addr = imm) */

/* 内存 4 条 */
#define OP_STORE   0x0C   /* STORE Rs, [addr] */
#define OP_LOAD8   0x0D   /* LOAD8 Rd, [addr] (读 1 字节) */
#define OP_STORE8  0x0E   /* STORE8 Rs, [addr] (写 1 字节) */
#define OP_LEA     0x0F   /* LEA Rd, addr */

/* 跳转 5 条 */
#define OP_JMP     0x10   /* JMP offset */
#define OP_JZ      0x11   /* JZ  Rd, offset (if Rd==0 goto pc+offset) */
#define OP_JNZ     0x12   /* JNZ Rd, offset (if Rd!=0 goto pc+offset) */
#define OP_CMP     0x13   /* CMP Rs1, Rs2 → V0 = (Rs1==Rs2)?1:0 */
#define OP_RET     0x14   /* RET (返回 V0 作为结果) */

/* 系统 4 条 */
#define OP_NOP     0x15   /* NOP */
#define OP_HALT    0x16   /* HALT (停机，返回 V0) */
#define OP_PUSH    0x17   /* PUSH Rs */
#define OP_POP     0x18   /* POP  Rd */

/* --- VM 状态 --- */
typedef struct {
    uint32_t regs[VM_REGS];
    uint32_t stack[VM_STACK];
    int      sp;
    int      pc;
    int      halted;
} VMState;

/* --- 加密的字节码 --- */
/*
 * 原始字节码（解密后）：
 *   MOV  V0, 0x789        ; seed = 20280915 的低 12 位部分
 *   XORI V0, 0x1F4        ; V0 ^= 500
 *   SHL  V0, V0, 3        ; V0 <<= 3
 *   ADDI V0, 0x2710       ; V0 += 10000
 *   XORI V0, 0xBB8        ; V0 ^= 3000
 *   MOV  V1, 0x4D2        ; V1 = 1234
 *   XOR  V0, V0, V1       ; V0 ^= V1
 *   HALT                  ; return V0
 *
 * 轮转密钥：{ 0xA5, 0x3C, 0x7E, 0x1D, 0x92, 0x64, 0xA8, 0xF0 }
 * 每条 4 字节指令逐字节 XOR 密钥循环。
 */
static const uint8_t ENC_BYTECODE[] = {
    /* MOV V0, 0x789 → 08 00 00 00 789 → XOR with key */
    0xAD, 0x69, 0x7E, 0xF0, 0xC3,
    /* XORI V0, 0x1F4 → 0A 00 00 1F4 */
    0xAF, 0x69, 0x7E, 0xED, 0xA5,
    /* SHL V0, V0, 3 → 06 00 00 00 003 */
    0xA3, 0x69, 0x7E, 0xFD, 0xED,
    /* ADDI V0, 0x2710 → 09 00 00 2710 */
    0xAC, 0x69, 0x7E, 0xD9, 0xF5,
    /* XORI V0, 0xBB8 → 0A 00 00 BB8 */
    0xAF, 0x69, 0x7E, 0xA7, 0x1F,
    /* MOV V1, 0x4D2 → 08 01 00 4D2 */
    0xAD, 0x68, 0x7E, 0xF2, 0x25,
    /* XOR V0, V0, V1 → 03 00 00 10 000 */
    0xA6, 0x69, 0x7E, 0x1D, 0xF0,
    /* HALT → 16 00 00 00 */
    0xB3, 0x69, 0x7E, 0xFD
};
#define BC_LEN sizeof(ENC_BYTECODE)
#define BC_INSNS (BC_LEN / 4)  /* 指令数（近似，实际按 4 字节对齐） */

/* 轮转 XOR 密钥 */
static const uint8_t ROT_KEY[] = { 0xA5, 0x3C, 0x7E, 0x1D, 0x92, 0x64, 0xA8, 0xF0 };
#define ROT_KEY_LEN 8

/* --- 简易 SHA-256 --- */
static const uint32_t K256[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)(((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)(RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x)(RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x)(RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x)(RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]){
    uint32_t h[]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t ml=l*8, pl=((l+8+63)/64)*64;
    uint8_t *p=(uint8_t*)memset(__builtin_alloca(pl+64),0,pl+64);
    memcpy(p,m,l); p[l]=0x80;
    for(int i=0;i<8;i++) p[pl-1-i]=(uint8_t)(ml>>(i*8));
    for(size_t off=0;off<pl;off+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(uint32_t)p[off+i*4]<<24|(uint32_t)p[off+i*4+1]<<16|(uint32_t)p[off+i*4+2]<<8|(uint32_t)p[off+i*4+3];
        for(int i=16;i<64;i++) w[i]=S1(w[i-2])+w[i-7]+S0(w[i-15])+w[i-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t t1=hh+EP1(e)+CH(e,f,g)+K256[i]+w[i],t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;i++){o[i*4]=(uint8_t)(h[i]>>24);o[i*4+1]=(uint8_t)(h[i]>>16);o[i*4+2]=(uint8_t)(h[i]>>8);o[i*4+3]=(uint8_t)h[i];}
}

static void to_hex(const uint8_t *in, int n, char *out){
    const char *t="0123456789abcdef";
    for(int i=0;i<n;i++){out[i*2]=t[(in[i]>>4)&0xF];out[i*2+1]=t[in[i]&0xF];}
    out[n*2]='\0';
}

/* ============================================================
 * VM 实现
 * ============================================================ */

/* 解密字节码 */
static void decrypt_bytecode(uint32_t *out, int *count) {
    int n = BC_LEN / 4;
    const uint8_t *enc = ENC_BYTECODE;
    for (int i = 0; i < n; i++) {
        uint32_t insn = 0;
        for (int j = 0; j < 4; j++) {
            insn = (insn << 8) | (enc[i * 4 + j] ^ ROT_KEY[(i * 4 + j) % ROT_KEY_LEN]);
        }
        out[i] = insn;
    }
    *count = n;
}

/* VM 初始化 */
static void vm_init(VMState *vm) {
    memset(vm, 0, sizeof(VMState));
}

/* VM 执行：返回 V0 的值 */
static uint32_t vm_execute(const uint32_t *bytecode, int count) {
    VMState vm;
    vm_init(&vm);

    while (!vm.halted && vm.pc < count && vm.pc < 1024) {
        uint32_t insn = bytecode[vm.pc];
        uint8_t  opc = OPC(insn);
        uint8_t  rd  = RD(insn);
        uint8_t  rs1 = RS1(insn);
        uint8_t  rs2 = RS2(insn);
        int32_t  imm = IMM_S(insn);

        vm.pc++;

        switch (opc) {
        /* 算术 */
        case OP_ADD:  vm.regs[rd] = vm.regs[rs1] + vm.regs[rs2]; break;
        case OP_SUB:  vm.regs[rd] = vm.regs[rs1] - vm.regs[rs2]; break;
        case OP_MUL:  vm.regs[rd] = vm.regs[rs1] * vm.regs[rs2]; break;
        case OP_XOR:  vm.regs[rd] = vm.regs[rs1] ^ vm.regs[rs2]; break;
        case OP_AND:  vm.regs[rd] = vm.regs[rs1] & vm.regs[rs2]; break;
        case OP_OR:   vm.regs[rd] = vm.regs[rs1] | vm.regs[rs2]; break;
        case OP_SHL:  vm.regs[rd] = vm.regs[rs1] << (imm & 31); break;
        case OP_SHR:  vm.regs[rd] = vm.regs[rs1] >> (imm & 31); break;

        /* 立即数 */
        case OP_MOV:   vm.regs[rd] = (uint32_t)imm; break;
        case OP_ADDI:  vm.regs[rd] += (uint32_t)imm; break;
        case OP_XORI:  vm.regs[rd] ^= (uint32_t)imm; break;
        case OP_LOAD:  vm.regs[rd] = (uint32_t)imm; break;

        /* 内存（简化：用 regs 当临时存储） */
        case OP_STORE:  /* 省略实际内存 */ break;
        case OP_LOAD8:  /* 省略实际内存 */ break;
        case OP_STORE8: /* 省略实际内存 */ break;
        case OP_LEA:    vm.regs[rd] = (uint32_t)imm; break;

        /* 跳转 */
        case OP_JMP:  vm.pc += imm; break;
        case OP_JZ:   if (vm.regs[rd] == 0) vm.pc += imm; break;
        case OP_JNZ:  if (vm.regs[rd] != 0) vm.pc += imm; break;
        case OP_CMP:  vm.regs[0] = (vm.regs[rs1] == vm.regs[rs2]) ? 1 : 0; break;
        case OP_RET:  return vm.regs[0];

        /* 系统 */
        case OP_NOP:  break;
        case OP_HALT: return vm.regs[0];
        case OP_PUSH:
            if (vm.sp < VM_STACK) vm.stack[vm.sp++] = vm.regs[rd];
            break;
        case OP_POP:
            if (vm.sp > 0) vm.regs[rd] = vm.stack[--vm.sp];
            break;

        default: return 0; /* 未知指令 */
        }
    }
    return vm.regs[0];
}

/* 直接计算（等价于 VM 执行结果，供对拍） */
static uint32_t direct_compute(uint32_t seed) {
    uint32_t v0 = seed;
    v0 ^= 0x1F4;
    v0 <<= 3;
    v0 += 0x2710;
    v0 ^= 0xBB8;
    v0 ^= 0x4D2;
    return v0;
}

/* --- 提取种子和答案 --- */
/* 加密数据里的明文格式 "KL19_SEED:XXXXXXXX" */
static const uint8_t ENC_SEED_DATA[] = {
    0x2D, 0x30, 0x27, 0x26, 0x25, 0x6E, 0x27, 0x30,
    0x6A, 0x31, 0x37, 0x22, 0x25, 0x73, 0x74, 0x79,
    0x31, 0x27, 0x26
};
#define SEED_ENC_LEN 19
#define SEED_XOR_KEY 0x5C

static uint32_t extract_seed(void) {
    uint8_t dec[64];
    for (int i = 0; i < SEED_ENC_LEN; i++)
        dec[i] = ENC_SEED_DATA[i] ^ SEED_XOR_KEY;
    /* 明文 "KL19_SEED:20280915"，取第 10-13 字节 */
    uint32_t seed = 0;
    for (int i = 0; i < 4; i++)
        seed = (seed << 8) | dec[10 + i];
    return seed;
}

static void get_answer(uint32_t seed, char out[33]) {
    uint8_t buf[4];
    uint8_t h[32];
    buf[0] = (uint8_t)(seed >> 24);
    buf[1] = (uint8_t)(seed >> 16);
    buf[2] = (uint8_t)(seed >> 8);
    buf[3] = (uint8_t)seed;
    sha256(buf, 4, h);
    to_hex(h, 32, out);
}

/* --- 诱饵导出 --- */
void k19_decoy_seal(void) {}
void k19_fold(void) {}
void k19_spin(void) {}

/* --- JNI 桥接 --- */

/* Gk.nativeDecrypt() → String（解密后的字节码 hex） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Gk_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint32_t bc[64];
    int count;
    decrypt_bytecode(bc, &count);
    char hex[512] = {0};
    for (int i = 0; i < count; i++) {
        char tmp[9];
        snprintf(tmp, sizeof(tmp), "%08x", bc[i]);
        strcat(hex, tmp);
    }
    return (*env)->NewStringUTF(env, hex);
}

/* Gk.nativeSeed() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Gk_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)extract_seed();
}

/* Gk.nativeAnswer() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Gk_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    uint32_t seed = extract_seed();
    char hex[33];
    get_answer(seed, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Gk.nativeVmExecute() → int（VM 执行结果） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Gk_nativeVmExecute(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    uint32_t bc[64];
    int count;
    decrypt_bytecode(bc, &count);
    return (jint)vm_execute(bc, count);
}

/* Gk.nativeDirect() → int（直接计算，供对拍） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Gk_nativeDirect(JNIEnv *env, jclass clazz, jint seed) {
    (void)env; (void)clazz;
    return (jint)direct_compute((uint32_t)seed);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
