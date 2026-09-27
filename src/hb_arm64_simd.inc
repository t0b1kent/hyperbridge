/* ═══ Claude 27.09.2026 — SIMD БЕЗ ПОМОЩНИКА: перемещения XMM, целые и FP (три гейта, умолчание 0) ═══
 *
 * Включается ТЕКСТОМ в hb_arm64_codegen.c (после emit_native_ymm_store): опирается на его
 * кодировщики, предикаты прямой памяти и медленный путь emit_interp_ir_helper.
 *
 * ИЗМЕРЕНО (Hollow Knight, главный поток, MACRUNNER_HB_TRACE_HELPER_OPS, отрезок 112 млн вызовов
 * помощника, меню и заставка): MOV 31,4 млн (movsd/movss рег-рег — слияние младшей дорожки),
 * VEC_PACKED 13,9 (vinsertf128, cmpltps), XMM_QWORD_LANE_MOV 10,9, FMUL 6,2, FSUB 4,4, PADD 4,2,
 * FSQRT 3,7, VZEROUPPER 3,3, XMM_AND 2,5, PSRLDQ 2,4, XMM_SCALAR_MOV 2,2. Каждый вызов —
 * сохранение регистров, TLS, разбор операндов интерпретатором.
 *
 * ЭТАЛОН — интерпретатор (src/hb_interpreter.c); семьи покрываются ЦЕЛИКОМ по его реализации, а
 * не по местам из переписи. Правила, общие для всех семей:
 *   • ширина результата — по ПРИЁМНИКУ (dst.size, 0 -> 16), операнды читаются этой шириной
 *     независимо от своего поля size (у vcmpps ymm источник приходит с size 16, а читается 32);
 *   • устаревшие SSE пишут только младшие 128 бит, ymm_hi и zmm_hi сохраняются; VEX.128 обнуляет
 *     ymm_hi и zmm_hi, VEX.256 — zmm_hi (write_vec_reg_bytes с zero_ymm_upper);
 *   • EVEX (признак в target) — помощнику: маски, рассылка и {er} здесь не выпускаются;
 *   • только x64 и только XMM0..15 (xmm16+ живут в xmm_ext); i386 — прежним путём: разностного
 *     стенда для него нет, а без стенда выпуск не включается;
 *   • память — прямым путём, тем же, что у существующих векторных чтений (адрес в X21,
 *     LDR Q/D/S, DMB ISHLD); запись — через готовые пути с проверкой прав;
 *   • всё чтение — ДО первой записи состояния гостя: отказ доступа точен, медленный путь видит
 *     исходное состояние.
 * Регистры: V0-V7, V16-V19, V28-V31 — все caller-saved (V8-V15 не трогаются: их низ callee-saved
 * по AAPCS64, а блок зовут как функцию C); X20-X23 как у соседей, с перекладкой hb_rm.
 * Кодировки сверены ассемблером хозяина (clang -c -arch arm64 + otool -t), выборка:
 *     add v2.4s,v0.4s,v1.4s 4ea18402   sqxtn2 v2.16b,v1.8h 4e214822   smull2 v2.4s,v0.8h,v1.8h 4e61c002
 *     uzp2 v2.8h 4e415802              usra v1.8h,v1.8h,#7 6f191421  ushr v2.2d,v0.2d,#64 6f400402
 *     sshr v2.4s,v0.4s,#32 4f200402    shl v2.2d,v0.2d,#1 4f415402   ext v2.16b,v0,v1,#8 6e014002
 *     fcmge v2.2d 6e61e402             frintm v2.4s 4e219802         fcvtzs v2.4s 4ea1b802
 *     uminv s2,v0.4s 6eb1a802          umov w21,v1.b[8] 0e113c35     dup v2.8h,w20 4e020e82
 *     movi v31.2d,#0 6f00e41f          movi v2.4s,#0x9e,lsl#24 4f0467c2  stp q31,q31,[x19,#640] ad147e7f
 *     fsqrt s2,s0 1e21c002             frintp s2,s0 1e24c002         fcvt d2,s1 1e22c022 */

#define HB_SIMD_FAM_MOVES 0u
#define HB_SIMD_FAM_INT   1u
#define HB_SIMD_FAM_FP    2u
static uint64_t g_native_simd_emitted[3];

/* LDR/STR Q делят смещение на 16 МОЛЧА, STP Q берёт imm7 (до 1008): раскладка обязана это держать. */
_Static_assert(offsetof(hb_context_t, regs.x64.xmm) % 16u == 0 && offsetof(hb_context_t, ymm_hi) % 16u == 0 &&
               offsetof(hb_context_t, zmm_hi) % 16u == 0, "векторное состояние hb_context_t не выровнено на 16");
_Static_assert(offsetof(hb_context_t, regs.x64.xmm) + 32u * 7u <= 1008u &&
               offsetof(hb_context_t, ymm_hi) + 32u * 7u <= 1008u, "STP Q по ctx вне imm7");

/* Сколько команд выпущено нативно по семьям (0 перемещения, 1 целые, 2 FP) — свидетель теста. */
uint64_t hb_codegen_native_simd_emitted(unsigned fam);
uint64_t hb_codegen_native_simd_emitted(unsigned fam) {
    return fam < 3u ? __atomic_load_n(&g_native_simd_emitted[fam], __ATOMIC_RELAXED) : 0u;
}

static bool simd_done(unsigned fam) {
    __atomic_add_fetch(&g_native_simd_emitted[fam], 1, __ATOMIC_RELAXED);
    return true;
}

static int simd_gate(enum hb_gate_id id, const char* imya, int* said) {
    int v = hb_jit_gate_flag(id, 0);
    if (!*said) {
        *said = 1;
        fprintf(stderr, "macrunner-gate: %s=%d\n", imya, v);
        fflush(stderr);
    }
    return v;
}
static int native_xmm_moves_enabled(void) {
    static int said;
    return simd_gate(HB_GATE_HB_NATIVE_XMM_MOVES, "MACRUNNER_HB_NATIVE_XMM_MOVES", &said);
}
static int native_simd_int_enabled(void) {
    static int said;
    return simd_gate(HB_GATE_HB_NATIVE_SIMD_INT, "MACRUNNER_HB_NATIVE_SIMD_INT", &said);
}
static int native_simd_fp_enabled(void) {
    static int said;
    return simd_gate(HB_GATE_HB_NATIVE_SIMD_FP, "MACRUNNER_HB_NATIVE_SIMD_FP", &said);
}
/* ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ разностного теста: выпущенный результат портится перед записью (NOT для
 * вектора, EOR #1 для GPR). Тест обязан покраснеть — иначе он не видит нативный путь. */
static int simd_test_flip(void) {
    return hb_jit_gate_flag(HB_GATE_HB_TEST_SIMD_FLIP, 0);
}

/* ---- кодировщики NEON (Q=1; size в битах 22-23: 0 B, 1 H, 2 S, 3 D; у FP sz: 0 S, 1 D) ---- */
#define NV_V(d, n)      (((uint32_t)(n) << 5) | (uint32_t)(d))
#define NV_VM(d, n, m)  (((uint32_t)(m) << 16) | ((uint32_t)(n) << 5) | (uint32_t)(d))
#define NV_SZ(s)        ((uint32_t)(s) << 22)
#define NV_Q            0x40000000u     /* «2»-формы: SMULL2, SQXTN2, XTN2 */
/* три одинаковых */
#define NV_ADD     0x4e208400u
#define NV_SUB     0x6e208400u
#define NV_SQADD   0x4e200c00u
#define NV_UQADD   0x6e200c00u
#define NV_SQSUB   0x4e202c00u
#define NV_UQSUB   0x6e202c00u
#define NV_URHADD  0x6e201400u
#define NV_MUL     0x4e209c00u
#define NV_CMEQ    0x6e208c00u
#define NV_CMGT    0x4e203400u
#define NV_CMHS    0x6e203c00u
#define NV_SSHL    0x4e204400u
#define NV_USHL    0x6e204400u
#define NV_SMAX    0x4e206400u
#define NV_SMIN    0x4e206c00u
#define NV_UMAX    0x6e206400u
#define NV_UMIN    0x6e206c00u
#define NV_UABD    0x6e207400u
#define NV_ADDP    0x4e20bc00u
#define NV_ZIP1    0x4e003800u
#define NV_ZIP2    0x4e007800u
#define NV_UZP2    0x4e005800u
#define NV_TRN1    0x4e002800u
#define NV_TRN2    0x4e006800u
#define NV_DUP_EL  0x4e000400u     /* DUP Vd.T, Vn.Ts[0]: | imm5 << 16 (1 B, 2 H, 4 S, 8 D) */
#define NV_AND     0x4e201c00u
#define NV_BIC     0x4e601c00u
#define NV_ORR     0x4ea01c00u
#define NV_EOR     0x6e201c00u
#define NV_BSL     0x6e601c00u
#define NV_SMULL   0x0e20c000u     /* 64-битные входы; | NV_Q — SMULL2 */
#define NV_UMULL   0x2e20c000u
#define NV_FADD    0x4e20d400u
#define NV_FSUB    0x4ea0d400u
#define NV_FMUL    0x6e20dc00u
#define NV_FDIV    0x6e20fc00u
#define NV_FCMEQ   0x4e20e400u
#define NV_FCMGE   0x6e20e400u
#define NV_FCMGT   0x6ea0e400u
/* два регистра */
#define NV_NOT     0x6e205800u
#define NV_ABS     0x4e20b800u
#define NV_UADDLP  0x6e202800u     /* size — ширина ИСТОЧНИКА */
#define NV_XTN     0x0e212800u     /* size — ширина ПРИЁМНИКА; | NV_Q — XTN2 */
#define NV_SQXTN   0x0e214800u
#define NV_SQXTUN  0x2e212800u
#define NV_FSQRT   0x6ea1f800u
#define NV_FRINTN  0x4e218800u
#define NV_FRINTM  0x4e219800u
#define NV_FRINTP  0x4ea18800u
#define NV_FRINTZ  0x4ea19800u
#define NV_FCVTZS  0x4ea1b800u
#define NV_SCVTF   0x4e21d800u
#define NV_UMINV_S 0x6eb1a800u     /* UMINV Sd, Vn.4S */
/* прочее */
#define NV_EXT     0x6e000000u     /* | imm4 << 11 */
#define NV_SHL     0x4f005400u     /* | (esize + sh) << 16 */
#define NV_USHR    0x6f000400u     /* | (2*esize - sh) << 16 */
#define NV_SSHR    0x4f000400u
#define NV_USRA    0x6f001400u
#define NV_MOVI0   0x6f00e400u     /* MOVI Vd.2D, #0 */
#define NV_MOVIM1  0x6f07e7e0u     /* MOVI Vd.2D, #-1 */
/* скалярные FP: type в битах 22-23 (0 S, 1 D) */
#define NS_FADD    0x1e202800u
#define NS_FSUB    0x1e203800u
#define NS_FMUL    0x1e200800u
#define NS_FDIV    0x1e201800u
#define NS_FSQRT   0x1e21c000u
#define NS_FRINTN  0x1e244000u
#define NS_FRINTP  0x1e24c000u
#define NS_FRINTM  0x1e254000u
#define NS_FRINTZ  0x1e25c000u

static void nv(hb_codegen_buffer_t* buf, uint32_t w) { emit_u32(buf, w); }
static void nv3(hb_codegen_buffer_t* buf, uint32_t base, int d, int n, int m) { nv(buf, base | NV_VM(d, n, m)); }
static void nv2(hb_codegen_buffer_t* buf, uint32_t base, int d, int n) { nv(buf, base | NV_V(d, n)); }
/* Сдвиг непосредственным: esize 8/16/32/64 бит, sh в допустимом диапазоне формы. */
static void nv_shl(hb_codegen_buffer_t* buf, unsigned esize, int d, int n, unsigned sh) {
    nv(buf, NV_SHL | ((esize + sh) << 16) | NV_V(d, n));
}
static void nv_shr(hb_codegen_buffer_t* buf, uint32_t base, unsigned esize, int d, int n, unsigned sh) {
    nv(buf, base | ((2u * esize - sh) << 16) | NV_V(d, n));
}
static void nv_movi0(hb_codegen_buffer_t* buf, int d) { nv(buf, NV_MOVI0 | (uint32_t)d); }
static void nv_mov(hb_codegen_buffer_t* buf, int d, int n) { if (d != n) nv3(buf, NV_ORR, d, n, n); }
/* UMOV Wd, Vn.B[idx] (idx 0..15) — байт в регистр общего назначения */
static void nv_umov_b(hb_codegen_buffer_t* buf, int rd, int vn, unsigned idx) {
    rd = hb_rm(buf, rd);
    nv(buf, 0x0e003c00u | (((idx << 1) | 1u) << 16) | ((uint32_t)vn << 5) | (uint32_t)rd);
}
/* DUP Vd.T, Wn/Xn: size 0 B, 1 H, 2 S, 3 D */
static void nv_dup_r(hb_codegen_buffer_t* buf, unsigned size, int vd, int rn) {
    rn = hb_rm(buf, rn);
    nv(buf, 0x4e000c00u | ((1u << size) << 16) | ((uint32_t)rn << 5) | (uint32_t)vd);
}
/* FMOV Xd, Dn */
static void nv_fmov_x_d(hb_codegen_buffer_t* buf, int rd, int vn) {
    rd = hb_rm(buf, rd);
    nv(buf, 0x9e660000u | ((uint32_t)vn << 5) | (uint32_t)rd);
}

/* ---- операнды ---- */
static bool simd_xreg(const hb_ir_operand_t* op) {
    return op && op->type == HB_OP_REG && op->reg >= HB_REG_XMM0 && op->reg <= HB_REG_XMM15;
}
static bool simd_evex(const hb_ir_instr_t* in) {
    return (((uint32_t)in->target) & HB_EVEX_TARGET_PRESENT) != 0;
}
static uint32_t simd_zmm_off(hb_reg_t reg) {
    return (uint32_t)(offsetof(hb_context_t, zmm_hi) + (size_t)(reg - HB_REG_XMM0) * 32u);
}
/* Ширина векторного результата, как у интерпретатора: 0 -> 16; прочее, кроме 16/32, — не наше. */
static unsigned simd_bytes_of(hb_size_t sz) {
    unsigned b = sz ? (unsigned)sz : 16u;
    return (b == 16u || b == 32u) ? b : 0u;
}
/* Память — прямым путём; форма адреса проверяется тем же предикатом, что у 128-битных чтений. */
static bool simd_mem_ok(hb_codegen_buffer_t* buf, const hb_ir_operand_t* op) {
    hb_ir_operand_t t;
    if (!op || op->type != HB_OP_MEM) return false;
    if (!jit_direct_mem_codegen_enabled(buf) || diag_no_xmm_dload()) return false;
    t = *op;
    t.size = HB_SIZE_128;
    return direct_user_xmm_mem_allowed(buf, &t);
}
static bool simd_src_ok(hb_codegen_buffer_t* buf, const hb_ir_operand_t* op) {
    return simd_xreg(op) || simd_mem_ok(buf, op);
}
/* Загрузить `bytes` (1, 2, 4, 8, 16, 32) операнда в V<lo> (32 — ещё старшие 16 в V<hi>). Регистр:
 * младшая часть из regs.x64.xmm, старшая из ymm_hi. Память — адрес в X21 (портит X21/X22), затем
 * DMB ISHLD. Скалярные LDR B/H/S/D обнуляют остаток V<lo>. */
static void simd_load(hb_codegen_buffer_t* buf, const hb_ir_operand_t* op, unsigned bytes, int lo, int hi) {
    if (simd_xreg(op)) {
        uint32_t off = xmm_reg_off(buf, op->reg);
        if (bytes == 4u || bytes == 8u) emit_fp_ldst(buf, true, bytes == 8u, lo, 19, off);
        else if (bytes < 4u) nv(buf, (bytes == 1u ? 0x3d400000u : 0x7d400000u) | ((off / bytes) << 10) |
                                     NV_V(lo, hb_rm(buf, 19)));        /* LDR B|H по смещению ctx */
        else emit_ldr_q(buf, lo, 19, off);
        if (bytes == 32u) emit_ldr_q(buf, hi, 19, ymm_hi_off(op->reg));
        return;
    }
    {
        unsigned char prev = hb_emit_mark_stack_access(op);
        emit_direct_mem_addr(buf, op);
        ea_materialize(buf);
        if (bytes == 4u || bytes == 8u) emit_fp_ldst(buf, true, bytes == 8u, lo, 21, 0);
        else if (bytes < 4u) nv(buf, (bytes == 1u ? 0x3d400000u : 0x7d400000u) | NV_V(lo, hb_rm(buf, 21)));
        else emit_ldr_q(buf, lo, 21, 0);
        if (bytes == 32u) emit_ldr_q(buf, hi, 21, 16);
        emit_dmb_ishld(buf);
        hb_emit_restore_stack_access(prev);
        jit_native_mem_count(0);
    }
}
static void simd_flip(hb_codegen_buffer_t* buf, int v) {
    if (simd_test_flip()) nv2(buf, NV_NOT, v, v);
}
/* Обнулить всё выше записанного — как write_vec_reg_bytes при zero_ymm_upper: записано 16 байт —
 * ymm_hi и zmm_hi, 32 — только zmm_hi. */
static void simd_zero_above(hb_codegen_buffer_t* buf, hb_reg_t reg, unsigned bytes) {
    nv_movi0(buf, 31);
    if (bytes <= 16u) emit_str_q(buf, 31, 19, ymm_hi_off(reg));
    emit_str_q(buf, 31, 19, simd_zmm_off(reg));
    emit_str_q(buf, 31, 19, simd_zmm_off(reg) + 16u);
}
/* Записать результат в приёмник-XMM: 16 байт — только младшая часть, 32 — и ymm_hi. */
static void simd_store(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr, unsigned bytes, int lo, int hi) {
    hb_reg_t r = instr->dst.reg;
    simd_flip(buf, lo);
    emit_str_q(buf, lo, 19, xmm_reg_off(buf, r));
    if (bytes == 32u) emit_str_q(buf, hi, 19, ymm_hi_off(r));
    if (instr->zero_ymm_upper) simd_zero_above(buf, r, bytes);
}

/* ═══ СЕМЬЯ 1: ПЕРЕМЕЩЕНИЯ (MACRUNNER_HB_NATIVE_XMM_MOVES) ═══ */

/* MOV xmm <- xmm (интерпретатор, case HB_IR_MOV): ширина по приёмнику. 4/8 — слияние младшей
 * дорожки, прочее сохраняется (movss/movsd рег-рег; `movsd xmm1,xmm1` — пустое место, НОЛЬ команд);
 * 16 — копия (VEX.128 обнуляет верх; устаревшую форму выпускает emit_native_xmm_mov);
 * 32 — копия обеих половин (VEX.256, zmm_hi обнуляется). Маска EVEX — помощнику. */
static bool emit_simd_mov(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const hb_ir_operand_t* d = &instr->dst;
    const hb_ir_operand_t* s = &instr->src1;
    unsigned bytes;
    if (!simd_xreg(d) || !simd_xreg(s) || jit_evex_write_masked(instr)) return false;
    bytes = d->size ? (unsigned)d->size : 16u;
    if (bytes == 4u || bytes == 8u) {
        uint32_t so = xmm_reg_off(buf, s->reg), dof = xmm_reg_off(buf, d->reg);
        if (so != dof || simd_test_flip()) {
            emit_fp_ldst(buf, true, bytes == 8u, 0, 19, so);
            simd_flip(buf, 0);
            emit_fp_ldst(buf, false, bytes == 8u, 0, 19, dof);
        }
        if (instr->zero_ymm_upper) simd_zero_above(buf, d->reg, 16u);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    if (bytes != 16u && bytes != 32u) return false;
    if (bytes == 16u && s->reg == d->reg && !simd_test_flip()) {
        if (instr->zero_ymm_upper) simd_zero_above(buf, d->reg, 16u);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    simd_load(buf, s, bytes, 0, 1);
    simd_store(buf, instr, bytes, 0, 1);
    return simd_done(HB_SIMD_FAM_MOVES);
}

/* XMM_QWORD_LANE_MOV (movlhps/movhlps/movhps/movhpd и VEX-хвосты vmovlps/vmovhps): приёмник
 * получает ОДНО 64-битное слово в дорожку dl из дорожки sl источника (регистр) или из памяти;
 * запись в память — 8 байт дорожки sl. ★ У VEX интерпретатор обнуляет ТОЛЬКО ymm_hi (write_xmm_reg
 * + memset ymm_hi), zmm_hi не трогает — повторяем буквально. */
static bool emit_simd_lane_mov(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const unsigned dl = (unsigned)(instr->target & 0xffu);
    const unsigned sl = (unsigned)((instr->target >> 8) & 0xffu);
    if (dl > 1u || sl > 1u || (instr->target >> 16) != 0) return false;
    if (instr->dst.type == HB_OP_MEM) {
        hb_ir_operand_t m = instr->dst;
        unsigned char prev;
        if (!simd_xreg(&instr->src1) || !jit_direct_mem_codegen_enabled(buf) || diag_no_xmm_dstore())
            return false;
        m.size = HB_SIZE_64;
        if (!direct_user_mem_store_allowed(buf, &m)) return false;   /* тот же предикат, что внутри _tso */
        prev = hb_emit_mark_stack_access(&m);
        emit_ldr_x(buf, 20, 19, xmm_reg_off(buf, instr->src1.reg) + 8u * sl);
        if (simd_test_flip()) emit_eor_imm64(buf, 20, 20, 1);
        if (!emit_direct_mem_store_from_x20_tso(buf, &m)) {   /* недостижимо: предикат спрошен выше */
            hb_emit_restore_stack_access(prev);
            return false;
        }
        hb_emit_restore_stack_access(prev);
        jit_native_mem_count(1);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    if (!simd_xreg(&instr->dst)) return false;
    if (simd_xreg(&instr->src1)) {
        emit_fp_ldst(buf, true, true, 0, 19, xmm_reg_off(buf, instr->src1.reg) + 8u * sl);
    } else if (simd_mem_ok(buf, &instr->src1)) {
        simd_load(buf, &instr->src1, 8u, 0, 0);
    } else {
        return false;
    }
    simd_flip(buf, 0);
    emit_fp_ldst(buf, false, true, 0, 19, xmm_reg_off(buf, instr->dst.reg) + 8u * dl);
    if (instr->zero_ymm_upper) {
        nv_movi0(buf, 31);
        emit_str_q(buf, 31, 19, ymm_hi_off(instr->dst.reg));
    }
    return simd_done(HB_SIMD_FAM_MOVES);
}

/* XMM_SCALAR_MOV (vmovss/vmovsd): 16 байт = src1 (или нули у формы с памятью) с дорожкой lane из
 * src2. Запись write_vec_reg_bytes_evex_scalar_masked: без маски — обычная, VEX обнуляет верх. */
static bool emit_simd_scalar_mov(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const unsigned lane = (unsigned)(instr->target & 0xffu);
    const bool with_src1 = instr->src1.type != HB_OP_NONE;
    if ((lane != 4u && lane != 8u) || jit_evex_write_masked(instr)) return false;
    if (!simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src2)) return false;
    if (with_src1 && !simd_xreg(&instr->src1)) return false;
    simd_load(buf, &instr->src2, lane, 1, 1);         /* LDR S/D обнуляет остаток V1 */
    if (with_src1) {
        emit_ldr_q(buf, 0, 19, xmm_reg_off(buf, instr->src1.reg));
        emit_ins_elem(buf, lane == 8u ? 3u : 2u, 0, 0, 1, 0);
        simd_store(buf, instr, 16u, 0, 0);
    } else {
        simd_store(buf, instr, 16u, 1, 1);
    }
    return simd_done(HB_SIMD_FAM_MOVES);
}

/* VZEROUPPER: интерпретатор обнуляет ВЕСЬ массив ymm_hi (16 регистров, в 32 битах тоже) и НЕ
 * трогает zmm_hi. VZEROALL: младшие 128 и ymm_hi шестнадцати регистров (32 байта через
 * write_vec_reg_bytes без zero_ymm_upper — zmm_hi тоже цел). */
static bool emit_simd_vzero(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    unsigned i;
    nv_movi0(buf, 31);
    simd_flip(buf, 31);
    if (instr->op == HB_IR_VZEROALL) {
        uint32_t base = xmm_reg_off(buf, HB_REG_XMM0);
        for (i = 0; i < 8u; i++)          /* STP Q31, Q31, [X19, #base+32i] — imm7 в пределах */
            nv(buf, 0xad000000u | ((((base + 32u * i) / 16u) & 0x7fu) << 15) | (31u << 10) |
                    ((uint32_t)hb_rm(buf, 19) << 5) | 31u);
    }
    for (i = 0; i < 8u; i++)
        nv(buf, 0xad000000u | ((((uint32_t)offsetof(hb_context_t, ymm_hi) + 32u * i) / 16u & 0x7fu) << 15) |
                (31u << 10) | ((uint32_t)hb_rm(buf, 19) << 5) | 31u);
    return simd_done(HB_SIMD_FAM_MOVES);
}

/* VEC_PACKED: vinsertf128/vinserti128, vextractf128/vextracti128, vperm2f128/vperm2i128 —
 * перестановки 128-битных половин (интерпретатор, ветви VINSERT/VEXTRACT/VPERM2 в VEC_PACKED). */
static bool emit_simd_lane128(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr, hb_ir_vec_op_t vop) {
    const unsigned imm = (unsigned)(instr->target & 0xffu);
    if (simd_evex(instr)) return false;
    if (!simd_xreg(&instr->src1)) return false;
    if (vop == HB_VEC_VINSERTF128 || vop == HB_VEC_VINSERTI128) {
        if (!simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src2)) return false;
        simd_load(buf, &instr->src2, 16u, 1, 1);                   /* вставляемая половина */
        if (imm & 1u) {
            emit_ldr_q(buf, 0, 19, xmm_reg_off(buf, instr->src1.reg));
            simd_store(buf, instr, 32u, 0, 1);
        } else {
            emit_ldr_q(buf, 0, 19, ymm_hi_off(instr->src1.reg));
            simd_store(buf, instr, 32u, 1, 0);
        }
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    if (vop == HB_VEC_VEXTRACTF128 || vop == HB_VEC_VEXTRACTI128) {
        const uint32_t half = (imm & 1u) ? ymm_hi_off(instr->src1.reg) : xmm_reg_off(buf, instr->src1.reg);
        if (simd_xreg(&instr->dst)) {
            emit_ldr_q(buf, 0, 19, half);
            simd_store(buf, instr, 16u, 0, 0);
            return simd_done(HB_SIMD_FAM_MOVES);
        }
        if (instr->dst.type != HB_OP_MEM || !jit_direct_mem_codegen_enabled(buf) || diag_no_xmm_dstore())
            return false;
        {
            hb_ir_operand_t m = instr->dst;
            unsigned char prev;
            m.size = HB_SIZE_128;
            if (!direct_user_xmm_mem_allowed(buf, &m)) return false;
            prev = hb_emit_mark_stack_access(&m);
            emit_direct_mem_addr(buf, &m);                /* X22 портится — значение грузим после */
            emit_ldr_x(buf, 20, 19, half);
            emit_ldr_x(buf, 22, 19, half + 8u);
            if (simd_test_flip()) emit_eor_imm64(buf, 20, 20, 1);
            emit_direct_mem128_store_from_x20_x22(buf);   /* тот же путь, что у 128-битных записей */
            hb_emit_restore_stack_access(prev);
        }
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    if (vop == HB_VEC_VPERM2F128 || vop == HB_VEC_VPERM2I128) {
        /* половины: 0 src1.lo (V0), 1 src1.hi (V1), 2 src2.lo (V2), 3 src2.hi (V3); бит 3/7 — ноль */
        if (!simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src2)) return false;
        simd_load(buf, &instr->src2, 32u, 2, 3);
        simd_load(buf, &instr->src1, 32u, 0, 1);
        nv_movi0(buf, 31);
        {
            const int lo = (imm & 0x08u) ? 31 : (int)(imm & 3u);
            const int hi = (imm & 0x80u) ? 31 : (int)((imm >> 4) & 3u);
            nv_mov(buf, 4, lo);
            nv_mov(buf, 5, hi);
        }
        simd_store(buf, instr, 32u, 4, 5);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    return false;
}

/* Дублирование и рассылка дорожек — тоже перемещения (семья 1, MACRUNNER_HB_NATIVE_XMM_MOVES):
 *   HB_IR_MOVDUP (устаревшие MOVDDUP/MOVSLDUP/MOVSHDUP, target 0/1/2): DDUP читает 8 байт, прочие 16,
 *     запись 16 байт — у устаревших ymm_hi сохраняется;
 *   VEC VMOVDDUP/VMOVSLDUP/VMOVSHDUP (VEX 128/256, по 128-битным половинам): источник читается ПОЛНОЙ
 *     шириной приёмника — у vmovddup xmm,m64 интерпретатор читает 16 байт, повторяем буквально;
 *   VEC VPBROADCASTB/W/D/Q, VBROADCASTSS/SD, VBROADCASTI128, VBROADCASTF128 (декодер зовёт её
 *     VBROADCASTF32X4): младшие 1/2/4/8/16 байт источника (XMM или память) по всей ширине приёмника.
 *     EVEX-рассылки (F32X2 и родня, маски) — помощнику. */
static bool emit_simd_dup(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr, hb_ir_vec_op_t vop) {
    unsigned bytes, h;
    if (!simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src1)) return false;
    if (instr->op == HB_IR_MOVDUP) {
        const unsigned vid = (unsigned)instr->target;
        if (vid > 2u) return false;
        simd_load(buf, &instr->src1, vid == 0u ? 8u : 16u, 1, 1);
        if (vid == 0u) nv2(buf, NV_DUP_EL | (8u << 16), 2, 1);            /* DUP V2.2D, V1.D[0] */
        else nv3(buf, (vid == 1u ? NV_TRN1 : NV_TRN2) | NV_SZ(2), 2, 1, 1); /* [x0 x0 x2 x2] | [x1 x1 x3 x3] */
        simd_store(buf, instr, 16u, 2, 2);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    if (simd_evex(instr) || (instr->target & 0xffffffffull) != 0) return false;
    bytes = simd_bytes_of(instr->dst.size);
    if (!bytes) return false;
    if (vop == HB_VEC_VMOVDDUP || vop == HB_VEC_VMOVSLDUP || vop == HB_VEC_VMOVSHDUP) {
        simd_load(buf, &instr->src1, bytes, 1, 5);
        for (h = 0; h < (bytes == 32u ? 2u : 1u); h++) {
            const int d = h ? 6 : 2, n = h ? 5 : 1;
            if (vop == HB_VEC_VMOVDDUP) nv2(buf, NV_DUP_EL | (8u << 16), d, n);
            else nv3(buf, (vop == HB_VEC_VMOVSLDUP ? NV_TRN1 : NV_TRN2) | NV_SZ(2), d, n, n);
        }
        simd_store(buf, instr, bytes, 2, 6);
        return simd_done(HB_SIMD_FAM_MOVES);
    }
    {
        const unsigned sb = vop == HB_VEC_VPBROADCASTB ? 1u : vop == HB_VEC_VPBROADCASTW ? 2u :
                            (vop == HB_VEC_VPBROADCASTD || vop == HB_VEC_VBROADCASTSS) ? 4u :
                            (vop == HB_VEC_VPBROADCASTQ || vop == HB_VEC_VBROADCASTSD) ? 8u :
                            (vop == HB_VEC_VBROADCASTI128 || vop == HB_VEC_VBROADCASTF32X4) ? 16u : 0u;
        if (!sb) return false;
        simd_load(buf, &instr->src1, instr->src1.type == HB_OP_MEM ? sb : 16u, 1, 1);
        if (sb == 16u) {
            simd_store(buf, instr, bytes, 1, 1);
        } else {
            nv2(buf, NV_DUP_EL | (sb << 16), 2, 1);             /* imm5 = 1/2/4/8: элемент 0 ширины sb */
            simd_store(buf, instr, bytes, 2, 2);
        }
        return simd_done(HB_SIMD_FAM_MOVES);
    }
}

static bool emit_simd_moves(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    switch (instr->op) {
        case HB_IR_MOV:               return emit_simd_mov(buf, instr);
        case HB_IR_XMM_QWORD_LANE_MOV: return emit_simd_lane_mov(buf, instr);
        case HB_IR_XMM_SCALAR_MOV:    return emit_simd_scalar_mov(buf, instr);
        case HB_IR_VZEROUPPER:
        case HB_IR_VZEROALL:          return emit_simd_vzero(buf, instr);
        case HB_IR_MOVDUP:            return emit_simd_dup(buf, instr, (hb_ir_vec_op_t)0);
        default:                      return false;
    }
}

/* ═══ СЕМЬЯ 2: ЦЕЛЫЕ (MACRUNNER_HB_NATIVE_SIMD_INT) ═══
 *
 * Каждая команда — поэлементная операция по 128-битным половинам (у VEX.256 интерпретатор тоже
 * считает по половинам: PACK/PUNPCK — `for base += 16`), поэтому выпуск один на половину. Вид:
 *   3SAME   — одна команда NEON «три одинаковых» (ADD/SUB/SQADD/UQADD/SQSUB/UQSUB/URHADD/MUL/
 *             CMEQ/CMGT/SMIN/SMAX/UMIN/UMAX/AND/ORR/EOR/ZIP1/ZIP2): семантика x86 совпадает поэлементно,
 *             включая насыщение и перенос по модулю;
 *   ANDN    — BIC Vd, Vsrc2, Vsrc1 (x86 считает ~src1 & src2);
 *   PMULH*  — SMULL/UMULL + вторая половина + UZP2 (старшие 16 бит 32-битного произведения);
 *   PMADDWD — SMULL + SMULL2 + ADDP (у -32768·-32768·2 перенос по модулю, как у интерпретатора);
 *   PSADBW  — UABD + три UADDLP: 64-битная сумма в каждой четверти, прочие байты нули;
 *   PACK    — SQXTN/SQXTUN младшей половиной из src1 и «2»-формой из src2;
 *   MULDQ   — XTN младших двойных слов + SMULL/UMULL (PMULDQ/PMULUDQ);
 *   ABS     — ABS (у INT_MIN ответ INT_MIN — как `-a` с усечением в интерпретаторе). */
enum { SI_3SAME, SI_ANDN, SI_PMULH, SI_PMULHU, SI_PMADDWD, SI_PSADBW, SI_PACK, SI_MULDQ, SI_ABS };
struct simd_int_op { int kind; uint32_t base; unsigned size; bool unary; };

static unsigned simd_lane_size(unsigned lane) {      /* 1/2/4/8 байт -> поле size NEON */
    return lane == 1u ? 0u : lane == 2u ? 1u : lane == 4u ? 2u : 3u;
}

/* Разбор команды в операцию NEON. false — не наша форма (EVEX, неизвестная дорожка, иной вид). */
static bool simd_int_classify(const hb_ir_instr_t* in, struct simd_int_op* o) {
    const uint64_t t = in->target;
    memset(o, 0, sizeof(*o));
    o->kind = SI_3SAME;
    switch (in->op) {
        case HB_IR_PADD: case HB_IR_PSUB: {
            const unsigned lane = (unsigned)(t & 0xffu);
            if ((t & ~0xffull) != 0 || (lane != 1u && lane != 2u && lane != 4u && lane != 8u)) return false;
            o->base = in->op == HB_IR_PADD ? NV_ADD : NV_SUB;
            o->size = simd_lane_size(lane);
            return true;
        }
        case HB_IR_PUNPCK: {
            const unsigned lane = (unsigned)(t & 0xffu);
            if ((t & ~0x1ffull) != 0 || (lane != 1u && lane != 2u && lane != 4u && lane != 8u)) return false;
            o->base = (t & 0x100u) ? NV_ZIP2 : NV_ZIP1;
            o->size = simd_lane_size(lane);
            return true;
        }
        case HB_IR_XMM_AND: case HB_IR_XMM_ANDN: case HB_IR_XMM_OR: case HB_IR_XORPS:
            if (t != 0) return false;                   /* лифтер пишет target только у EVEX */
            if (in->op == HB_IR_XMM_ANDN) { o->kind = SI_ANDN; return true; }
            o->base = in->op == HB_IR_XMM_AND ? NV_AND : in->op == HB_IR_XMM_OR ? NV_ORR : NV_EOR;
            return true;
        default:
            break;
    }
    if (in->op != HB_IR_VEC_PACKED) {
        if (t != 0) return false;                       /* у прочих target = 0 вне EVEX */
        switch (in->op) {
            case HB_IR_PCMPEQB: o->base = NV_CMEQ; o->size = 0; return true;
            case HB_IR_PCMPEQW: o->base = NV_CMEQ; o->size = 1; return true;
            case HB_IR_PCMPEQD: o->base = NV_CMEQ; o->size = 2; return true;
            case HB_IR_PCMPGTB: o->base = NV_CMGT; o->size = 0; return true;
            case HB_IR_PCMPGTW: o->base = NV_CMGT; o->size = 1; return true;
            case HB_IR_PCMPGTD: o->base = NV_CMGT; o->size = 2; return true;
            case HB_IR_PADDSB:  o->base = NV_SQADD; o->size = 0; return true;
            case HB_IR_PADDSW:  o->base = NV_SQADD; o->size = 1; return true;
            case HB_IR_PADDUSB: o->base = NV_UQADD; o->size = 0; return true;
            case HB_IR_PADDUSW: o->base = NV_UQADD; o->size = 1; return true;
            case HB_IR_PSUBSB:  o->base = NV_SQSUB; o->size = 0; return true;
            case HB_IR_PSUBSW:  o->base = NV_SQSUB; o->size = 1; return true;
            case HB_IR_PSUBUSB: o->base = NV_UQSUB; o->size = 0; return true;
            case HB_IR_PSUBUSW: o->base = NV_UQSUB; o->size = 1; return true;
            case HB_IR_PAVGB:   o->base = NV_URHADD; o->size = 0; return true;
            case HB_IR_PAVGW:   o->base = NV_URHADD; o->size = 1; return true;
            case HB_IR_PMULLW:  o->base = NV_MUL; o->size = 1; return true;
            case HB_IR_PMULHW:  o->kind = SI_PMULH; return true;
            case HB_IR_PMULHUW: o->kind = SI_PMULHU; return true;
            case HB_IR_PMADDWD: o->kind = SI_PMADDWD; return true;
            case HB_IR_PSADBW:  o->kind = SI_PSADBW; return true;
            case HB_IR_PACKSSWB: o->kind = SI_PACK; o->base = NV_SQXTN;  o->size = 0; return true;
            case HB_IR_PACKUSWB: o->kind = SI_PACK; o->base = NV_SQXTUN; o->size = 0; return true;
            case HB_IR_PACKSSDW: o->kind = SI_PACK; o->base = NV_SQXTN;  o->size = 1; return true;
            default: return false;
        }
    }
    if ((t & 0xffffffffull) != 0) return false;         /* imm и EVEX у этих видов пусты */
    switch ((hb_ir_vec_op_t)(t >> 32)) {
        case HB_VEC_PCMPEQQ:  o->base = NV_CMEQ; o->size = 3; return true;
        case HB_VEC_PCMPGTQ:  o->base = NV_CMGT; o->size = 3; return true;
        case HB_VEC_PSUBSB:   o->base = NV_SQSUB; o->size = 0; return true;
        case HB_VEC_PSUBSW:   o->base = NV_SQSUB; o->size = 1; return true;
        case HB_VEC_PSUBUSB:  o->base = NV_UQSUB; o->size = 0; return true;
        case HB_VEC_PSUBUSW:  o->base = NV_UQSUB; o->size = 1; return true;
        case HB_VEC_PMINSB:   o->base = NV_SMIN; o->size = 0; return true;
        case HB_VEC_PMINSW:   o->base = NV_SMIN; o->size = 1; return true;
        case HB_VEC_PMINSD:   o->base = NV_SMIN; o->size = 2; return true;
        case HB_VEC_PMINUB:   o->base = NV_UMIN; o->size = 0; return true;
        case HB_VEC_PMINUW:   o->base = NV_UMIN; o->size = 1; return true;
        case HB_VEC_PMINUD:   o->base = NV_UMIN; o->size = 2; return true;
        case HB_VEC_PMAXSB:   o->base = NV_SMAX; o->size = 0; return true;
        case HB_VEC_PMAXSW:   o->base = NV_SMAX; o->size = 1; return true;
        case HB_VEC_PMAXSD:   o->base = NV_SMAX; o->size = 2; return true;
        case HB_VEC_PMAXUB:   o->base = NV_UMAX; o->size = 0; return true;
        case HB_VEC_PMAXUW:   o->base = NV_UMAX; o->size = 1; return true;
        case HB_VEC_PMAXUD:   o->base = NV_UMAX; o->size = 2; return true;
        case HB_VEC_PMULLD:   o->base = NV_MUL; o->size = 2; return true;
        case HB_VEC_PMULUDQ:  o->kind = SI_MULDQ; o->base = NV_UMULL; return true;
        case HB_VEC_PMULDQ:   o->kind = SI_MULDQ; o->base = NV_SMULL; return true;
        case HB_VEC_PSADBW:   o->kind = SI_PSADBW; return true;
        case HB_VEC_PACKUSDW: o->kind = SI_PACK; o->base = NV_SQXTUN; o->size = 1; return true;
        case HB_VEC_PABSB:    o->kind = SI_ABS; o->size = 0; o->unary = true; return true;
        case HB_VEC_PABSW:    o->kind = SI_ABS; o->size = 1; o->unary = true; return true;
        case HB_VEC_PABSD:    o->kind = SI_ABS; o->size = 2; o->unary = true; return true;
        default: return false;
    }
}

/* Одна 128-битная половина: d <- op(n, m); черновики V16, V17. */
static void simd_int_half(hb_codegen_buffer_t* buf, const struct simd_int_op* o, int d, int n, int m) {
    switch (o->kind) {
        case SI_3SAME:  nv3(buf, o->base | NV_SZ(o->size), d, n, m); break;
        case SI_ANDN:   nv3(buf, NV_BIC, d, m, n); break;
        case SI_ABS:    nv2(buf, NV_ABS | NV_SZ(o->size), d, n); break;
        case SI_PMULH:
        case SI_PMULHU: {
            const uint32_t mull = o->kind == SI_PMULH ? NV_SMULL : NV_UMULL;
            nv3(buf, mull | NV_SZ(1), 16, n, m);                 /* .4S <- .4H x .4H */
            nv3(buf, mull | NV_SZ(1) | NV_Q, 17, n, m);          /* .4S <- .8H(верх) */
            nv3(buf, NV_UZP2 | NV_SZ(1), d, 16, 17);             /* старшие 16 бит каждого */
            break;
        }
        case SI_PMADDWD:
            nv3(buf, NV_SMULL | NV_SZ(1), 16, n, m);
            nv3(buf, NV_SMULL | NV_SZ(1) | NV_Q, 17, n, m);
            nv3(buf, NV_ADDP | NV_SZ(2), d, 16, 17);             /* соседние пары */
            break;
        case SI_PSADBW:
            nv3(buf, NV_UABD, 16, n, m);
            nv2(buf, NV_UADDLP | NV_SZ(0), 16, 16);
            nv2(buf, NV_UADDLP | NV_SZ(1), 16, 16);
            nv2(buf, NV_UADDLP | NV_SZ(2), d, 16);
            break;
        case SI_PACK:
            nv2(buf, o->base | NV_SZ(o->size), d, n);            /* младшие 8 байт из src1 */
            nv2(buf, o->base | NV_SZ(o->size) | NV_Q, d, m);     /* старшие из src2 */
            break;
        case SI_MULDQ:
            nv2(buf, NV_XTN | NV_SZ(2), 16, n);                  /* младшие двойные слова четвертей */
            nv2(buf, NV_XTN | NV_SZ(2), 17, m);
            nv3(buf, o->base | NV_SZ(2), d, 16, 17);             /* .2D <- .2S x .2S */
            break;
        default: break;
    }
}

static bool emit_simd_int_binop(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    struct simd_int_op o;
    const unsigned bytes = simd_bytes_of(instr->dst.size);
    if (!bytes || !simd_xreg(&instr->dst) || !simd_int_classify(instr, &o)) return false;
    if (!simd_src_ok(buf, &instr->src1)) return false;
    if (!o.unary && !simd_src_ok(buf, &instr->src2)) return false;
    /* XORPS x,x (и VEX vxorps d,s,s): ноль без чтения — «самообнуление» */
    if (o.kind == SI_3SAME && o.base == NV_EOR && simd_xreg(&instr->src1) && simd_xreg(&instr->src2) &&
        instr->src1.reg == instr->src2.reg) {
        nv_movi0(buf, 2);
        nv_movi0(buf, 6);
        simd_store(buf, instr, bytes, 2, 6);
        return simd_done(HB_SIMD_FAM_INT);
    }
    if (!o.unary && instr->src2.type == HB_OP_MEM) {     /* память первой: её адрес портит X21/X22 */
        simd_load(buf, &instr->src2, bytes, 1, 5);
        simd_load(buf, &instr->src1, bytes, 0, 4);
    } else {
        simd_load(buf, &instr->src1, bytes, 0, 4);
        if (!o.unary) simd_load(buf, &instr->src2, bytes, 1, 5);
    }
    simd_int_half(buf, &o, 2, 0, 1);
    if (bytes == 32u) simd_int_half(buf, &o, 6, 4, 5);
    simd_store(buf, instr, bytes, 2, 6);
    return simd_done(HB_SIMD_FAM_INT);
}

/* Сдвиги (интерпретатор: PSRL/PSRA/PSLL — дорожки 2/4; PSRLQ/PSLLQ; PSRLDQ/PSLLDQ — байты по
 * 128-битным половинам). Счётчик: непосредственный — imm & 0xff; XMM/память — младшие 64 бита из
 * ШЕСТНАДЦАТИ прочитанных байт (read_packed_shift_count), больше ширины — ноль или знак.
 * Непосредственный разбирается при выпуске (0 — копия, >= ширины — ноль / SSHR #ширина), счётчик из
 * регистра — min(c, 64) в GPR и USHL/SSHL на DUP-векторе (отрицательный — сдвиг вправо). */
static bool emit_simd_shift(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const hb_ir_op_t op = instr->op;
    const unsigned bytes = simd_bytes_of(instr->dst.size);
    const bool right = op == HB_IR_PSRL || op == HB_IR_PSRA || op == HB_IR_PSRLQ || op == HB_IR_PSRLDQ;
    const bool arith = op == HB_IR_PSRA;
    unsigned esize, size, half;
    if (!bytes || !simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src1)) return false;
    if (op == HB_IR_PSRL || op == HB_IR_PSRA || op == HB_IR_PSLL) {
        const uint64_t lane = instr->target;
        if (lane != 2u && lane != 4u) return false;
        esize = (unsigned)lane * 8u;
    } else if (op == HB_IR_PSRLQ || op == HB_IR_PSLLQ) {
        if (instr->target != 0) return false;
        esize = 64u;
    } else {
        if (instr->target != 0 || instr->src2.type != HB_OP_IMM) return false;   /* только imm8 */
        esize = 0u;
    }
    size = esize == 16u ? 1u : esize == 32u ? 2u : 3u;
    if (instr->src2.type == HB_OP_IMM) {
        const unsigned c = (unsigned)((uint64_t)instr->src2.imm & 0xffu);
        simd_load(buf, &instr->src1, bytes, 0, 4);
        nv_movi0(buf, 31);
        for (half = 0; half < (bytes == 32u ? 2u : 1u); half++) {
            const int d = half ? 6 : 2, n = half ? 4 : 0;
            if (esize == 0u) {                                   /* PSRLDQ / PSLLDQ */
                if (c >= 16u) nv_movi0(buf, d);
                else if (c == 0u) nv_mov(buf, d, n);
                else if (right) nv(buf, NV_EXT | ((uint32_t)c << 11) | NV_VM(d, n, 31));
                else nv(buf, NV_EXT | ((uint32_t)(16u - c) << 11) | NV_VM(d, 31, n));
            } else if (c == 0u) {
                nv_mov(buf, d, n);
            } else if (c >= esize) {
                if (arith) nv_shr(buf, NV_SSHR, esize, d, n, esize);   /* заполнение знаком */
                else nv_movi0(buf, d);
            } else if (!right) {
                nv_shl(buf, esize, d, n, c);
            } else {
                nv_shr(buf, arith ? NV_SSHR : NV_USHR, esize, d, n, c);
            }
        }
        simd_store(buf, instr, bytes, 2, 6);
        return simd_done(HB_SIMD_FAM_INT);
    }
    if (esize == 0u || !simd_src_ok(buf, &instr->src2)) return false;
    if (instr->src2.type == HB_OP_MEM) {                         /* память первой */
        simd_load(buf, &instr->src2, 16u, 3, 3);
        simd_load(buf, &instr->src1, bytes, 0, 4);
    } else {
        simd_load(buf, &instr->src1, bytes, 0, 4);
        simd_load(buf, &instr->src2, 16u, 3, 3);
    }
    nv_fmov_x_d(buf, 20, 3);                                     /* X20 = младшие 64 бита счётчика */
    emit_mov_imm_compact(buf, 21, 64);
    emit_gpr_word(buf, 0xeb00001fu, 31, 20, 21);                 /* CMP X20, X21 */
    emit_gpr_word(buf, 0x9a800000u | (3u << 12), 20, 20, 21);    /* CSEL X20, X20, X21, LO: min(c,64) */
    if (right) emit_neg_reg(buf, true, 20, 20);
    nv_dup_r(buf, size, 3, 20);                                  /* младший байт элемента — сдвиг */
    for (half = 0; half < (bytes == 32u ? 2u : 1u); half++) {
        const int d = half ? 6 : 2, n = half ? 4 : 0;
        nv3(buf, (arith ? NV_SSHL : NV_USHL) | NV_SZ(size), d, n, 3);
    }
    simd_store(buf, instr, bytes, 2, 6);
    return simd_done(HB_SIMD_FAM_INT);
}

/* PMOVMSKB / MOVMSKPS / MOVMSKPD: знаковые биты в 32-битный GPR (write_reg_sized 32: верх
 * обнуляется). Ширина источника — по ЕГО полю size (32 — ymm, прочее 16), как у интерпретатора.
 * Сжатие: USHR до 0/1 на дорожку, затем USRA складывает соседей (биты не пересекаются) — в байте 0
 * каждой четверти маска её дорожек; два UMOV и ORR со сдвигом. */
static bool emit_simd_movmsk(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const bool bytes_mask = instr->op == HB_IR_PMOVMSKB;
    unsigned lane, per_q, half, halves;
    hb_ir_operand_t dst = instr->dst;
    if (!is_plain_gpr_reg_operand(&instr->dst) || !simd_xreg(&instr->src1)) return false;
    if (bytes_mask) {
        if (instr->target != 0) return false;
        lane = 1u;
    } else {
        lane = (unsigned)instr->target;
        if (lane != 4u && lane != 8u) return false;
    }
    per_q = 8u / lane;                                           /* бит маски на четверть */
    halves = (instr->src1.size == HB_SIZE_256) ? 2u : 1u;
    simd_load(buf, &instr->src1, halves == 2u ? 32u : 16u, 0, 4);
    for (half = 0; half < halves; half++) {
        const int v = half ? 4 : 0;
        if (lane == 1u) {
            nv_shr(buf, NV_USHR, 8u, 1, v, 7u);
            nv_shr(buf, NV_USRA, 16u, 1, 1, 7u);
            nv_shr(buf, NV_USRA, 32u, 1, 1, 14u);
            nv_shr(buf, NV_USRA, 64u, 1, 1, 28u);
        } else if (lane == 4u) {
            nv_shr(buf, NV_USHR, 32u, 1, v, 31u);
            nv_shr(buf, NV_USRA, 64u, 1, 1, 31u);
        } else {
            nv_shr(buf, NV_USHR, 64u, 1, v, 63u);
        }
        if (half == 0) {
            nv_umov_b(buf, 20, 1, 0);
        } else {
            nv_umov_b(buf, 21, 1, 0);
            emit_gpr_word(buf, 0x2a000000u | ((2u * per_q) << 10), 20, 20, 21);   /* ORR W20, W20, W21, LSL */
        }
        nv_umov_b(buf, 21, 1, 8);
        emit_gpr_word(buf, 0x2a000000u | (((2u * half + 1u) * per_q) << 10), 20, 20, 21);
    }
    if (simd_test_flip()) emit_eor_imm64(buf, 20, 20, 1);
    dst.size = HB_SIZE_32;
    emit_store_x20_to_gpr_sized(buf, &dst);
    return simd_done(HB_SIMD_FAM_INT);
}

/* ═══ СЕМЬЯ 3: ПЛАВАЮЩАЯ ТОЧКА (MACRUNNER_HB_NATIVE_SIMD_FP) ═══
 *
 * Соглашения — те же, что у emit_native_sse_fp (разбор там же):
 *   • арифметика и корень считаются той же операцией IEEE при том же FPCR хозяина, что и в C
 *     интерпретатора; расходятся только NaN-исходы (выбор полезной нагрузки, знак «неопределённого»),
 *     поэтому любой NaN в результате — медленный путь ДО записи (помощник видит исходное состояние);
 *   • MIN/MAX — выбор битов FCMGT+BSL (вектор) / FCMP+FCSEL (скаляр), верно только без DAZ и FTZ
 *     у гостя: при них — помощник (как у вектора в emit_native_sse_fp);
 *   • ROUND — FRINTN/M/P/Z по imm (или по MXCSR.RC при imm&4 — ветвлением, FPCR тут не судья);
 *     NaN и бесконечности FRINT отдаёт так же, как hb_round_fp_bits (тихий NaN с той же полезной
 *     нагрузкой). DAZ у гостя сводит денормаль к нулю, а FRINTM/P дали бы ±1 — при DAZ|FTZ помощник;
 *   • CMPPS/PD/SS/SD — все 32 предиката выражаются FCMEQ/FCMGE/FCMGT и их отрицаниями; FZ хозяина
 *     действует на сравнения NEON так же, как на сравнения C;
 *   • преобразования в целое — без флагов исключений ХОЗЯИНА (договор tests/hb_sse_integer_rounding_test):
 *     опасные дорожки (вне диапазона, NaN) обнуляются ДО FRINT/FCVTZS, «целое неопределённое»
 *     0x80000000 накладывается маской.
 * Устаревшие формы ADD/SUB/MUL/DIV/MIN/MAX/CVT* выпускает emit_native_sse_fp под своим гейтом;
 * здесь — то, чего нет у него: VEX (3 операнда, VEX.128/VEX.256, скалярный VEX), SQRT/RSQRT/RCP,
 * ROUND, CMP*, CVT*PS2DQ/PD2DQ во всех формах. */

/* Медленный путь по NaN в векторе (одна или две половины): CBZ на помощника, позицию вернуть. */
static size_t simd_nan_guard_vec(hb_codegen_buffer_t* buf, bool dbl, int r0, int r1) {
    const uint32_t eq = NV_FCMEQ | NV_SZ(dbl ? 1u : 0u);
    nv3(buf, eq, 16, r0, r0);                        /* все единицы, где НЕ NaN */
    if (r1 >= 0) {
        nv3(buf, eq, 17, r1, r1);
        nv3(buf, NV_AND, 16, 16, 17);
    }
    nv2(buf, NV_UMINV_S, 16, 16);
    emit_fmov_s_to_w(buf, 20, 16);
    return emit_cbz_x_deferred(buf, 20);
}

/* DAZ или FTZ у гостя -> две ветви на медленный путь (TST #0x40, TST #0x8000). */
static void simd_mxcsr_daz_ftz_guard(hb_codegen_buffer_t* buf, size_t* b1, size_t* b2) {
    emit_ldr_w(buf, 22, 19, (uint32_t)offsetof(hb_context_t, mxcsr));
    emit_gpr_word(buf, 0x721a001fu, 31, 22, 0);          /* TST W22, #0x40   (DAZ) */
    *b1 = emit_bcond_deferred(buf, 1 /* NE */);
    emit_gpr_word(buf, 0x7211001fu, 31, 22, 0);          /* TST W22, #0x8000 (FTZ) */
    *b2 = emit_bcond_deferred(buf, 1 /* NE */);
}

/* FRINT по режиму 0 ближ. чётн., 1 вниз, 2 вверх, 3 к нулю. scalar — форма S/D, иначе вектор. */
static void simd_frint(hb_codegen_buffer_t* buf, unsigned mode, bool scalar, bool dbl, int d, int n) {
    static const uint32_t vec[4] = { NV_FRINTN, NV_FRINTM, NV_FRINTP, NV_FRINTZ };
    static const uint32_t sc[4] = { NS_FRINTN, NS_FRINTM, NS_FRINTP, NS_FRINTZ };
    nv2(buf, (scalar ? sc[mode & 3u] : vec[mode & 3u]) | NV_SZ(dbl ? 1u : 0u), d, n);
}

/* FRINT с режимом из W22 (MXCSR гостя, уже загружен): 4 ветви по RC, каждая — пары (d[i], n[i]). */
static void simd_frint_rc(hb_codegen_buffer_t* buf, bool scalar, bool dbl, const int* d, const int* n,
                          unsigned count) {
    size_t to_n, to_m, to_p, j_z, j_n, j_m;
    unsigned i;
    emit_ubfx_x(buf, 23, 22, 13u, 2u);                   /* X23 = RC */
    to_n = emit_cbz_x_deferred(buf, 23);
    emit_cmp_imm(buf, 23, 1);
    to_m = emit_bcond_deferred(buf, 0 /* EQ */);
    emit_cmp_imm(buf, 23, 2);
    to_p = emit_bcond_deferred(buf, 0 /* EQ */);
    for (i = 0; i < count; i++) simd_frint(buf, 3u, scalar, dbl, d[i], n[i]);
    j_z = emit_b_deferred(buf);
    patch_cbz_x(buf, to_n, 23, buf->size);
    for (i = 0; i < count; i++) simd_frint(buf, 0u, scalar, dbl, d[i], n[i]);
    j_n = emit_b_deferred(buf);
    patch_bcond(buf, to_m, 0, buf->size);
    for (i = 0; i < count; i++) simd_frint(buf, 1u, scalar, dbl, d[i], n[i]);
    j_m = emit_b_deferred(buf);
    patch_bcond(buf, to_p, 0, buf->size);
    for (i = 0; i < count; i++) simd_frint(buf, 2u, scalar, dbl, d[i], n[i]);
    patch_b(buf, j_z, buf->size);
    patch_b(buf, j_n, buf->size);
    patch_b(buf, j_m, buf->size);
}

/* ADD/SUB/MUL/DIV/MIN/MAX в VEX-формах (скаляр: младшая дорожка src1 op src2, остальное — src1;
 * вектор: 128/256). Устаревшие формы — emit_native_sse_fp (гейт MACRUNNER_HB_NATIVE_SSE_FP). */
static bool emit_simd_fp_arith(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    static const uint32_t vop[4] = { NV_FADD, NV_FSUB, NV_FMUL, NV_FDIV };
    static const uint32_t sop[4] = { NS_FADD, NS_FSUB, NS_FMUL, NS_FDIV };
    const uint64_t t = instr->target;
    const unsigned lane = (unsigned)(t & 0xffu);
    const bool scalar = (t & 0x100u) != 0, dbl = lane == 8u;
    const bool minmax = instr->op == HB_IR_FMIN || instr->op == HB_IR_FMAX;
    const bool is_max = instr->op == HB_IR_FMAX;
    const int fop = instr->op == HB_IR_FADD ? 0 : instr->op == HB_IR_FSUB ? 1 : instr->op == HB_IR_FMUL ? 2 : 3;
    const uint32_t szb = NV_SZ(dbl ? 1u : 0u);
    unsigned bytes;
    size_t slow1 = 0, slow2 = 0, done;
    int nan_scalar = 0;
    if ((t & ~0x1ffull) != 0 || (lane != 4u && lane != 8u) || !instr->zero_ymm_upper) return false;
    if (!simd_xreg(&instr->dst) || !simd_xreg(&instr->src1) || !simd_src_ok(buf, &instr->src2)) return false;
    bytes = scalar ? 16u : simd_bytes_of(instr->dst.size);
    if (!bytes) return false;
    if (scalar) {
        simd_load(buf, &instr->src2, lane, 1, 1);
        simd_load(buf, &instr->src1, 16u, 0, 0);
    } else {
        simd_load(buf, &instr->src2, bytes, 1, 5);
        simd_load(buf, &instr->src1, bytes, 0, 4);
    }
    if (minmax) {
        simd_mxcsr_daz_ftz_guard(buf, &slow1, &slow2);
        if (scalar) {
            emit_fcmp_rr(buf, dbl, 0, 1);
            emit_fcsel(buf, dbl, 2, 0, 1, is_max ? HB_AC_GT : HB_AC_MI);
        } else {
            unsigned h;
            for (h = 0; h < (bytes == 32u ? 2u : 1u); h++) {
                const int d = h ? 6 : 2, a = h ? 4 : 0, b = h ? 5 : 1;
                if (is_max) nv3(buf, NV_FCMGT | szb, d, a, b);   /* маска a > b */
                else        nv3(buf, NV_FCMGT | szb, d, b, a);   /* маска b > a, то есть a < b */
                nv3(buf, NV_BSL, d, a, b);
            }
        }
    } else if (scalar) {
        nv3(buf, sop[fop] | szb, 2, 0, 1);
        emit_fcmp_rr(buf, dbl, 2, 2);
        slow1 = emit_bcond_deferred(buf, HB_AC_VS);
        nan_scalar = 1;
    } else {
        nv3(buf, vop[fop] | szb, 2, 0, 1);
        if (bytes == 32u) nv3(buf, vop[fop] | szb, 6, 4, 5);
        slow1 = simd_nan_guard_vec(buf, dbl, 2, bytes == 32u ? 6 : -1);
    }
    if (scalar) {
        emit_ins_elem(buf, dbl ? 3u : 2u, 0, 0, 2, 0);
        simd_store(buf, instr, 16u, 0, 0);
    } else {
        simd_store(buf, instr, bytes, 2, 6);
    }
    done = emit_b_deferred(buf);
    if (minmax) {
        patch_bcond(buf, slow1, 1, buf->size);
        patch_bcond(buf, slow2, 1, buf->size);
    } else if (nan_scalar) {
        patch_bcond(buf, slow1, HB_AC_VS, buf->size);
    } else {
        patch_cbz_x(buf, slow1, 20, buf->size);
    }
    emit_interp_ir_helper(buf, instr);
    patch_b(buf, done, buf->size);
    return simd_done(HB_SIMD_FAM_FP);
}

/* SQRT (все формы), RSQRT/RCP (интерпретатор считает ТОЧНО: 1/sqrtf(x), 1/x — не приближения x86;
 * повторяем его, а не железо). NaN в результате — помощник (знак «неопределённого», полезная нагрузка). */
static bool emit_simd_fp_sqrt(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const uint64_t t = instr->target;
    const unsigned lane = (unsigned)(t & 0xffu);
    const bool scalar = (t & 0x100u) != 0, dbl = lane == 8u;
    const uint32_t szb = NV_SZ(dbl ? 1u : 0u);
    unsigned bytes, h;
    size_t slow, done;
    if ((t & ~0x1ffull) != 0 || (lane != 4u && lane != 8u)) return false;
    if (instr->op != HB_IR_FSQRT && lane != 4u) return false;
    if (!simd_xreg(&instr->dst) || !simd_xreg(&instr->src1) || !simd_src_ok(buf, &instr->src2)) return false;
    bytes = scalar ? 16u : simd_bytes_of(instr->dst.size);
    if (!bytes) return false;
    if (scalar) {
        simd_load(buf, &instr->src2, lane, 1, 1);
        simd_load(buf, &instr->src1, 16u, 0, 0);
        if (instr->op == HB_IR_FSQRT) {
            nv2(buf, NS_FSQRT | szb, 2, 1);
        } else {
            nv(buf, 0x1e2e1000u | 3u);                                 /* FMOV S3, #1.0 */
            if (instr->op == HB_IR_FRSQRT) {
                nv2(buf, NS_FSQRT, 2, 1);
                nv3(buf, NS_FDIV, 2, 3, 2);
            } else {
                nv3(buf, NS_FDIV, 2, 3, 1);
            }
        }
        emit_fcmp_rr(buf, dbl, 2, 2);
        slow = emit_bcond_deferred(buf, HB_AC_VS);
        emit_ins_elem(buf, dbl ? 3u : 2u, 0, 0, 2, 0);
        simd_store(buf, instr, 16u, 0, 0);
        done = emit_b_deferred(buf);
        patch_bcond(buf, slow, HB_AC_VS, buf->size);
    } else {
        simd_load(buf, &instr->src2, bytes, 1, 5);
        if (instr->op != HB_IR_FSQRT) nv(buf, 0x4f03f600u | 3u);       /* FMOV V3.4S, #1.0 */
        for (h = 0; h < (bytes == 32u ? 2u : 1u); h++) {
            const int d = h ? 6 : 2, n = h ? 5 : 1;
            if (instr->op == HB_IR_FSQRT) {
                nv2(buf, NV_FSQRT | szb, d, n);
            } else if (instr->op == HB_IR_FRSQRT) {
                nv2(buf, NV_FSQRT, d, n);
                nv3(buf, NV_FDIV, d, 3, d);
            } else {
                nv3(buf, NV_FDIV, d, 3, n);
            }
        }
        slow = simd_nan_guard_vec(buf, dbl, 2, bytes == 32u ? 6 : -1);
        simd_store(buf, instr, bytes, 2, 6);
        done = emit_b_deferred(buf);
        patch_cbz_x(buf, slow, 20, buf->size);
    }
    emit_interp_ir_helper(buf, instr);
    patch_b(buf, done, buf->size);
    return simd_done(HB_SIMD_FAM_FP);
}

/* ROUNDPS/PD/SS/SD (все формы): режим imm&3 или MXCSR.RC при imm&4; DAZ|FTZ — помощник.
 * ★ Без флагов хозяина — договор tests/hb_round_instruction_test (категория host): эталон
 * hb_round_fp_bits чисто целочисленный, а FRINT взводит Invalid на сигнальном NaN. Поэтому дорожки-NaN
 * (модуль, сдвинутый влево, выше порога — ЦЕЛЫМ сравнением) обнуляются ДО FRINT, а в ответ идёт
 * исходный NaN с поднятым битом тишины — ровно как у hb_round_fp_bits. Других флагов FRINTN/M/P/Z
 * не дают (Inexact — только у FRINTX); сброс денормали (IDC) сюда не доходит: при DAZ|FTZ помощник.
 * Скаляр считается той же векторной формой: LDR S/D обнулил прочие дорожки V1. */
static bool emit_simd_fp_round(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const uint64_t t = instr->target;
    const unsigned lane = (unsigned)(t & 0xffu), imm = (unsigned)((t >> 16) & 0xffu);
    const bool scalar = (t & 0x100u) != 0, dbl = lane == 8u;
    const unsigned esize = dbl ? 64u : 32u, size = dbl ? 3u : 2u;
    unsigned bytes, cnt, h;
    size_t slow1, slow2, done;
    if ((t & 0xfe00ull) != 0 || (t >> 24) != 0 || (lane != 4u && lane != 8u)) return false;
    if (!simd_xreg(&instr->dst) || !simd_xreg(&instr->src1) || !simd_src_ok(buf, &instr->src2)) return false;
    bytes = scalar ? 16u : simd_bytes_of(instr->dst.size);
    if (!bytes) return false;
    cnt = (!scalar && bytes == 32u) ? 2u : 1u;
    if (scalar) {
        simd_load(buf, &instr->src2, lane, 1, 1);
        simd_load(buf, &instr->src1, 16u, 0, 0);
    } else {
        simd_load(buf, &instr->src2, bytes, 1, 5);
    }
    simd_mxcsr_daz_ftz_guard(buf, &slow1, &slow2);
    if (dbl) {
        emit_mov_imm_compact(buf, 20, 0xffe0000000000000ull);    /* порог NaN: exp=0x7ff, дробь != 0 */
        nv_dup_r(buf, 3u, 30, 20);
        emit_mov_imm_compact(buf, 20, 0x0008000000000000ull);    /* бит тишины */
        nv_dup_r(buf, 3u, 29, 20);
    } else {
        nv(buf, 0x4f0767e0u | 30u);                              /* MOVI V30.4S, #0xff, LSL #24 */
        nv(buf, 0x4f024400u | 29u);                              /* MOVI V29.4S, #0x40, LSL #16 */
    }
    for (h = 0; h < cnt; h++) {
        const int n = h ? 5 : 1, m = h ? 18 : 16, sfe = h ? 19 : 17;
        nv_shl(buf, esize, m, n, 1u);
        nv3(buf, 0x6e203400u | NV_SZ(size), m, m, 30);          /* CMHI: дорожка — NaN */
        nv3(buf, NV_BIC, sfe, n, m);                             /* NaN -> 0 до FRINT */
    }
    {
        const int dd[2] = { 2, 6 }, nn[2] = { 17, 19 };
        if (imm & 4u) {
            simd_frint_rc(buf, false, dbl, dd, nn, cnt);
        } else {
            for (h = 0; h < cnt; h++) simd_frint(buf, imm & 3u, false, dbl, dd[h], nn[h]);
        }
    }
    for (h = 0; h < cnt; h++) {
        const int n = h ? 5 : 1, m = h ? 18 : 16, d = h ? 6 : 2, q = h ? 7 : 3;
        nv3(buf, NV_ORR, q, n, 29);                              /* тихий NaN источника */
        nv3(buf, NV_BSL, m, q, d);                               /* m <- NaN ? тихий : округлённое */
    }
    if (scalar) {
        emit_ins_elem(buf, dbl ? 3u : 2u, 0, 0, 16, 0);
        simd_store(buf, instr, 16u, 0, 0);
    } else {
        simd_store(buf, instr, bytes, 16, 18);
    }
    done = emit_b_deferred(buf);
    patch_bcond(buf, slow1, 1, buf->size);
    patch_bcond(buf, slow2, 1, buf->size);
    emit_interp_ir_helper(buf, instr);
    patch_b(buf, done, buf->size);
    return simd_done(HB_SIMD_FAM_FP);
}

/* Предикат сравнения (интерпретатор, VEC_PACKED VCMP*: p и p+16 совпадают) на одной половине:
 * d <- маска; черновики V16, V17. «Неупорядочено» = ~(a==a & b==b). */
static void simd_fcmp_half(hb_codegen_buffer_t* buf, unsigned p, bool dbl, int d, int a, int b) {
    const uint32_t eq = NV_FCMEQ | NV_SZ(dbl ? 1u : 0u);
    const uint32_t ge = NV_FCMGE | NV_SZ(dbl ? 1u : 0u);
    const uint32_t gt = NV_FCMGT | NV_SZ(dbl ? 1u : 0u);
    switch (p & 15u) {
        case 0:  nv3(buf, eq, d, a, b); break;                                   /* EQ_OQ  */
        case 1:  nv3(buf, gt, d, b, a); break;                                   /* LT_OS  */
        case 2:  nv3(buf, ge, d, b, a); break;                                   /* LE_OS  */
        case 3:  nv3(buf, eq, 16, a, a); nv3(buf, eq, 17, b, b);                 /* UNORD  */
                 nv3(buf, NV_AND, 16, 16, 17); nv2(buf, NV_NOT, d, 16); break;
        case 4:  nv3(buf, eq, 16, a, b); nv2(buf, NV_NOT, d, 16); break;         /* NEQ_UQ */
        case 5:  nv3(buf, gt, 16, b, a); nv2(buf, NV_NOT, d, 16); break;         /* NLT_US */
        case 6:  nv3(buf, ge, 16, b, a); nv2(buf, NV_NOT, d, 16); break;         /* NLE_US */
        case 7:  nv3(buf, eq, 16, a, a); nv3(buf, eq, 17, b, b);                 /* ORD    */
                 nv3(buf, NV_AND, d, 16, 17); break;
        case 8:  nv3(buf, eq, 16, a, a); nv3(buf, eq, 17, b, b);                 /* EQ_UQ  */
                 nv3(buf, NV_AND, 16, 16, 17); nv3(buf, eq, 17, a, b);
                 nv3(buf, NV_BIC, 16, 16, 17); nv2(buf, NV_NOT, d, 16); break;
        case 9:  nv3(buf, ge, 16, a, b); nv2(buf, NV_NOT, d, 16); break;         /* NGE_US */
        case 10: nv3(buf, gt, 16, a, b); nv2(buf, NV_NOT, d, 16); break;         /* NGT_US */
        case 11: nv_movi0(buf, d); break;                                        /* FALSE  */
        case 12: nv3(buf, eq, 16, a, a); nv3(buf, eq, 17, b, b);                 /* NEQ_OQ */
                 nv3(buf, NV_AND, 16, 16, 17); nv3(buf, eq, 17, a, b);
                 nv3(buf, NV_BIC, d, 16, 17); break;
        case 13: nv3(buf, ge, d, a, b); break;                                   /* GE_OS  */
        case 14: nv3(buf, gt, d, a, b); break;                                   /* GT_OS  */
        default: nv(buf, NV_MOVIM1 | (uint32_t)d); break;                        /* TRUE   */
    }
}

/* VEC_PACKED VCMPPS/PD/SS/SD (и устаревшие CMPPS/…, их декодер x64 ведёт сюда же). Ширина — по
 * приёмнику, оба источника читаются ею же (у CMPSS с памятью интерпретатор читает 16 байт). */
static bool emit_simd_vcmp(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr, hb_ir_vec_op_t vop) {
    const bool dbl = vop == HB_VEC_VCMPPD || vop == HB_VEC_VCMPSD;
    const bool scalar = vop == HB_VEC_VCMPSS || vop == HB_VEC_VCMPSD;
    const unsigned pred = (unsigned)(instr->target & 31u);
    const unsigned bytes = simd_bytes_of(instr->dst.size);
    if (simd_evex(instr) || (instr->target & 0xffffff00ull & 0xffffffffull) != 0) return false;
    if (!bytes || !simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src1) || !simd_src_ok(buf, &instr->src2))
        return false;
    if (instr->src2.type == HB_OP_MEM) {
        simd_load(buf, &instr->src2, bytes, 1, 5);
        simd_load(buf, &instr->src1, bytes, 0, 4);
    } else {
        simd_load(buf, &instr->src1, bytes, 0, 4);
        simd_load(buf, &instr->src2, bytes, 1, 5);
    }
    simd_fcmp_half(buf, pred, dbl, 2, 0, 1);
    if (scalar) {
        emit_ins_elem(buf, dbl ? 3u : 2u, 0, 0, 2, 0);
        simd_store(buf, instr, 16u, 0, 0);
    } else {
        if (bytes == 32u) simd_fcmp_half(buf, pred, dbl, 6, 4, 5);
        simd_store(buf, instr, bytes, 2, 6);
    }
    return simd_done(HB_SIMD_FAM_FP);
}

/* CVTPS2DQ (по MXCSR.RC) / CVTTPS2DQ (усечение), 128/256: опасные дорожки |x| >= 2^31 и NaN —
 * «целое неопределённое» 0x80000000. Ближе к 2^31 float целые, так что FRINT за предел не выводит. */
static bool emit_simd_cvt_ps2dq(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const bool trunc = instr->op == HB_IR_CVTTPS2DQ;
    const unsigned bytes = simd_bytes_of(instr->dst.size);
    const unsigned cnt = bytes == 32u ? 2u : 1u;
    const int u[2] = { 17, 19 };
    unsigned h;
    if (instr->target != 0 || !bytes || !simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src1)) return false;
    simd_load(buf, &instr->src1, bytes, 1, 5);
    nv(buf, 0x4f0467c0u | 30u);                          /* MOVI V30.4S, #0x9e, LSL #24 = 2^31 << 1 */
    nv(buf, 0x4f046400u | 29u);                          /* MOVI V29.4S, #0x80, LSL #24 */
    for (h = 0; h < cnt; h++) {
        const int n = h ? 5 : 1, tm = h ? 18 : 16;
        nv_shl(buf, 32u, tm, n, 1u);                     /* модуль, сдвинутый влево */
        nv3(buf, NV_CMHS | NV_SZ(2), tm, tm, 30);        /* опасно: |x| >= 2^31, NaN, inf */
        nv3(buf, NV_BIC, u[h], n, tm);                   /* безопасное значение (опасные -> 0) */
    }
    if (trunc) {
        for (h = 0; h < cnt; h++) simd_frint(buf, 3u, false, false, u[h], u[h]);
    } else {
        emit_ldr_w(buf, 22, 19, (uint32_t)offsetof(hb_context_t, mxcsr));
        simd_frint_rc(buf, false, false, u, u, cnt);
    }
    for (h = 0; h < cnt; h++) {
        const int d = h ? 6 : 2, tm = h ? 18 : 16;
        nv2(buf, NV_FCVTZS | NV_SZ(0), d, u[h]);         /* точное целое в диапазоне: флагов нет */
        nv3(buf, NV_AND, tm, tm, 29);
        nv3(buf, NV_ORR, d, d, tm);
    }
    simd_store(buf, instr, bytes, 2, 6);
    return simd_done(HB_SIMD_FAM_FP);
}

/* CVTPD2DQ / CVTTPD2DQ: источник 16 или 32 байта (по ЕГО size), приёмник 16 байт, лишнее — нули.
 * У double до 2^31 округление может вывести ЗА предел (2147483647.5 -> 2^31), поэтому два шага:
 * |x| >= 2^32 и NaN обнуляются до FRINT, затем |r| >= 2^31 — после. */
static bool emit_simd_cvt_pd2dq(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const bool trunc = instr->op == HB_IR_CVTTPD2DQ;
    const unsigned src_bytes = instr->src1.size ? (unsigned)instr->src1.size : 16u;
    const unsigned cnt = src_bytes == 32u ? 2u : 1u;
    const int u[2] = { 17, 19 };
    unsigned h;
    if (instr->target != 0 || (src_bytes != 16u && src_bytes != 32u)) return false;
    if (!simd_xreg(&instr->dst) || !simd_src_ok(buf, &instr->src1)) return false;
    simd_load(buf, &instr->src1, src_bytes, 1, 5);
    emit_mov_imm_compact(buf, 20, 0x83e0000000000000ull);    /* 2^32 << 1 */
    nv_dup_r(buf, 3u, 30, 20);
    emit_mov_imm_compact(buf, 20, 0x83c0000000000000ull);    /* 2^31 << 1 */
    nv_dup_r(buf, 3u, 28, 20);
    for (h = 0; h < cnt; h++) {
        const int n = h ? 5 : 1, tm = h ? 18 : 16;
        nv_shl(buf, 64u, tm, n, 1u);
        nv3(buf, NV_CMHS | NV_SZ(3), tm, tm, 30);        /* |x| >= 2^32, NaN, inf */
        nv3(buf, NV_BIC, u[h], n, tm);
    }
    if (trunc) {
        for (h = 0; h < cnt; h++) simd_frint(buf, 3u, false, true, u[h], u[h]);
    } else {
        emit_ldr_w(buf, 22, 19, (uint32_t)offsetof(hb_context_t, mxcsr));
        simd_frint_rc(buf, false, true, u, u, cnt);
    }
    for (h = 0; h < cnt; h++) {
        const int tm = h ? 18 : 16;
        nv_shl(buf, 64u, 3, u[h], 1u);
        nv3(buf, NV_CMHS | NV_SZ(3), 3, 3, 28);          /* после округления |r| >= 2^31 */
        nv3(buf, NV_ORR, tm, tm, 3);
        nv3(buf, NV_BIC, u[h], u[h], tm);
        nv2(buf, NV_FCVTZS | NV_SZ(1), u[h], u[h]);      /* точное, в диапазоне int32 */
    }
    nv2(buf, NV_XTN | NV_SZ(2), 2, u[0]);                /* .2S; старшие 64 бита — нули */
    nv2(buf, NV_XTN | NV_SZ(2), 3, 16);
    if (cnt == 2u) {
        nv2(buf, NV_XTN | NV_SZ(2) | NV_Q, 2, u[1]);
        nv2(buf, NV_XTN | NV_SZ(2) | NV_Q, 3, 18);
    }
    nv(buf, 0x4f046400u | 29u);                          /* MOVI V29.4S, #0x80, LSL #24 */
    nv3(buf, NV_AND, 3, 3, 29);
    nv3(buf, NV_ORR, 2, 2, 3);
    simd_store(buf, instr, 16u, 2, 2);
    return simd_done(HB_SIMD_FAM_FP);
}

/* VEX-формы преобразований без целого приёмника (устаревшие выпускает emit_native_sse_fp):
 * CVTDQ2PS 128/256 (SCVTF по FPCR — как `(float)v`), CVTPS2PD и CVTDQ2PD (приёмник 16/32 из
 * половины его ширины), CVTPD2PS (источник 16/32 -> 16), скалярные трёхоперандные
 * CVTSS2SD/CVTSD2SS/CVTSI2SS/CVTSI2SD (младшая дорожка — преобразованное, остальное — src1). */
static bool emit_simd_fp_cvt_vex(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    if (!instr->zero_ymm_upper || instr->target != 0 || !simd_xreg(&instr->dst)) return false;
    switch (instr->op) {
        case HB_IR_CVTDQ2PS: {
            const unsigned bytes = simd_bytes_of(instr->dst.size);
            if (!bytes || !simd_src_ok(buf, &instr->src1)) return false;
            simd_load(buf, &instr->src1, bytes, 1, 5);
            nv2(buf, NV_SCVTF | NV_SZ(0), 2, 1);
            if (bytes == 32u) nv2(buf, NV_SCVTF | NV_SZ(0), 6, 5);
            simd_store(buf, instr, bytes, 2, 6);
            return simd_done(HB_SIMD_FAM_FP);
        }
        case HB_IR_CVTPS2PD: case HB_IR_CVTDQ2PD: {
            const unsigned bytes = simd_bytes_of(instr->dst.size);
            const bool from_int = instr->op == HB_IR_CVTDQ2PD;
            if (!bytes || !simd_src_ok(buf, &instr->src1)) return false;
            simd_load(buf, &instr->src1, bytes / 2u, 1, 1);
            if (from_int) {
                nv2(buf, 0x0f20a400u, 2, 1);             /* SXTL  V2.2D, V1.2S */
                nv2(buf, NV_SCVTF | NV_SZ(1), 2, 2);
                if (bytes == 32u) {
                    nv2(buf, 0x4f20a400u, 6, 1);         /* SXTL2 V6.2D, V1.4S */
                    nv2(buf, NV_SCVTF | NV_SZ(1), 6, 6);
                }
            } else {
                nv2(buf, 0x0e617800u, 2, 1);             /* FCVTL  V2.2D, V1.2S */
                if (bytes == 32u) nv2(buf, 0x4e617800u, 6, 1);   /* FCVTL2 V6.2D, V1.4S */
            }
            simd_store(buf, instr, bytes, 2, 6);
            return simd_done(HB_SIMD_FAM_FP);
        }
        case HB_IR_CVTPD2PS: {
            const unsigned src_bytes = instr->src1.size ? (unsigned)instr->src1.size : 16u;
            if ((src_bytes != 16u && src_bytes != 32u) || !simd_src_ok(buf, &instr->src1)) return false;
            simd_load(buf, &instr->src1, src_bytes, 1, 5);
            nv2(buf, 0x0e616800u, 2, 1);                 /* FCVTN V2.2S, V1.2D; верх 64 = 0 */
            if (src_bytes == 32u) nv2(buf, 0x4e616800u, 2, 5);   /* FCVTN2 V2.4S, V5.2D */
            simd_store(buf, instr, 16u, 2, 2);
            return simd_done(HB_SIMD_FAM_FP);
        }
        case HB_IR_CVTSS2SD: case HB_IR_CVTSD2SS: {
            const bool from_d = instr->op == HB_IR_CVTSD2SS;
            if (instr->src2.type == HB_OP_NONE || !simd_xreg(&instr->src1) || !simd_src_ok(buf, &instr->src2))
                return false;
            simd_load(buf, &instr->src2, from_d ? 8u : 4u, 1, 1);
            simd_load(buf, &instr->src1, 16u, 0, 0);
            nv2(buf, from_d ? 0x1e624000u : 0x1e22c000u, 2, 1);          /* FCVT S2,D1 | D2,S1 */
            emit_ins_elem(buf, from_d ? 2u : 3u, 0, 0, 2, 0);
            simd_store(buf, instr, 16u, 0, 0);
            return simd_done(HB_SIMD_FAM_FP);
        }
        case HB_IR_CVTSI2SS: case HB_IR_CVTSI2SD: {
            const bool to_d = instr->op == HB_IR_CVTSI2SD;
            const hb_ir_operand_t* s = &instr->src2;
            const bool src64 = s->size == HB_SIZE_64;
            if (s->type == HB_OP_NONE || !simd_xreg(&instr->src1)) return false;
            if (s->size != HB_SIZE_32 && !src64) return false;
            if (is_gpr_reg_operand(s)) {
                if (!emit_load_gpr_sized_to_x20(buf, s)) return false;
            } else if (s->type == HB_OP_MEM && jit_direct_mem_codegen_enabled(buf) &&
                       !diag_no_scalar_dload() && direct_user_mem_load_allowed(buf, s)) {
                unsigned char prev_stack = hb_emit_mark_stack_access(s);
                emit_direct_mem_addr(buf, s);
                emit_direct_mem_load_to_x20(buf, src64 ? HB_SIZE_64 : HB_SIZE_32);
                hb_emit_restore_stack_access(prev_stack);
                jit_native_mem_count(0);
            } else {
                return false;
            }
            emit_ldr_q(buf, 0, 19, xmm_reg_off(buf, instr->src1.reg));
            nv(buf, (src64 ? 0x9e220000u : 0x1e220000u) | (to_d ? 0x00400000u : 0u) |
                    ((uint32_t)hb_rm(buf, 20) << 5) | 2u);                /* SCVTF S|D2, W|X20 */
            emit_ins_elem(buf, to_d ? 3u : 2u, 0, 0, 2, 0);
            simd_store(buf, instr, 16u, 0, 0);
            return simd_done(HB_SIMD_FAM_FP);
        }
        default:
            return false;
    }
}

/* CVTSS2SI / CVTSD2SI (округление по MXCSR.RC) в GPR 32/64, все формы (VEX тоже: приёмник не вектор).
 * Интерпретатор: не конечное -> «целое неопределённое»; иначе hb_round_by_rc и проверка диапазона.
 * Без флагов хозяина (договор tests/hb_sse_integer_rounding_test), как CVTT в emit_native_sse_fp:
 * опасное значение до FRINT заменяется нулём (FCSEL), FCVTZS видит только целое в диапазоне.
 * Предел до FRINT — 2^31 (float->i32), 2^63 (->i64): ближе к ним float/double целые, округление за
 * предел не выводит. У double->i32 выводит (2147483647.5 -> 2^31), там предел 2^32 и проверка после. */
static bool emit_simd_cvt_si(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    const bool dbl = instr->op == HB_IR_CVTSD2SI;
    const bool w64 = instr->dst.size == HB_SIZE_64;
    const unsigned bytes = dbl ? 8u : 4u;
    const uint64_t limit = dbl ? (w64 ? 0x43e0000000000000ull : 0x41f0000000000000ull)
                               : (w64 ? 0x5f000000ull : 0x4f000000ull);
    const int one[1] = { 1 };
    int k1;
    if (!is_gpr_reg_operand(&instr->dst) || (instr->dst.size != HB_SIZE_32 && !w64)) return false;
    k1 = sse_fp_src_kind(buf, &instr->src1, bytes);
    if (!k1) return false;
    emit_sse_fp_src(buf, &instr->src1, k1, bytes, 0);                /* V0 = x */
    if (dbl) {
        emit_gpr_word(buf, 0x9e660000u, 21, 0, 0);                   /* FMOV X21, D0 */
        emit_and_imm64(buf, 22, 21, 0x7fffffffffffffffull);
        nv(buf, 0x9e6703e0u | 3u);                                    /* FMOV D3, XZR */
    } else {
        emit_gpr_word(buf, 0x1e260000u, 21, 0, 0);                   /* FMOV W21, S0 */
        emit_and_imm64(buf, 22, 21, 0x7fffffffull);
        nv(buf, 0x1e2703e0u | 3u);                                    /* FMOV S3, WZR */
    }
    emit_mov_imm_compact(buf, 23, limit);
    emit_gpr_word(buf, 0xeb00001fu, 31, 22, 23);                      /* CMP X22, X23: LO — безопасно */
    emit_fcsel(buf, dbl, 1, 0, 3, 3 /* LO */);
    emit_cset_w(buf, 20, 2 /* HS */);                                 /* W20 = опасно */
    emit_ldr_w(buf, 22, 19, (uint32_t)offsetof(hb_context_t, mxcsr));
    simd_frint_rc(buf, true, dbl, one, one, 1u);                      /* S1|D1 целое */
    if (dbl && !w64) {                                                /* округление вывело за 2^31? */
        emit_gpr_word(buf, 0x9e660000u, 21, 1, 0);                   /* FMOV X21, D1 */
        emit_and_imm64(buf, 22, 21, 0x7fffffffffffffffull);
        emit_mov_imm_compact(buf, 23, 0x41e0000000000000ull);
        emit_gpr_word(buf, 0xeb00001fu, 31, 22, 23);
        emit_fcsel(buf, true, 1, 1, 3, 3 /* LO */);
        emit_cset_w(buf, 21, 2 /* HS */);
        emit_orr_reg(buf, 20, 20, 21);
    }
    nv(buf, (w64 ? (dbl ? 0x9e780000u : 0x9e380000u) : (dbl ? 0x1e780000u : 0x1e380000u)) |
            (1u << 5) | (uint32_t)hb_rm(buf, 22));                    /* FCVTZS W|X22, S1|D1 */
    emit_mov_imm_compact(buf, 23, w64 ? 0x8000000000000000ull : 0x80000000ull);
    emit_cmp_imm(buf, 20, 0);
    emit_gpr_word(buf, 0x9a800000u | (0u << 12), 20, 22, 23);        /* CSEL X20, X22, X23, EQ */
    if (simd_test_flip()) emit_eor_imm64(buf, 20, 20, 1);
    emit_store_x20_to_gpr_sized(buf, &instr->dst);
    return simd_done(HB_SIMD_FAM_FP);
}

static bool emit_simd_fp(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    switch (instr->op) {
        case HB_IR_FADD: case HB_IR_FSUB: case HB_IR_FMUL: case HB_IR_FDIV:
        case HB_IR_FMIN: case HB_IR_FMAX:
            return emit_simd_fp_arith(buf, instr);
        case HB_IR_FSQRT: case HB_IR_FRSQRT: case HB_IR_FRCP:
            return emit_simd_fp_sqrt(buf, instr);
        case HB_IR_FROUND:
            return emit_simd_fp_round(buf, instr);
        case HB_IR_CVTPS2DQ: case HB_IR_CVTTPS2DQ:
            return emit_simd_cvt_ps2dq(buf, instr);
        case HB_IR_CVTPD2DQ: case HB_IR_CVTTPD2DQ:
            return emit_simd_cvt_pd2dq(buf, instr);
        case HB_IR_CVTSS2SI: case HB_IR_CVTSD2SI:
            return emit_simd_cvt_si(buf, instr);
        case HB_IR_CVTDQ2PS: case HB_IR_CVTPS2PD: case HB_IR_CVTDQ2PD: case HB_IR_CVTPD2PS:
        case HB_IR_CVTSS2SD: case HB_IR_CVTSD2SS: case HB_IR_CVTSI2SS: case HB_IR_CVTSI2SD:
            return emit_simd_fp_cvt_vex(buf, instr);
        default:
            return false;
    }
}

/* ═══ ВХОД: одна точка на все три семьи. Зовётся ПОСЛЕ прежних нативных выпусков (они сохраняют
 * свои формы и свои гейты) и ПЕРЕД уходом в помощника. true — команда выпущена целиком. ═══ */
static bool emit_native_simd(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {
    if (!buf || !instr || buf->arch != HB_ARCH_X64) return false;
    switch (instr->op) {
        case HB_IR_MOV: case HB_IR_XMM_QWORD_LANE_MOV: case HB_IR_XMM_SCALAR_MOV:
        case HB_IR_VZEROUPPER: case HB_IR_VZEROALL: case HB_IR_MOVDUP:
            return native_xmm_moves_enabled() && emit_simd_moves(buf, instr);
        case HB_IR_VEC_PACKED: {
            const hb_ir_vec_op_t vop = (hb_ir_vec_op_t)(instr->target >> 32);
            switch (vop) {
                case HB_VEC_VINSERTF128: case HB_VEC_VINSERTI128:
                case HB_VEC_VEXTRACTF128: case HB_VEC_VEXTRACTI128:
                case HB_VEC_VPERM2F128: case HB_VEC_VPERM2I128:
                    return native_xmm_moves_enabled() && emit_simd_lane128(buf, instr, vop);
                case HB_VEC_VMOVDDUP: case HB_VEC_VMOVSLDUP: case HB_VEC_VMOVSHDUP:
                case HB_VEC_VPBROADCASTB: case HB_VEC_VPBROADCASTW: case HB_VEC_VPBROADCASTD:
                case HB_VEC_VPBROADCASTQ: case HB_VEC_VBROADCASTSS: case HB_VEC_VBROADCASTSD:
                case HB_VEC_VBROADCASTI128: case HB_VEC_VBROADCASTF32X4:
                    return native_xmm_moves_enabled() && emit_simd_dup(buf, instr, vop);
                case HB_VEC_VCMPPS: case HB_VEC_VCMPPD: case HB_VEC_VCMPSS: case HB_VEC_VCMPSD:
                    return native_simd_fp_enabled() && emit_simd_vcmp(buf, instr, vop);
                default:
                    return native_simd_int_enabled() && emit_simd_int_binop(buf, instr);
            }
        }
        case HB_IR_PADD: case HB_IR_PSUB: case HB_IR_PUNPCK:
        case HB_IR_XMM_AND: case HB_IR_XMM_ANDN: case HB_IR_XMM_OR: case HB_IR_XORPS:
        case HB_IR_PCMPEQB: case HB_IR_PCMPEQW: case HB_IR_PCMPEQD:
        case HB_IR_PCMPGTB: case HB_IR_PCMPGTW: case HB_IR_PCMPGTD:
        case HB_IR_PADDSB: case HB_IR_PADDSW: case HB_IR_PADDUSB: case HB_IR_PADDUSW:
        case HB_IR_PSUBSB: case HB_IR_PSUBSW: case HB_IR_PSUBUSB: case HB_IR_PSUBUSW:
        case HB_IR_PAVGB: case HB_IR_PAVGW: case HB_IR_PSADBW:
        case HB_IR_PMULLW: case HB_IR_PMULHW: case HB_IR_PMULHUW: case HB_IR_PMADDWD:
        case HB_IR_PACKSSWB: case HB_IR_PACKUSWB: case HB_IR_PACKSSDW:
            return native_simd_int_enabled() && emit_simd_int_binop(buf, instr);
        case HB_IR_PSRL: case HB_IR_PSRA: case HB_IR_PSLL:
        case HB_IR_PSRLQ: case HB_IR_PSLLQ: case HB_IR_PSRLDQ: case HB_IR_PSLLDQ:
            return native_simd_int_enabled() && emit_simd_shift(buf, instr);
        case HB_IR_PMOVMSKB: case HB_IR_MOVMSK:
            return native_simd_int_enabled() && emit_simd_movmsk(buf, instr);
        default:
            return native_simd_fp_enabled() && emit_simd_fp(buf, instr);
    }
}
