/* Inline acceptance uses no C calls, no permission-table walk and no flags/FP
 * state changes. All caller-saved registers are dead at the frame48 boundary.
 * Low D8-D15 and all host callee-saved registers are untouched. */
static void native_entry_emit_imm(hb_codegen_buffer_t *b, unsigned reg, uint64_t value) {
    for (unsigned hw = 0; hw != 4; ++hw)
        emit_u32(b, (hw ? 0xf2800000u | (hw << 21) : 0xd2800000u) |
                    ((uint32_t)((value >> (hw * 16)) & 0xffffu) << 5) | reg);
}

static void native_entry_patch_branch(hb_codegen_buffer_t *b, size_t at, size_t to,
                                      unsigned reg, bool conditional) {
    int64_t words = ((int64_t)to - (int64_t)at) / 4;
    uint32_t word = conditional ? 0xb5000000u | (((uint32_t)words & 0x7ffffu) << 5) | reg
                                : 0x14000000u | ((uint32_t)words & 0x3ffffffu);
    memcpy(b->code + at, &word, sizeof(word));
}

static uint64_t native_entry_prefix_hash(const uint8_t *p, size_t len) {
    uint64_t h = UINT64_C(1469598103934665603);
    while (len--) h = (h ^ *p++) * UINT64_C(1099511628211);
    return h;
}

static void emit_native_entry_guard(hb_codegen_buffer_t *b) {
    hb_native_entry_descriptor_t *d = (hb_native_entry_descriptor_t *)b->native_entry_desc;
    size_t state_br[12], byte_br[5], contract_br[2], ns = 0, nb = 0;
    if (!d) return;
    b->native_entry_guard_off = (uint32_t)b->size;
    d->load_count = 0;
    native_entry_emit_imm(b, 10, (uint64_t)(uintptr_t)d->context_slot);
    emit_u32(b, 0xc8dffd49u); /* LDAR X9,[X10] */
    emit_u32(b, 0xca130129u); /* EOR X9,X9,X19; does not set NZCV */
    contract_br[0] = b->size; emit_u32(b, 0);
    _Static_assert(offsetof(hb_context_t, memory) % 8 == 0 &&
                   offsetof(hb_context_t, memory) < 32768, "memory identity LDR offset");
    emit_u32(b, 0xf9400000u | ((uint32_t)(offsetof(hb_context_t, memory) / 8) << 10) |
                (19u << 5) | 9u);
    native_entry_emit_imm(b, 11, (uint64_t)(uintptr_t)d->memory);
    emit_u32(b, 0xca0b0129u);
    contract_br[1] = b->size; emit_u32(b, 0);

    for (unsigned pass = 0; pass != 2; ++pass) {
        if (pass) emit_u32(b, 0xd50339bfu); /* DMB ISHLD: bytes before ALL postchecks */
        native_entry_emit_imm(b, 10, (uint64_t)(uintptr_t)&d->live);
        emit_u32(b, 0x88dffd49u); /* LDAR W9,[X10] */
        emit_u32(b, 0x5280002bu); /* MOV W11,#1 */
        emit_u32(b, 0x4a0b0129u); /* EOR W9,W9,W11 */
        state_br[ns++] = b->size; emit_u32(b, 0);
        native_entry_emit_imm(b, 10, (uint64_t)(uintptr_t)d->invalidation_current);
        emit_u32(b, 0xc8dffd49u);
        native_entry_emit_imm(b, 10, (uint64_t)(uintptr_t)d->invalidation_seen);
        emit_u32(b, 0xc8dffd4bu); /* LDAR X11,[X10] */
        emit_u32(b, 0xca0b0129u);
        state_br[ns++] = b->size; emit_u32(b, 0);
        for (unsigned page = 0; page != d->page_count; ++page) {
            native_entry_emit_imm(b, 10, (uint64_t)(uintptr_t)&d->pages[page]->state);
            emit_u32(b, 0xc8dffd49u);
            native_entry_emit_imm(b, 11, d->expected[page]);
            emit_u32(b, 0xca0b0129u);
            state_br[ns++] = b->size; emit_u32(b, 0);
        }
        if (pass) break;
        native_entry_emit_imm(b, 12, d->span_start);
        native_entry_emit_imm(b, 13, (uint64_t)(uintptr_t)d->bytes);
        size_t chunks = d->span_len / 16, tail = d->span_len % 16;
        if (chunks) {
            native_entry_emit_imm(b, 14, chunks);
            size_t loop = b->size;
            d->load_offsets[d->load_count] = (uint32_t)b->size;
            d->load_widths[d->load_count++] = 16;
            emit_u32(b, 0x3dc00180u); /* LDR Q0,[X12] -- validation fault site */
            emit_u32(b, 0x3dc001a1u); /* LDR Q1,[X13] -- owned immutable bytes */
            emit_u32(b, 0x6e211c02u); /* EOR V2.16B,V0.16B,V1.16B */
            emit_u32(b, 0x4e083c49u); /* UMOV X9,V2.D[0] */
            emit_u32(b, 0x4e183c4au); /* UMOV X10,V2.D[1] */
            emit_u32(b, 0xaa0a0129u); /* ORR X9,X9,X10 */
            byte_br[nb++] = b->size; emit_u32(b, 0);
            emit_u32(b, 0x9100418cu); /* ADD X12,X12,#16 */
            emit_u32(b, 0x910041adu); /* ADD X13,X13,#16 */
            emit_u32(b, 0xd10005ceu); /* SUB X14,X14,#1; no flags */
            size_t back = b->size; emit_u32(b, 0);
            native_entry_patch_branch(b, back, loop, 14, true);
        }
        for (unsigned width = 8; width; width >>= 1) {
            if (!(tail & width)) continue;
            uint32_t op = width == 8 ? 0xf9400000u : width == 4 ? 0xb9400000u :
                          width == 2 ? 0x79400000u : 0x39400000u;
            d->load_offsets[d->load_count] = (uint32_t)b->size;
            d->load_widths[d->load_count++] = (uint8_t)width;
            emit_u32(b, op | (12u << 5) | 9u);
            emit_u32(b, op | (13u << 5) | 10u);
            emit_u32(b, 0xca0a0129u); /* EOR X9,X9,X10 */
            byte_br[nb++] = b->size; emit_u32(b, 0);
            emit_u32(b, 0x91000000u | (width << 10) | (12u << 5) | 12u);
            emit_u32(b, 0x91000000u | (width << 10) | (13u << 5) | 13u);
        }
    }
    size_t accept_branch = b->size; emit_u32(b, 0);
    size_t state_label = b->size; emit_u32(b, 0x52800022u); /* W2=STATE */
    size_t state_join = b->size; emit_u32(b, 0);
    size_t bytes_label = b->size; emit_u32(b, 0x52800042u); /* W2=BYTES */
    size_t bytes_join = b->size; emit_u32(b, 0);
    size_t contract_label = b->size; emit_u32(b, 0x52800082u); /* W2=CONTRACT */
    size_t reject = b->size;
    /* Cold C call only: retain ambient guest FP mode/status and flags even if
     * a future rejection diagnostic uses caller-clobbered FP instructions. */
    emit_u32(b, 0xd53b4211u);
    emit_u32(b, 0xd53b440fu);
    emit_u32(b, 0xd53b442eu);
    emit_u32(b, 0xa9be7bf1u);
    emit_u32(b, 0xa9013befu);
    emit_u32(b, 0xaa1303e0u); /* X0=ctx */
    native_entry_emit_imm(b, 1, (uint64_t)(uintptr_t)d);
    native_entry_emit_imm(b, 16, (uint64_t)(uintptr_t)hb_native_entry_guard);
    b->native_entry_guard_call_off = (uint32_t)b->size;
    emit_blr(b, 16); /* cold rejection only: no reclamation here */
    emit_u32(b, 0xa9413befu);
    emit_u32(b, 0xa8c27bf1u);
    emit_u32(b, 0xd51b440fu);
    emit_u32(b, 0xd51b442eu);
    emit_u32(b, 0xd51b4211u);
    emit_u32(b, 0xa9427bf7u);
    emit_u32(b, 0xa9415bf5u);
    emit_u32(b, 0xa8c353f3u);
    emit_ret(b);
    size_t accept = b->size;
    emit_u32(b, 0xaa1303e0u); /* Raw MOV: chained X0 was arbitrary. */
    for (size_t i = 0; i < ns; ++i) native_entry_patch_branch(b, state_br[i], state_label, 9, true);
    for (size_t i = 0; i < nb; ++i) native_entry_patch_branch(b, byte_br[i], bytes_label, 9, true);
    for (unsigned i = 0; i < 2; ++i) native_entry_patch_branch(b, contract_br[i], contract_label, 9, true);
    native_entry_patch_branch(b, accept_branch, accept, 0, false);
    native_entry_patch_branch(b, state_join, reject, 0, false);
    native_entry_patch_branch(b, bytes_join, reject, 0, false);
    b->x0_holds_ctx = ctx_arg_reuse_enabled() ? 1 : 0;
    b->native_entry_guard_continue_off = (uint32_t)b->size;
    b->native_entry_guard_emitted = 1;
    d->emitted_hash = native_entry_prefix_hash(b->code, b->size);
}
