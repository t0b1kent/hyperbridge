#include "hb_lifter.h"
#include "hb_ir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hb_lift_source.h"

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); } } while(0)

static void lifted(hb_arch_t arch, const uint8_t* bytes, size_t n, int enabled) {
    uint8_t code[4096]; memset(code, 0xcc, sizeof(code)); memcpy(code, bytes, n);
    hb_decoder_t* d = hb_decoder_create(arch, code, sizeof(code), 0x100000);
    hb_ir_func_t* f = NULL;
    hb_result_t r = arch == HB_ARCH_X64 ? hb_lift_func_x64(d, &f) : hb_lift_func_x86(d, &f);
    CHECK(r == HB_OK && f);
    if (f) {
        CHECK(f->guest_len == sizeof(code));
        CHECK(d->code == code);
        CHECK(d->pos >= n && d->pos <= sizeof(code));
        CHECK(enabled ? f->decoded_source != NULL : f->decoded_source == NULL);
        if (f->decoded_source) {
            CHECK(f->decoded_source_len == d->pos);
            CHECK(memcmp(f->decoded_source, code, d->pos) == 0);
            CHECK(f->decoded_source_len < 4096);
            uint8_t first = f->decoded_source[0]; code[0] ^= 0xff;
            CHECK(f->decoded_source[0] == first);
            for (size_t b = 0; b < f->cfg->block_count; b++)
                for (size_t i = 0; i < f->cfg->blocks[b]->instr_count; i++) {
                    hb_ir_instr_t* in = &f->cfg->blocks[b]->instrs[i];
                    CHECK(in->guest_addr >= f->guest_addr &&
                          in->guest_addr - f->guest_addr + in->guest_len <= f->decoded_source_len);
                }
        }
        hb_ir_func_destroy(f);
    }
    hb_decoder_destroy(d);
}

int main(void) {
    int enabled = hb_gate_flag(HB_GATE_HB_DECODED_SOURCE, 0);
    const uint8_t ret[] = {0xc3};
    const uint8_t movret[] = {0xb8, 0x34, 0x12, 0, 0, 0xc3};
    const uint8_t call[] = {0xe8, 0x00, 0x01, 0, 0};
    const uint8_t nops[] = {0x90,0x90,0x90,0xc3};
    const uint8_t merge[] = {0x75,0x05,0xb8,0x78,0x56,0,0,0xc3};
    for (int a = 0; a < 2; a++) {
        hb_arch_t arch = a ? HB_ARCH_X64 : HB_ARCH_X86;
        lifted(arch, ret, sizeof(ret), enabled);
        lifted(arch, movret, sizeof(movret), enabled);
        lifted(arch, call, sizeof(call), enabled);
        lifted(arch, nops, sizeof(nops), enabled);
        if (getenv("MACRUNNER_HB_MERGE_BLOCKS") && getenv("MACRUNNER_HB_MERGE_BLOCKS")[0]=='1')
            lifted(arch, merge, sizeof(merge), enabled);
    }
    /* Deterministic mutation AFTER freeze but BEFORE decode. The generated IR
     * must use the old immutable bytes; neither a post-decode copy nor merely
     * retaining the caller pointer can satisfy this test. */
    uint8_t bytes[] = {0xb8,0x34,0x12,0,0,0xc3};
    hb_decoder_t d = {.arch=HB_ARCH_X64,.code=bytes,.code_len=sizeof(bytes),.base_addr=0x100000};
    hb_ir_func_t* f = hb_ir_func_create(d.base_addr,d.code_len);
    const uint8_t* original = hb_lift_source_begin(f,&d);
    bytes[1] = 0x78;
    hb_decoded_t decoded; CHECK(hb_decode_next(&d,&decoded)==HB_OK);
    CHECK(decoded.op2.imm == (enabled ? 0x1234 : 0x1278));
    hb_lift_source_end(f,&d,original);
    CHECK(d.code == bytes);
    if (enabled) CHECK(f->decoded_source_len==5 && f->decoded_source[1]==0x34);
    hb_ir_func_destroy(f);
    /* Untagged custom starts and over-limit windows cannot claim provenance. */
    uint8_t large[4097]={0};
    d.code=large;d.code_len=sizeof(large);d.pos=0;
    f=hb_ir_func_create(d.base_addr,d.code_len);original=hb_lift_source_begin(f,&d);
    CHECK(!f->decoded_source && d.code==large);hb_lift_source_end(f,&d,original);hb_ir_func_destroy(f);
    d.code=bytes;d.code_len=sizeof(bytes);d.pos=1;
    f=hb_ir_func_create(d.base_addr,d.code_len);original=hb_lift_source_begin(f,&d);
    CHECK(!f->decoded_source && d.code==bytes);hb_lift_source_end(f,&d,original);hb_ir_func_destroy(f);
    printf("source03 checks=%u failures=%u source=%d\n",checks,failures,enabled);
    return failures ? 1 : 0;
}
