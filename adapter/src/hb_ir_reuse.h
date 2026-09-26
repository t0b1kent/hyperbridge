#ifndef HB_IR_REUSE_H
#define HB_IR_REUSE_H

#include <stdint.h>
#include <string.h>
#include "hb_lifter.h"

/* One invocation owns the table and every lifted function. The caller must
 * freshly fetch/decode/classify first, and may execute only while borrowed.
 * No guest permission, context, callback or decoder pointer is retained.
 * create/destroy must not reenter this table; nested invocations own separate
 * tables. The decoded value must come from these same freshly fetched bytes. */
#define HB_IR_REUSE_SLOTS 64u
typedef hb_result_t (*hb_ir_reuse_create_fn)(void *, const hb_decoded_t *, hb_ir_func_t **);
typedef void (*hb_ir_reuse_destroy_fn)(void *, hb_ir_func_t *);

struct hb_ir_reuse_entry {
    uint64_t pc;
    uint8_t length;
    uint8_t bytes[15];
    hb_ir_func_t *func;
};

struct hb_ir_reuse_table {
    struct hb_ir_reuse_entry entries[HB_IR_REUSE_SLOTS];
    const hb_ir_func_t *borrowed;
    uint64_t hits, misses, creates, destroys;
};

static int hb_ir_reuse_valid_unit(const hb_ir_func_t *func, uint64_t pc, uint8_t length)
{
    return func && func->cfg && func->cfg->blocks && func->cfg->block_count == 1 &&
           func->cfg->block_cap >= 1 && func->cfg->entry &&
           func->cfg->blocks[0] == func->cfg->entry && !func->truncated &&
           !func->has_unsupported && func->guest_addr == pc && func->guest_len == length &&
           hb_ir_is_exec_unit(func->cfg->entry) &&
           func->cfg->entry->exec_unit_pc == pc && func->cfg->entry->exec_unit_size == length;
}

static hb_result_t hb_ir_reuse_acquire(struct hb_ir_reuse_table *table,
                                      uint64_t pc, const uint8_t *bytes, size_t length,
                                      const hb_decoded_t *decoded,
                                      hb_ir_reuse_create_fn create,
                                      hb_ir_reuse_destroy_fn destroy, void *user,
                                      const hb_ir_func_t **out)
{
    struct hb_ir_reuse_entry *entry;
    hb_ir_func_t *fresh = NULL;
    hb_result_t result;
    if (!table || !bytes || !decoded || !create || !destroy || !out ||
        table->borrowed || !length || length > 15 || pc > UINT64_MAX - length ||
        decoded->addr != pc || decoded->len != length)
        return HB_ERR_INVALID_ARG;
    /* The index is only a placement policy. Every hit compares the full key. */
    entry = &table->entries[pc & (HB_IR_REUSE_SLOTS - 1u)];
    if (entry->func && entry->pc == pc && entry->length == length &&
        !memcmp(entry->bytes, bytes, length)) {
        if (!hb_ir_reuse_valid_unit(entry->func, pc, (uint8_t)length))
            return HB_ERR_INVALID_ARG;
        table->hits++;
    } else {
        table->misses++;
        result = create(user, decoded, &fresh);
        if (result != HB_OK || !hb_ir_reuse_valid_unit(fresh, pc, (uint8_t)length)) {
            if (fresh) { destroy(user, fresh); table->destroys++; }
            return result != HB_OK ? result : HB_ERR_INVALID_ARG;
        }
        table->creates++;
        /* Keep the previous entry on lift/allocation failure. No entry is
         * replaced while borrowed; creation completes before old ownership ends. */
        if (entry->func) { destroy(user, entry->func); table->destroys++; }
        memset(entry, 0, sizeof(*entry));
        entry->pc = pc;
        entry->length = (uint8_t)length;
        memcpy(entry->bytes, bytes, length);
        entry->func = fresh;
    }
    table->borrowed = entry->func;
    *out = entry->func;
    return HB_OK;
}

static hb_result_t hb_ir_reuse_release(struct hb_ir_reuse_table *table,
                                      const hb_ir_func_t *func)
{
    if (!table || !func || table->borrowed != func) return HB_ERR_INVALID_ARG;
    table->borrowed = NULL;
    return HB_OK;
}

/* Teardown ends the invocation, including a stopped/pending/error execution.
 * No borrowed pointer may be used after this call. Repeated teardown is safe. */
static void hb_ir_reuse_clear(struct hb_ir_reuse_table *table,
                              hb_ir_reuse_destroy_fn destroy, void *user)
{
    size_t i;
    if (!table || !destroy) return;
    table->borrowed = NULL;
    for (i = 0; i < HB_IR_REUSE_SLOTS; ++i) {
        hb_ir_func_t *func = table->entries[i].func;
        memset(&table->entries[i], 0, sizeof(table->entries[i]));
        if (func) { destroy(user, func); table->destroys++; }
    }
}

#endif
