#ifndef HB_LIFTER_H
#define HB_LIFTER_H

#include "hb_result.h"
#include "hb_ir.h"
#include "hb_decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

hb_result_t hb_lift_x64(const hb_decoded_t* dec, hb_ir_builder_t* b);
hb_result_t hb_lift_x86(const hb_decoded_t* dec, hb_ir_builder_t* b);

/* Продлевать ли единицу трансляции за этот условный переход. Одно правило на обе ветви —
 * разбор у определения в hb_lift_x86.c. Гейт MACRUNNER_HB_MERGE_BLOCKS, умолчание ВЫКЛ. */
int hb_lift_edinica_prodlit(const hb_decoder_t* dec, const hb_decoded_t* d, size_t merged);

/* Кончается ли единица трансляции на этой команде, хотя она не переход: сериализующая команда
 * (CPUID). Самоизменённые байты за ней обязаны читаться заново (Intel SDM т. 3A §9.1.3).
 * Одно правило на обе ветви — разбор у определения в hb_lift_x86.c. */
int hb_lift_edinica_serializing(const hb_decoded_t* d);

hb_result_t hb_lift_func_x64(hb_decoder_t* dec, hb_ir_func_t** out);
/* Lift exactly one COMPLETE x64 decoded instruction. Caller supplies the
 * decoded value from a successful decoder probe; no further byte is read.
 * Output is published only on success, with explicit unit metadata retained
 * even if the instruction emits no IR. No successor is decoded or merged. */
hb_result_t hb_lift_unit_x64(const hb_decoded_t* dec, hb_ir_func_t** out);
hb_result_t hb_lift_func_x86(hb_decoder_t* dec, hb_ir_func_t** out);

#ifdef __cplusplus
}
#endif

#endif
