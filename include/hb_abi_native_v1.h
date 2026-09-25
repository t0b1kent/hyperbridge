#ifndef HB_ABI_NATIVE_V1_H
#define HB_ABI_NATIVE_V1_H

#include "hb_context.h"
#include "hb_result.h"
#include "hb_abi_x64_v1.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ★ 14.09.2026, независимая линия HyperBridge — ТИПИЗИРОВАННАЯ ГРАНИЦА С НАТИВНЫМ КОДОМ
 * (пункт 4 карты паритета FEX -> HyperBridge).
 *
 * ДОНОР (FEX, Source/Windows/ARM64EC): типизированного ABI у него НЕТ. Под ARM64EC
 * регистры тождественны (x0..x3 = RCX,RDX,R8,R9; v0..v15 = XMM0..15), а переупаковку
 * позиционных слотов Win64 в AAPCS64 (раздельные счётчики целых и плавающих) делает
 * ВХОДНОЙ ТРАМПЛИН вызываемого, порождённый компилятором (смещение в 4 байтах перед
 * первой командой, Module.S:72-81). Наш клей Wine грузит x0..x7/q0..q7 ПО ИНДЕКСУ и зовёт
 * вызываемого напрямую, минуя трамплин (macrunner_hb.c:20005-20017, :36615-36626), а у
 * DXMT (чистый ARM64, CHPEMetadataPointer=0) трамплинов нет вовсе. Для смешанной подписи
 * f(u64, double, u64, double) это x1 <- RDX-мусор и d1 <- второй аргумент: вызываемый
 * видит не то. Измерено `tests/hb_abi_native_v1_test.c` с компилятором в роли оракула.
 *
 * ЧТО ЗДЕСЬ: чистые функции без исполнения. Описатель подписи (виды и ширины аргументов
 * и результата) + понижение позиционного образа Win64 из контекста гостя в образ
 * регистров/стека AAPCS64 (Windows ARM64: слоты стека по 8 байт) + сбор результата +
 * обратное поднятие образа AAPCS64 в описатель Win64 v1 для обратных вызовов.
 * Виды и ширины — те же, что у hb_abi_x64_v1 (GPR 1/2/4/8, F32, F64). Агрегаты, HFA/HVA,
 * векторы и переменное число аргументов НЕ описываются: неизвестный вид даёт
 * UNSUPPORTED_FEATURE, а не тихую позиционную укладку. Источник видов — вызывающий
 * (таблица клея или трамплин ARM64EC); эта библиотека их не выводит. */

#define HB_ABI_NATIVE_V1                  1u
#define HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1 1u   /* AAPCS64 как на Windows ARM64: 8 x, 8 d, стек слотами по 8 */
#define HB_ABI_NATIVE_MAX_ARGS_V1         20u
#define HB_ABI_NATIVE_X_REGS_V1           8u
#define HB_ABI_NATIVE_D_REGS_V1           8u
/* Флаги описателя. ПЕРЕМЕННОЕ ЧИСЛО АРГУМЕНТОВ по видам не распознать (все виды известны), а
 * укладка у него другая (Windows ARM64: все аргументы как целые в x0..x7, потом стек; Apple:
 * все безымянные — на стек). Поэтому источник видов ОБЯЗАН нести и этот признак; с ним
 * lower/raise отвечают UNSUPPORTED_FEATURE. Прочие биты — INVALID_ARG. */
#define HB_ABI_NATIVE_FLAG_VARIADIC_V1    1u

typedef struct {
    uint32_t kind;          /* HB_ABI_X64_{NONE,GPR,F32,F64}_V1 */
    uint32_t width_bytes;   /* GPR: 1/2/4/8; F32: 4; F64: 8; NONE: 0 */
} hb_abi_native_arg_v1_t;

/* Внутрипроцессный интерфейс C, не сериализованный пакет. Позиции >= argument_count
 * обязаны быть NONE/0. ret NONE/0 — результат не собирается. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t target_abi;
    uint32_t argument_count;
    uint32_t flags;             /* HB_ABI_NATIVE_FLAG_* */
    uint32_t reserved;          /* 0 */
    hb_abi_native_arg_v1_t ret;
    hb_abi_native_arg_v1_t args[HB_ABI_NATIVE_MAX_ARGS_V1];
} hb_abi_native_sig_v1_t;

/* Образ вызова AAPCS64: x0..x7, d0..d7 (сырые биты; F32 в младших 32), слоты стека по 8
 * байт в порядке аргументов ([sp+0], [sp+8], ...). Неиспользованные элементы — нули.
 * ПОТРЕБИТЕЛЬ образа обязан отвести под стек round_up(stack_count*8, 16) байт ниже SP
 * (проверка выравнивания SP включена и на Windows, и на macOS). x_count/d_count/stack_count
 * на ВХОДЕ raise — обязательства: raise отказывает INVALID_ARG, если подпись требует больше
 * элементов, чем заявлено.
 * ★ Это укладка Windows ARM64 (= общая AAPCS64): каждый стековый аргумент занимает 8-байтный
 * слот, узкие GPR расширяются НУЛЯМИ и вызываемый расширяет их сам заново (не-Darwin PCS);
 * знаковость не представлена. У ABI Apple arm64 иначе: узкие стековые аргументы пакуются по
 * естественному выравниванию, а узкие регистровые обязан расширить до 32 бит ВЫЗЫВАЮЩИЙ по
 * знаку. Образ пригоден для вызываемых Windows ARM64 (Wine ARM64X, DXMT), НЕ для вызываемых
 * с ABI Apple со знаковыми узкими параметрами. Для беззнаковых узких РЕГИСТРОВЫХ аргументов
 * оба ABI сходятся — это проверяет оракул-компилятор хоста. Узкие стековые аргументы Apple
 * пакует иначе независимо от знаковости; их этот оракул не подтверждает. */
typedef struct {
    uint64_t x[HB_ABI_NATIVE_X_REGS_V1];
    uint64_t d_bits[HB_ABI_NATIVE_D_REGS_V1];
    uint64_t stack[HB_ABI_NATIVE_MAX_ARGS_V1];
    uint32_t stack_count;
    uint32_t x_count;
    uint32_t d_count;
    uint32_t reserved;
} hb_abi_native_image_v1_t;

/* Понижение: читает позиционный образ Win64 из ПРИОСТАНОВЛЕННОГО контекста x64 (позиции
 * 0..3 — RCX/RDX/R8/R9 или младшие биты XMM0..3 по виду; позиции 4+ — гостевая память
 * по RSP+8+32+8*(i-4), т.е. RSP указывает на адрес возврата, как в клее) и раскладывает
 * по AAPCS64 раздельными счётчиками: GPR -> x0..x7, F32/F64 -> d0..d7, переполнение ->
 * стек в порядке аргументов. Биты обрезаются по ширине (GPR расширяется нулями).
 * Выравнивание RSP не проверяется: формула хвоста предполагает, что RSP указывает на адрес
 * возврата (вход в функцию по Win64, RSP = 8 mod 16); при ином RSP вызывающий получит не те
 * слоты — это его контракт, как и у клея. Переполнение адреса хвоста -> INVALID_ARG.
 * Ничего не исполняет и контекст не меняет. Ошибки: NULL/арх/режим/размер/ширина/счёт/
 * NONE в активной позиции/неизвестный флаг/переполнение адреса -> INVALID_ARG; версия/цель/
 * неизвестный вид/флаг VARIADIC -> UNSUPPORTED_FEATURE; чтение хвоста -> MEMORY_FAULT.
 * Порядок проверки при нескольких ошибках не оговаривается. out записывается только при
 * успехе; sig и ctx могут перекрываться с out — все входы прочитаны до первой записи. */
hb_result_t hb_abi_native_lower_v1(const hb_context_t *ctx, const hb_abi_native_sig_v1_t *sig,
                                   hb_abi_native_image_v1_t *out);

/* Сбор результата после того, как вызывающий сам установил нормальный возврат:
 * ret GPR -> RAX = x0 по ширине (нулевое расширение); ret F32/F64 -> заменяются только
 * младшие 32/64 бита XMM0 битами d0; ret NONE -> контекст не меняется. */
hb_result_t hb_abi_native_collect_return_v1(hb_context_t *ctx, const hb_abi_native_sig_v1_t *sig,
                                            uint64_t x0, uint64_t d0_bits);

/* Обратное поднятие (нативный -> гость): образ AAPCS64 по той же подписи превращается в
 * описатель Win64 v1 для hb_abi_x64_prepare_v1: позиции 0..3 в slots, хвост в out_tail
 * (tail_capacity >= argument_count-4, иначе INVALID_ARG; out_call->stack_args = out_tail
 * при непустом хвосте). Образ обязан заявить достаточно x_count/d_count/stack_count. Выходы
 * пишутся только при успехе. out_tail живёт, пока hb_abi_x64_prepare_v1 не потребил
 * out_call, и не должен перекрываться с out_call. */
hb_result_t hb_abi_native_raise_v1(const hb_abi_native_image_v1_t *image,
                                   const hb_abi_native_sig_v1_t *sig, uint64_t return_pc,
                                   hb_abi_x64_call_v1_t *out_call,
                                   hb_abi_x64_value_v1_t *out_tail, size_t tail_capacity);

#ifdef __cplusplus
}
#endif
#endif
