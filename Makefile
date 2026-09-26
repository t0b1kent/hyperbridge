# MacRunner HyperBridge Makefile

CC ?= clang
CFLAGS = -O2 -Wall -Wextra -Werror -std=c11 -I./include -fPIC -fvisibility=hidden -MMD -MP
# Debug builds use: CFLAGS += -g -DDEBUG -O0
LDFLAGS = -shared

# macOS ARM64 target (production)
ARCH_FLAGS = -arch arm64 -mmacosx-version-min=14.0

# W^X compliant
CFLAGS += $(ARCH_FLAGS)

include third_party/softfloat/Makefile

SRCS = \
	src/hb_gates_tbl.c \
  src/hb_env.c \
  src/hb_context.c \
  src/hb_memory.c \
  src/hb_x87.c \
  src/hb_x87_exact.c \
  src/hb_wow64cpu.c \
  src/hb_flags.c \
  src/hb_ir.c \
  src/hb_decode_x64.c \
  src/hb_decode_x86.c \
  src/hb_lift_x64.c \
  src/hb_lift_x86.c \
  src/hb_interpreter.c \
  src/hb_arm64_codegen.c \
  src/hb_jit.c \
  src/hb_aot_cache.c \
  src/hb_contract_telemetry.c \
  src/hb_marker.c \
  src/hb_probe.c \
  src/hb_iat.c \
  src/hb_fault.c \
  src/hb_pe_loader.c \
  src/hb_imports.c \
  src/hb_abi_x64.c \
  src/hb_abi_x64_v1.c \
  src/hb_abi_native_v1.c \
  src/hb_winemetal_compute_v1.c \
  src/hb_abi_x86.c \
  src/hb_thunks.c \
  src/hb_runtime.c \
  src/hb_record.c \
  src/hb_trace.c \
  src/hb_validate.c \
  src/hb_bench.c

SRCS += $(SOFTFLOAT_SRCS)

# Standalone attributed binary128 Cephes sources and our private adapter.
CEPHES_ROOT := third_party/cephes
CEPHES_SRCS := \
  $(CEPHES_ROOT)/atanll.c \
  $(CEPHES_ROOT)/constll.c \
  $(CEPHES_ROOT)/exp2ll.c \
  $(CEPHES_ROOT)/floorll.c \
  $(CEPHES_ROOT)/log2ll.c \
  $(CEPHES_ROOT)/mtherr.c \
  $(CEPHES_ROOT)/polevll.c \
  $(CEPHES_ROOT)/sinll.c \
  $(CEPHES_ROOT)/tanll.c
CEPHES_OBJS := $(CEPHES_SRCS:.c=.o)
SRCS += src/hb_x87_transcendental.c $(CEPHES_SRCS)

# ★ ЦЕЛЬ ПО УМОЛЧАНИЮ ЗАКРЕПЛЕНА ЯВНО.
#
# Правило `stamp` ниже вставлено ВЫШЕ цели `all`, и этим молча сделало `stamp`
# целью по умолчанию: `make` переставал собирать вообще что-либо, выводил пустоту
# и возвращал 0. Сборка, которая «успешна» и не собирает, — ровно тот класс
# молчаливой лжи, ради которого весь этот отпечаток и заводится.
#
# Закрепление снимает зависимость от ПОРЯДКА строк в файле: где бы ни оказалось
# новое правило, умолчание останется прежним.
.DEFAULT_GOAL := all

# ═══ ОТПЕЧАТОК СБОРКИ ═══
#
# ЗАЧЕМ. За 04.09.2026 одна и та же ловушка укусила ЧЕТЫРЕ раза: доска, сверка с
# оракулом, замер до вехи и проба шторма мерили дистрибутив ДЕСЯТИЧАСОВОЙ давности
# и назвали бы это результатом правки. Лечили каждый раз одинаково — дописывали
# сторож по ДАТАМ в очередной скрипт. Это леса: сторож надо не забыть поставить, а
# даты врут (пересборка без изменений двигает дату, правка в общий заголовок — нет).
#
# Здесь лечится КЛАСС. Отпечаток — хеш СОДЕРЖИМОГО всех исходников движка — вшит в
# библиотеку, значит доезжает до дистрибутива вместе с ней и печатается в первой же
# строке прогона. После этого:
#   • любой журнал сам называет код, который его породил;
#   • два прогона сравнимы тогда и только тогда, когда отпечатки совпали;
#   • «протухший дист» перестаёт быть предположением и становится видимым фактом.
# Сторожа по датам после этого — вспомогательные: они предупреждают заранее, но
# отвечает за правду отпечаток, а его нельзя забыть поставить.
#
# hb_stamp.h ИСКЛЮЧЁН из хеша (иначе неподвижной точки нет) и переписывается только
# при изменении, поэтому лишних пересборок нет.
# Отпечаток живёт в ПОРОЖДАЕМОМ .c, а не в заголовке — и вот почему.
#
# Первая редакция клала его в include/hb_stamp.h. Не работало при -j8, причём
# невоспроизводимо на глаз: `-MMD -MP` выпускает для КАЖДОГО заголовка пустое
# правило без предпосылок (в этом и смысл -MP — чтобы удалённый заголовок не ломал
# сборку). Такое правило делает hb_stamp.h целью, которая «уже готова», и моё
# настоящее правило переставало срабатывать. Отпечаток отставал молча — то есть
# прибор против молчаливого протухания сам протухал молча.
#
# Порождаемый .c этой беды лишён: он не заголовок, в .d-файлах не появляется, а
# порядок «породить -> скомпилировать -> заархивировать» задаёт обычный граф make.
# hb_runtime.c берёт значение через extern и от пересборки не зависит вовсе.
STAMP_C = src/hb_stamp.c
STAMP_IN = $(SRCS) $(wildcard include/*.h) $(wildcard src/*.h) $(wildcard src/*.inc) $(SOFTFLOAT_HEADERS) Makefile third_party/softfloat/Makefile $(CEPHES_ROOT)/mconf.h $(CEPHES_ROOT)/LICENSE

# ПОРОЖДАЕТСЯ ПРИ РАЗБОРЕ Makefile, а не правилом. Причина — третья по счёту за
# этот заход, и найдена пробой «добавил строку / убрал строку»: GNU make 3.81
# (штатный на macOS) сравнивает даты файлов С ТОЧНОСТЬЮ ДО СЕКУНДЫ. Правка и
# пересборка в одну секунду для него неразличимы, и правило не срабатывало —
# отпечаток оставался прежним, то есть врал ровно в том случае, ради которого
# заведён. Пересчёт при разборе от дат не зависит вовсе: он выполняется ДО того,
# как make начнёт что-либо сравнивать.
#
# Перезапись — только при РАЗЛИЧИИ содержимого (cmp), поэтому холостая сборка
# ничего не пересобирает и libhyperbridge.a не дёргается зря.
# ПОРЯДОК ФАЙЛОВ ПРИШИТ. Первая редакция брала их в порядке $(wildcard), то есть
# в порядке сортировки ТЕКУЩЕЙ ЛОКАЛИ: под LC_ALL=C один хеш, под ru_RU.UTF-8
# другой — на одних и тех же исходниках. Отпечаток, меняющийся от переменной
# окружения, отпечатком не является; поймано тем, что проверялка (она выставляет
# ru_RU) и ручной вызов разошлись на одном дереве.
$(shell h=`printf '%s\n' $(STAMP_IN) | LC_ALL=C sort | tr '\n' ' ' | xargs cat 2>/dev/null | md5 -q | cut -c1-12`; \
	printf '/* ПОРОЖДЁННЫЙ ФАЙЛ — правки затираются сборкой. См. STAMP_C в Makefile. */\nconst char hb_build_stamp[] = "%s";\n' "$$h" > $(STAMP_C).tmp; \
	cmp -s $(STAMP_C).tmp $(STAMP_C) || mv $(STAMP_C).tmp $(STAMP_C); \
	rm -f $(STAMP_C).tmp)

.PHONY: stamp
stamp:
	@sed -n 's/.*"\(.*\)".*/\1/p' $(STAMP_C)

OBJS = $(SRCS:.c=.o) $(STAMP_C:.c=.o)
DEPS = $(OBJS:.o=.d)

$(OBJS): Makefile

STATIC_LIB = libhyperbridge.a
SHARED_LIB = libhyperbridge.dylib
TEST_BIN = tests/hb_test_runner
CONTRACT_TELEMETRY_TEST_BIN = tests/hb_contract_telemetry_test
IMUL_FLAGS_TEST_BIN = tests/hb_imul_flags_test
# ★ MacRunner 2026-09-04 — ТЕСТ БЫЛ НАПИСАН И НИКОГДА НЕ СОБИРАЛСЯ.
#
# tests/ripmap_index.c лежит в дереве с 01.08.2026 и в Makefile не значился: ни одна цель его
# не строила, то есть он не исполнялся НИ РАЗУ. Это единственная проба, где открывается опасное
# окно карты отказов — блок со СЛИЯНИЕМ команд, в котором номер записи карты расходится с
# номером команды (host_instr[n] != n). Исчерпывающая самопроверка внутри движка
# (MACRUNNER_HB_RIPMAP_SELFTEST) на нашем корпусе сообщает «блоков-со-слиянием=0», то есть про
# эту опасность не говорит НИЧЕГО. Подключено к цели test.
RIPMAP_INDEX_TEST_BIN = tests/hb_ripmap_index_test
# ★ 06.09.2026 — ПРИБОР, КОТОРЫЙ НЕ МОЖЕТ ВЫДАТЬ НЕОТЛИЧИМЫЙ НОЛЬ (include/hb_probe.h).
# Приёмка двурукая: рука A гонит батарею по настоящему классификатору, рука B — по
# ПЯТИ порчам, каждая из которых воспроизводит настоящий класс лжи из нашей истории.
# Батарея обязана покраснеть на всех пяти; не покраснела хоть на одной — отказ.
PROBE_TEST_BIN = tests/hb_probe_test
# ★ 07.09.2026, лейн ОСНАСТКА — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПУЛЬСА ПЕРЕПИСИ.
# Отдельный двоичный, потому что проверяемое условие — «приборов НЕТ ВОВСЕ», а в
# hb_probe_test приборы регистрируются конструкторами до main() и тот случай оттуда
# недостижим в принципе. Пульс в образе без приборов обязан молчать ПОЛНОСТЬЮ: строка
# «itog vsego=0» выглядела бы как перепись исправного образа с молчащими приборами.
PROBE_ZERO_TEST_BIN = tests/hb_probe_zero_test
# ★ 06.09.2026, лейн КЕШ — ОТПЕЧАТОК СБОРКИ В ЗАГОЛОВКЕ ФАЙЛА КЕША.
# Отрицательный контроль внутри: тот же файл с подделанными четырьмя байтами обязан дать
# НОЛЬ записей, а с возвращённым отпечатком — снова попадание. Без второй половины «не
# видна» означало бы «файл разрушен», а не «отвергнут по сборке».
CACHE_STAMP_TEST_BIN = tests/hb_cache_build_stamp_test
# ★ 07.09.2026, лейн ВЫПУСК — КОДИРОВЩИК ЛОГИЧЕСКОГО НЕПОСРЕДСТВЕННОГО (N:immr:imms).
# Оракул — ОБРАТНЫЙ ход по букве ISA, а не тот же алгоритм задом наперёд: перебираются все
# 8192 сочетания полей, 7680 допустимых обязаны сойтись по значению. Отрицательный контроль
# проверен вручную: сдвиг immr на единицу даёт 7681 отказ, то есть прибор УМЕЕТ КРАСНЕТЬ.
LOGICAL_IMM_TEST_BIN = tests/hb_logical_imm_test
BIT_STRING_TEST_BIN = tests/hb_bit_string_test
SEGMENT_ADDRESS_TEST_BIN = tests/hb_segment_address_test
ABI_X64_STATE_TEST_BIN = tests/hb_abi_x64_state_test
ABI_X64_FRAME_TEST_BIN = tests/hb_abi_x64_frame_test
ABI_X64_V1_TEST_BIN = tests/hb_abi_x64_v1_test
ABI_NATIVE_V1_TEST_BIN = tests/hb_abi_native_v1_test
WINEMETAL_COMPUTE_TEST_BIN = tests/hb_winemetal_compute_v1_test
MXCSR_TEST_BIN = tests/hb_mxcsr_test
XMM_PAIR_X22_TEST_BIN = tests/hb_xmm_pair_x22_test
SMC_FASTPATH_TEST_BIN = tests/hb_smc_fastpath_test
VEX_MOVD_YMM_TEST_BIN = tests/hb_vex_movd_ymm_test
SSE_FP_NATIVE_TEST_BIN = tests/hb_sse_fp_native_test
BT_PENDING_NATIVE_TEST_BIN = tests/hb_bt_pending_native_test
VEX_YMM_MOVE_TEST_BIN = tests/hb_vex_ymm_move_test
LAZY_COND_NATIVE_TEST_BIN = tests/hb_lazy_cond_native_test
UPPER_STATE_TEST_BIN = tests/hb_upper_state_test
EVEX_DISP8_TEST_BIN = tests/hb_evex_disp8_test
SSE_ORACLE_RUNNER_BIN = tests/hb_diff_case_runner
FXSTATE_MXCSR_TEST_BIN = tests/hb_fxstate_mxcsr_test
FXSTATE_X87_TEST_BIN = tests/hb_fxstate_x87_test
X87_INTEGER_TEST_BIN = tests/hb_x87_integer_test
X87_ENVIRONMENT_TEST_BIN = tests/hb_x87_environment_test
SSE_INTEGER_ROUNDING_TEST_BIN = tests/hb_sse_integer_rounding_test
VEX_UPPER_STATE_TEST_BIN = tests/hb_vex_upper_state_test
ROUND_INSTRUCTION_TEST_BIN = tests/hb_round_instruction_test
HALF_CONVERSION_TEST_BIN = tests/hb_half_conversion_test
X87_FRNDINT_TEST_BIN = tests/hb_x87_frndint_test
DIAGNOSTIC_FENV_TEST_BIN = tests/hb_diagnostic_fenv_test
X87_FPREM_TEST_BIN = tests/hb_x87_fprem_test
X87_BCD_TEST_BIN = tests/hb_x87_bcd_test
X87_BCD_LOAD_TEST_BIN = tests/hb_x87_bcd_load_test
X87_LOADED_STATUS_TEST_BIN = tests/hb_x87_loaded_status_test
CONTEXT_RESET_FAULT_TEST_BIN = tests/hb_context_reset_fault_test
FXSTATE_ALIGNMENT_TEST_BIN = tests/hb_fxstate_alignment_test
X87_FLOATING_LOAD_STATUS_TEST_BIN = tests/hb_x87_floating_load_status_test
X87_RAW_LOAD_TEST_BIN = tests/hb_x87_raw_load_test
X87_SHORT_ENVIRONMENT_TEST_BIN = tests/hb_x87_short_environment_test
XSAVE_STATE_TEST_BIN = tests/hb_xsave_state_test
XGETBV_INDEX_TEST_BIN = tests/hb_xgetbv_index_test
X87_REGISTER_TRANSFER_TEST_BIN = tests/hb_x87_register_transfer_test
XSTATE_ADMISSION_TEST_BIN = tests/hb_xstate_admission_test
X87_EXACT_ADDSUB_TEST_BIN = tests/hb_x87_exact_addsub_test
X87_ARITHMETIC_DESTINATION_TEST_BIN = tests/hb_x87_arithmetic_destination_test
X87_FIP_CLASSIFICATION_TEST_BIN = tests/hb_x87_fip_classification_test
X87_EXACT_NONPOP_ADDSUB_TEST_BIN = tests/hb_x87_exact_nonpop_addsub_test
X87_COMPARISON_FLAGS_TEST_BIN = tests/hb_x87_comparison_flags_test
X87_FTST_FLAGS_TEST_BIN = tests/hb_x87_ftst_flags_test
X87_ORDERED_COMPARISON_FLAGS_TEST_BIN = tests/hb_x87_ordered_comparison_flags_test
X87_BCD_SUCCESS_FIP_TEST_BIN = tests/hb_x87_bcd_success_fip_test
X87_RAW_FTST_TEST_BIN = tests/hb_x87_raw_ftst_test
X87_RAW_FCOMI_TEST_BIN = tests/hb_x87_raw_fcomi_test
X87_RAW_FCOM_TEST_BIN = tests/hb_x87_raw_fcom_test
X87_MIXED_CACHE_COMPARE_TEST_BIN = tests/hb_x87_mixed_cache_compare_test
X87_RAW_MEMORY_COMPARE_TEST_BIN = tests/hb_x87_raw_memory_compare_test
X87_INFINITY_COMPARE_TEST_BIN = tests/hb_x87_infinity_compare_test
X87_EXACT_MULDIV_TEST_BIN = tests/hb_x87_exact_muldiv_test
X87_EXACT_NONPOP_MULDIV_TEST_BIN = tests/hb_x87_exact_nonpop_muldiv_test
X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN = tests/hb_x87_exact_memory_arithmetic_test
X87_FINITE_BRIDGE_TEST_BIN = tests/hb_x87_finite_bridge_test
X87_FINITE_SQRT_BRIDGE_TEST_BIN = tests/hb_x87_finite_sqrt_bridge_test
X87_FINITE_SQRT_TEST_BIN = tests/hb_x87_finite_sqrt_test
X87_FINITE_FXAM_TEST_BIN = tests/hb_x87_finite_fxam_test
X87_FINITE_FXTRACT_TEST_BIN = tests/hb_x87_finite_fxtract_test
X87_CACHED_FINITE_SIGN_TEST_BIN = tests/hb_x87_cached_finite_sign_test
X87_CACHED_FINITE_FSCALE_TEST_BIN = tests/hb_x87_cached_finite_fscale_test
X87_CACHED_TINY_FSIN_TEST_BIN = tests/hb_x87_cached_tiny_fsin_test
X87_CACHED_TINY_FSINCOS_TEST_BIN = tests/hb_x87_cached_tiny_fsincos_test
X87_CACHED_TINY_FCOS_TEST_BIN = tests/hb_x87_cached_tiny_fcos_test
X87_CACHED_TINY_FPTAN_TEST_BIN = tests/hb_x87_cached_tiny_fptan_test
X87_CACHED_EXACT_FYL2X_TEST_BIN = tests/hb_x87_cached_exact_fyl2x_test
X87_CACHED_EXACT_FYL2XP1_TEST_BIN = tests/hb_x87_cached_exact_fyl2xp1_test
X87_TRANSCENDENTAL_COMPONENT_TEST_BIN = tests/hb_x87_transcendental_component_test
X87_TRANSCENDENTAL_GUEST_TEST_BIN = tests/hb_x87_transcendental_guest_test
X87_MASKED_PRECISION_TEST_BIN = tests/hb_x87_masked_precision_test
BENCH_BIN = tests/hb_bench_runner

.PHONY: all clean test bench report contract-telemetry-test imul-flags-test ripmap-index-test fault-kind-test memory-contract-test perepis-directmem probe-test probe-zero-test probe-kill-probe cache-stamp-test logical-imm-test x87-transcendental-component-test x87-transcendental-guest-test

all: $(STATIC_LIB) $(SHARED_LIB)

$(STATIC_LIB): $(OBJS)
	ar rcs $@ $(OBJS)

$(SHARED_LIB): $(OBJS)
	$(CC) $(LDFLAGS) $(ARCH_FLAGS) -o $@ $(OBJS)

# Retained vendor diagnostics remain visible; build-01 observed only the two
# unused mtherr parameters. Our own adapter keeps the parent -Werror policy.
$(CEPHES_OBJS) src/hb_x87_transcendental.o: Makefile third_party/softfloat/Makefile

$(CEPHES_OBJS): %.o: %.c
	$(CC) $(filter-out -Werror -std=c11,$(CFLAGS)) -std=gnu11 -fno-builtin -fno-fast-math -fno-lto $(SOFTFLOAT_CONFIG) -c $< -o $@

src/hb_x87_transcendental.o: src/hb_x87_transcendental.c
	$(CC) $(CFLAGS) -fno-builtin -fno-fast-math -fno-lto $(SOFTFLOAT_CONFIG) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 обязателен ИМЕННО ЗДЕСЬ: hb_test_runner — самостоятельный
# двоичный, обработчика wine у него нет, и без этой двери отказ в выпущенном коде убивает
# процесс (проверено: с гейтами прямой памяти дверь=0 даёт сегфолт, дверь=1 — 441 passed).
# Под wine дверь ВРЕДНА и потому выключена по умолчанию — разбор у гейта в hb_memory.c.
# ★ 07.09.2026: эти два присваивания стояли НИЖЕ цели `test`, и это делало `make test`
# КРАСНЫМ на чистом дереве. GNU make раскрывает предпосылки НЕМЕДЛЕННО при чтении
# правила, поэтому в списке ниже стояли пустые строки, двоичные не собирались
# никогда, и цель падала с Error 127. Исходники при этом компилируются без ошибок,
# поэтому дефект выглядел как поломка тестов. Стоил времени ТРЁМ лейнам независимо.
POVTOR_PROBE_BIN = tests/povtor_prichina_probe
IC_RETRANS_PROBE_BIN = tests/ic_retranslate_probe

test: memory-fault-guard $(STATIC_LIB) $(TEST_BIN) $(IMUL_FLAGS_TEST_BIN) $(RIPMAP_INDEX_TEST_BIN) $(PROBE_TEST_BIN) $(PROBE_ZERO_TEST_BIN) $(CACHE_STAMP_TEST_BIN) $(LOGICAL_IMM_TEST_BIN) $(POVTOR_PROBE_BIN) $(IC_RETRANS_PROBE_BIN) $(BIT_STRING_TEST_BIN) $(SEGMENT_ADDRESS_TEST_BIN) $(ABI_X64_STATE_TEST_BIN) $(ABI_X64_FRAME_TEST_BIN) $(ABI_X64_V1_TEST_BIN) $(ABI_NATIVE_V1_TEST_BIN) $(MXCSR_TEST_BIN) $(FXSTATE_MXCSR_TEST_BIN) $(SSE_INTEGER_ROUNDING_TEST_BIN) $(FXSTATE_X87_TEST_BIN) $(X87_INTEGER_TEST_BIN) $(X87_ENVIRONMENT_TEST_BIN) $(VEX_UPPER_STATE_TEST_BIN) $(ROUND_INSTRUCTION_TEST_BIN) $(HALF_CONVERSION_TEST_BIN) $(X87_FRNDINT_TEST_BIN) $(DIAGNOSTIC_FENV_TEST_BIN) $(X87_FPREM_TEST_BIN) $(X87_BCD_TEST_BIN) $(X87_BCD_LOAD_TEST_BIN) $(X87_LOADED_STATUS_TEST_BIN) $(CONTEXT_RESET_FAULT_TEST_BIN) $(FXSTATE_ALIGNMENT_TEST_BIN) $(X87_FLOATING_LOAD_STATUS_TEST_BIN) $(X87_RAW_LOAD_TEST_BIN) $(X87_SHORT_ENVIRONMENT_TEST_BIN) $(XSAVE_STATE_TEST_BIN) $(XGETBV_INDEX_TEST_BIN) $(X87_REGISTER_TRANSFER_TEST_BIN) $(XSTATE_ADMISSION_TEST_BIN) $(X87_EXACT_ADDSUB_TEST_BIN) $(X87_ARITHMETIC_DESTINATION_TEST_BIN) $(X87_FIP_CLASSIFICATION_TEST_BIN) $(X87_EXACT_NONPOP_ADDSUB_TEST_BIN) $(X87_COMPARISON_FLAGS_TEST_BIN) $(X87_FTST_FLAGS_TEST_BIN) $(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN) $(X87_BCD_SUCCESS_FIP_TEST_BIN) $(X87_RAW_FTST_TEST_BIN) $(X87_RAW_FCOMI_TEST_BIN) $(X87_RAW_FCOM_TEST_BIN) $(X87_MIXED_CACHE_COMPARE_TEST_BIN) $(X87_RAW_MEMORY_COMPARE_TEST_BIN) $(X87_INFINITY_COMPARE_TEST_BIN) $(X87_EXACT_MULDIV_TEST_BIN) $(X87_EXACT_NONPOP_MULDIV_TEST_BIN) $(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN) $(X87_FINITE_BRIDGE_TEST_BIN) $(X87_MASKED_PRECISION_TEST_BIN) $(X87_FINITE_SQRT_BRIDGE_TEST_BIN) $(X87_FINITE_SQRT_TEST_BIN) $(X87_FINITE_FXAM_TEST_BIN) $(X87_FINITE_FXTRACT_TEST_BIN) $(X87_CACHED_FINITE_SIGN_TEST_BIN) $(X87_CACHED_FINITE_FSCALE_TEST_BIN) $(X87_CACHED_TINY_FSIN_TEST_BIN) $(X87_CACHED_TINY_FSINCOS_TEST_BIN) $(X87_CACHED_TINY_FCOS_TEST_BIN) $(X87_CACHED_TINY_FPTAN_TEST_BIN) $(X87_CACHED_EXACT_FYL2X_TEST_BIN) $(X87_CACHED_EXACT_FYL2XP1_TEST_BIN) $(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN) $(X87_TRANSCENDENTAL_GUEST_TEST_BIN) $(XMM_PAIR_X22_TEST_BIN) $(SMC_FASTPATH_TEST_BIN) $(VEX_MOVD_YMM_TEST_BIN) $(SSE_FP_NATIVE_TEST_BIN) $(BT_PENDING_NATIVE_TEST_BIN) $(VEX_YMM_MOVE_TEST_BIN) $(LAZY_COND_NATIVE_TEST_BIN) $(UPPER_STATE_TEST_BIN) $(EVEX_DISP8_TEST_BIN) $(SSE_ORACLE_RUNNER_BIN)
	@echo "Running C unit tests..."
	MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 ./$(TEST_BIN)
	@echo "Running IMUL flag regression test..."
	./$(IMUL_FLAGS_TEST_BIN)
	./$(BIT_STRING_TEST_BIN)
	./$(SEGMENT_ADDRESS_TEST_BIN)
	./$(ABI_X64_STATE_TEST_BIN)
	./$(ABI_X64_FRAME_TEST_BIN)
	./$(ABI_X64_V1_TEST_BIN)
	./$(ABI_NATIVE_V1_TEST_BIN)
	./$(WINEMETAL_COMPUTE_TEST_BIN)
	./$(MXCSR_TEST_BIN)
	./$(FXSTATE_MXCSR_TEST_BIN)
	./$(SSE_INTEGER_ROUNDING_TEST_BIN)
	./$(VEX_UPPER_STATE_TEST_BIN)
	./$(ROUND_INSTRUCTION_TEST_BIN)
	./$(HALF_CONVERSION_TEST_BIN)
	./$(X87_FRNDINT_TEST_BIN)
	./$(DIAGNOSTIC_FENV_TEST_BIN)
	./$(X87_FPREM_TEST_BIN)
	./$(X87_BCD_TEST_BIN)
	./$(X87_BCD_LOAD_TEST_BIN)
	./$(X87_LOADED_STATUS_TEST_BIN)
	./$(CONTEXT_RESET_FAULT_TEST_BIN)
	./$(FXSTATE_ALIGNMENT_TEST_BIN)
	./$(X87_FLOATING_LOAD_STATUS_TEST_BIN)
	./$(X87_RAW_LOAD_TEST_BIN)
	./$(X87_SHORT_ENVIRONMENT_TEST_BIN)
	./$(XSAVE_STATE_TEST_BIN)
	./$(XGETBV_INDEX_TEST_BIN)
	./$(X87_REGISTER_TRANSFER_TEST_BIN)
	./$(XSTATE_ADMISSION_TEST_BIN)
	./$(X87_EXACT_ADDSUB_TEST_BIN)
	./$(X87_ARITHMETIC_DESTINATION_TEST_BIN)
	./$(X87_FIP_CLASSIFICATION_TEST_BIN)
	./$(X87_EXACT_NONPOP_ADDSUB_TEST_BIN)
	./$(X87_COMPARISON_FLAGS_TEST_BIN)
	./$(X87_FTST_FLAGS_TEST_BIN)
	./$(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN)
	./$(X87_BCD_SUCCESS_FIP_TEST_BIN)
	./$(X87_RAW_FTST_TEST_BIN)
	./$(X87_RAW_FCOMI_TEST_BIN)
	./$(X87_RAW_FCOM_TEST_BIN)
	./$(X87_MIXED_CACHE_COMPARE_TEST_BIN)
	./$(X87_RAW_MEMORY_COMPARE_TEST_BIN)
	./$(X87_INFINITY_COMPARE_TEST_BIN)
	./$(X87_EXACT_MULDIV_TEST_BIN)
	./$(X87_EXACT_NONPOP_MULDIV_TEST_BIN)
	./$(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN)
	./$(X87_FINITE_BRIDGE_TEST_BIN)
	./$(X87_MASKED_PRECISION_TEST_BIN)
	./$(X87_FINITE_SQRT_BRIDGE_TEST_BIN)
	./$(X87_FINITE_SQRT_TEST_BIN)
	./$(X87_FINITE_FXAM_TEST_BIN)
	./$(X87_FINITE_FXTRACT_TEST_BIN)
	./$(X87_CACHED_FINITE_SIGN_TEST_BIN)
	./$(X87_CACHED_FINITE_FSCALE_TEST_BIN)
	./$(X87_CACHED_TINY_FSIN_TEST_BIN)
	./$(X87_CACHED_TINY_FSINCOS_TEST_BIN)
	./$(X87_CACHED_TINY_FCOS_TEST_BIN)
	./$(X87_CACHED_TINY_FPTAN_TEST_BIN)
	./$(X87_CACHED_EXACT_FYL2X_TEST_BIN)
	./$(X87_CACHED_EXACT_FYL2XP1_TEST_BIN)
	./$(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN)
	./$(X87_TRANSCENDENTAL_GUEST_TEST_BIN)
	./$(FXSTATE_X87_TEST_BIN)
	./$(X87_INTEGER_TEST_BIN)
	./$(X87_ENVIRONMENT_TEST_BIN)
	@echo "Running ripmap index test..."
	./$(RIPMAP_INDEX_TEST_BIN)
	@echo "Running probe (non-lying instrument) test..."
	./$(PROBE_TEST_BIN)
	@echo "Running probe ZERO test (census pulse must stay silent with no probes)..."
	./$(PROBE_ZERO_TEST_BIN)
	@echo "Running cache build-stamp test (foreign build must be rejected)..."
	./$(CACHE_STAMP_TEST_BIN)
	@echo "Running ARM64 logical-immediate encoder test..."
	./$(LOGICAL_IMM_TEST_BIN)
	@echo "Running povtor cause census negative control (4 arms, 3 zero buckets each)..."
	MACRUNNER_HB_POVTOR_STATS=1 ./$(POVTOR_PROBE_BIN)
	@echo "Running IC-after-retranslate correctness probe (arm B must reproduce the defect)..."
	MACRUNNER_HB_INDIRECT_IC=1 MACRUNNER_HB_POVTOR_STATS=1 ./$(IC_RETRANS_PROBE_BIN)
	MACRUNNER_HB_INDIRECT_IC=1 MACRUNNER_HB_POVTOR_STATS=1 MACRUNNER_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE=1 ./$(IC_RETRANS_PROBE_BIN)
	@echo "Running XMM logic x22-pair regression (memory src2 must not clobber src1.hi)..."
	./$(XMM_PAIR_X22_TEST_BIN)
	@echo "Running SMC fast-path test (generation check with page protection; off arm is the control)..."
	./$(SMC_FASTPATH_TEST_BIN)
	./$(SMC_FASTPATH_TEST_BIN) off
	@echo "Running VEX MOVD/MOVQ upper-YMM test (VEX zeroes ymm_hi, legacy SSE keeps it)..."
	./$(VEX_MOVD_YMM_TEST_BIN)
	@echo "Running native SSE FP parity test (special values; the NO_SLOW arm must FAIL)..."
	./$(SSE_FP_NATIVE_TEST_BIN)
	! MACRUNNER_HB_TEST_SSE_FP_NO_SLOW=1 ./$(SSE_FP_NATIVE_TEST_BIN) > /dev/null
	@echo "Running native BT pending-flags parity test (the ZF_INVERT arm must FAIL)..."
	./$(BT_PENDING_NATIVE_TEST_BIN)
	! MACRUNNER_HB_TEST_BT_ZF_INVERT=1 ./$(BT_PENDING_NATIVE_TEST_BIN) > /dev/null
	@echo "Running VEX YMM move parity test (VEX.256 load/store, VEX.128 load upper zeroing)..."
	./$(VEX_YMM_MOVE_TEST_BIN)
	@echo "Running native lazy-flag condition test (Jcc/CMOVcc/SETcc; FLIP and gate-off arms must FAIL)..."
	HB_LAZY_COND_QUICK=1 ./$(LAZY_COND_NATIVE_TEST_BIN) 2>/dev/null
	! HB_LAZY_COND_QUICK=2 MACRUNNER_HB_TEST_LAZY_COND_FLIP=1 ./$(LAZY_COND_NATIVE_TEST_BIN) > /dev/null 2>&1
	! HB_LAZY_COND_QUICK=2 MACRUNNER_HB_NATIVE_LAZY_COND=0 ./$(LAZY_COND_NATIVE_TEST_BIN) > /dev/null 2>&1
	@echo "Running vector upper-state test (Astra's x86 corpus: VEX/EVEX writeback, fused LOAD+STORE)..."
	./$(UPPER_STATE_TEST_BIN) --self-test > /dev/null
	mkdir -p tests/hb_upper_audit/out
	gunzip -c tests/hb_upper_audit/native.cases.gz > tests/hb_upper_audit/out/native.cases
	MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_LEAN_FRAME=0 ./$(UPPER_STATE_TEST_BIN) tests/hb_upper_audit/out/native.cases --filter U01 --require-pair 2>/dev/null
	MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_LEAN_FRAME=0 ./$(UPPER_STATE_TEST_BIN) tests/hb_upper_audit/out/native.cases --exclude-mask 2>/dev/null
	MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_LEAN_FRAME=1 ./$(UPPER_STATE_TEST_BIN) tests/hb_upper_audit/out/native.cases --exclude-mask 2>/dev/null
	@echo "Running EVEX disp8*N decoder table (capstone reference: x64 956 + i386 888 forms, 3 refusals)..."
	./$(EVEX_DISP8_TEST_BIN)
	@echo "Running hardware SSE oracle (x86 answers; the JIT must never be worse than the interpreter)..."
	mkdir -p tests/hb_sse_oracle/out
	for c in tests/hb_sse_oracle/corpus/smoke.cases tests/hb_sse_oracle/corpus/regressions.cases; do \
	  for fp in 1 0; do \
	    HB_DIFF_IDENTITY=1 HB_DIFF_LIVE_FALLBACK=0 MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_MXCSR_FPCR=$$fp \
	      ./$(SSE_ORACLE_RUNNER_BIN) < $$c 2>tests/hb_sse_oracle/out/runner.stderr > tests/hb_sse_oracle/out/runner.stdout; \
	      rc=$$?; python3 tests/hb_sse_oracle/jit_not_worse.py < tests/hb_sse_oracle/out/runner.stdout || { \
	        echo "runner exit=$$rc corpus=$$c FPCR=$$fp; stderr tail:"; tail -5 tests/hb_sse_oracle/out/runner.stderr; exit 1; }; \
	  done; \
	done
	@echo "Running Python test suite..."
	python3 -m unittest discover -s tests -v

# Guards the two/three-operand IMUL CF/OF write. Verified to FAIL (11 of 12 cases) against the
# pre-fix behaviour via MACRUNNER_HB_IMUL_FLAGS=0, so it is a test with a negative control rather
# than one that merely agrees with whatever the code does.
imul-flags-test: $(IMUL_FLAGS_TEST_BIN)
	./$(IMUL_FLAGS_TEST_BIN)

$(IMUL_FLAGS_TEST_BIN): tests/hb_imul_flags_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: bit-string-test
bit-string-test: $(BIT_STRING_TEST_BIN)
	./$(BIT_STRING_TEST_BIN)

$(BIT_STRING_TEST_BIN): tests/hb_bit_string_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: segment-address-test abi-x64-state-test abi-x64-frame-test abi-x64-v1-test mxcsr-test sse-integer-rounding-test fxstate-x87-test x87-integer-test x87-environment-test
.PHONY: vex-upper-state-test
.PHONY: round-instruction-test
.PHONY: half-conversion-test
.PHONY: x87-frndint-test
.PHONY: diagnostic-fenv-test x87-fprem-test x87-bcd-test x87-bcd-load-test x87-loaded-status-test context-reset-fault-test fxstate-alignment-test x87-floating-load-status-test x87-raw-load-test x87-short-environment-test xsave-state-test xgetbv-index-test x87-register-transfer-test xstate-admission-test x87-exact-addsub-test x87-arithmetic-destination-test x87-fip-classification-test x87-exact-nonpop-addsub-test x87-comparison-flags-test x87-ftst-flags-test x87-ordered-comparison-flags-test x87-bcd-success-fip-test x87-raw-ftst-test x87-raw-fcomi-test
segment-address-test: $(SEGMENT_ADDRESS_TEST_BIN)
	./$(SEGMENT_ADDRESS_TEST_BIN)

abi-x64-state-test: $(ABI_X64_STATE_TEST_BIN)
	./$(ABI_X64_STATE_TEST_BIN)

$(SEGMENT_ADDRESS_TEST_BIN): tests/hb_segment_address_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

$(ABI_X64_STATE_TEST_BIN): tests/hb_abi_x64_state_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

abi-x64-frame-test: $(ABI_X64_FRAME_TEST_BIN)
	./$(ABI_X64_FRAME_TEST_BIN)

$(ABI_X64_FRAME_TEST_BIN): tests/hb_abi_x64_frame_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

abi-x64-v1-test: $(ABI_X64_V1_TEST_BIN)
	./$(ABI_X64_V1_TEST_BIN)

# 14.09.2026, пункт 4 карты (типизированный нативный ABI): оракул — компилятор хоста.
abi-native-v1-test: $(ABI_NATIVE_V1_TEST_BIN)
	./$(ABI_NATIVE_V1_TEST_BIN)

$(ABI_NATIVE_V1_TEST_BIN): tests/hb_abi_native_v1_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

test: $(WINEMETAL_COMPUTE_TEST_BIN)

.PHONY: winemetal-compute-v1-test clean-winemetal-compute-v1-test
winemetal-compute-v1-test: $(WINEMETAL_COMPUTE_TEST_BIN)
	./$(WINEMETAL_COMPUTE_TEST_BIN)

$(WINEMETAL_COMPUTE_TEST_BIN): tests/hb_winemetal_compute_v1_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

clean: clean-winemetal-compute-v1-test
clean-winemetal-compute-v1-test:
	rm -f $(WINEMETAL_COMPUTE_TEST_BIN)

$(ABI_X64_V1_TEST_BIN): tests/hb_abi_x64_v1_test.c tests/hb_native_callback_capture.inc tests/hb_nested_callback_boundary.inc $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

mxcsr-test: $(MXCSR_TEST_BIN) $(FXSTATE_MXCSR_TEST_BIN)
	./$(MXCSR_TEST_BIN)
	./$(FXSTATE_MXCSR_TEST_BIN)

$(MXCSR_TEST_BIN): tests/hb_mxcsr_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

$(FXSTATE_MXCSR_TEST_BIN): tests/hb_fxstate_mxcsr_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

sse-integer-rounding-test: $(SSE_INTEGER_ROUNDING_TEST_BIN)
	./$(SSE_INTEGER_ROUNDING_TEST_BIN)

$(SSE_INTEGER_ROUNDING_TEST_BIN): tests/hb_sse_integer_rounding_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

vex-upper-state-test: $(VEX_UPPER_STATE_TEST_BIN)
	./$(VEX_UPPER_STATE_TEST_BIN)

$(VEX_UPPER_STATE_TEST_BIN): tests/hb_vex_upper_state_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

round-instruction-test: $(ROUND_INSTRUCTION_TEST_BIN)
	./$(ROUND_INSTRUCTION_TEST_BIN)

$(ROUND_INSTRUCTION_TEST_BIN): tests/hb_round_instruction_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

half-conversion-test: $(HALF_CONVERSION_TEST_BIN)
	./$(HALF_CONVERSION_TEST_BIN)

$(HALF_CONVERSION_TEST_BIN): tests/hb_half_conversion_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-frndint-test: $(X87_FRNDINT_TEST_BIN)
	./$(X87_FRNDINT_TEST_BIN)

$(X87_FRNDINT_TEST_BIN): tests/hb_x87_frndint_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

diagnostic-fenv-test: $(DIAGNOSTIC_FENV_TEST_BIN)
	./$(DIAGNOSTIC_FENV_TEST_BIN)

$(DIAGNOSTIC_FENV_TEST_BIN): tests/hb_diagnostic_fenv_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-fprem-test: $(X87_FPREM_TEST_BIN)
	./$(X87_FPREM_TEST_BIN)

$(X87_FPREM_TEST_BIN): tests/hb_x87_fprem_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-bcd-test: $(X87_BCD_TEST_BIN)
	./$(X87_BCD_TEST_BIN)

$(X87_BCD_TEST_BIN): tests/hb_x87_bcd_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-bcd-load-test: $(X87_BCD_LOAD_TEST_BIN)
	./$(X87_BCD_LOAD_TEST_BIN)

$(X87_BCD_LOAD_TEST_BIN): tests/hb_x87_bcd_load_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-loaded-status-test: $(X87_LOADED_STATUS_TEST_BIN)
	./$(X87_LOADED_STATUS_TEST_BIN)

$(X87_LOADED_STATUS_TEST_BIN): tests/hb_x87_loaded_status_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

context-reset-fault-test: $(CONTEXT_RESET_FAULT_TEST_BIN)
	./$(CONTEXT_RESET_FAULT_TEST_BIN)

$(CONTEXT_RESET_FAULT_TEST_BIN): tests/hb_context_reset_fault_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

fxstate-alignment-test: $(FXSTATE_ALIGNMENT_TEST_BIN)
	./$(FXSTATE_ALIGNMENT_TEST_BIN)

$(FXSTATE_ALIGNMENT_TEST_BIN): tests/hb_fxstate_alignment_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-floating-load-status-test: $(X87_FLOATING_LOAD_STATUS_TEST_BIN)
	./$(X87_FLOATING_LOAD_STATUS_TEST_BIN)

$(X87_FLOATING_LOAD_STATUS_TEST_BIN): tests/hb_x87_floating_load_status_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-raw-load-test: $(X87_RAW_LOAD_TEST_BIN)
	./$(X87_RAW_LOAD_TEST_BIN)

$(X87_RAW_LOAD_TEST_BIN): tests/hb_x87_raw_load_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-short-environment-test: $(X87_SHORT_ENVIRONMENT_TEST_BIN)
	./$(X87_SHORT_ENVIRONMENT_TEST_BIN)

$(X87_SHORT_ENVIRONMENT_TEST_BIN): tests/hb_x87_short_environment_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

xsave-state-test: $(XSAVE_STATE_TEST_BIN)
	./$(XSAVE_STATE_TEST_BIN)

$(XSAVE_STATE_TEST_BIN): tests/hb_xsave_state_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

xgetbv-index-test: $(XGETBV_INDEX_TEST_BIN)
	./$(XGETBV_INDEX_TEST_BIN)

$(XGETBV_INDEX_TEST_BIN): tests/hb_xgetbv_index_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-register-transfer-test: $(X87_REGISTER_TRANSFER_TEST_BIN)
	./$(X87_REGISTER_TRANSFER_TEST_BIN)

$(X87_REGISTER_TRANSFER_TEST_BIN): tests/hb_x87_register_transfer_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

xstate-admission-test: $(XSTATE_ADMISSION_TEST_BIN)
	./$(XSTATE_ADMISSION_TEST_BIN)

$(XSTATE_ADMISSION_TEST_BIN): tests/hb_xstate_admission_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-exact-addsub-test: $(X87_EXACT_ADDSUB_TEST_BIN)
	./$(X87_EXACT_ADDSUB_TEST_BIN)

$(X87_EXACT_ADDSUB_TEST_BIN): tests/hb_x87_exact_addsub_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-arithmetic-destination-test: $(X87_ARITHMETIC_DESTINATION_TEST_BIN)
	./$(X87_ARITHMETIC_DESTINATION_TEST_BIN)

$(X87_ARITHMETIC_DESTINATION_TEST_BIN): tests/hb_x87_arithmetic_destination_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-fip-classification-test: $(X87_FIP_CLASSIFICATION_TEST_BIN)
	./$(X87_FIP_CLASSIFICATION_TEST_BIN)

$(X87_FIP_CLASSIFICATION_TEST_BIN): tests/hb_x87_fip_classification_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-exact-nonpop-addsub-test: $(X87_EXACT_NONPOP_ADDSUB_TEST_BIN)
	./$(X87_EXACT_NONPOP_ADDSUB_TEST_BIN)

$(X87_EXACT_NONPOP_ADDSUB_TEST_BIN): tests/hb_x87_exact_nonpop_addsub_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-comparison-flags-test: $(X87_COMPARISON_FLAGS_TEST_BIN)
	./$(X87_COMPARISON_FLAGS_TEST_BIN)

$(X87_COMPARISON_FLAGS_TEST_BIN): tests/hb_x87_comparison_flags_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-ftst-flags-test: $(X87_FTST_FLAGS_TEST_BIN)
	./$(X87_FTST_FLAGS_TEST_BIN)

$(X87_FTST_FLAGS_TEST_BIN): tests/hb_x87_ftst_flags_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-ordered-comparison-flags-test: $(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN)
	./$(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN)

$(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN): tests/hb_x87_ordered_comparison_flags_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-bcd-success-fip-test: $(X87_BCD_SUCCESS_FIP_TEST_BIN)
	./$(X87_BCD_SUCCESS_FIP_TEST_BIN)

$(X87_BCD_SUCCESS_FIP_TEST_BIN): tests/hb_x87_bcd_success_fip_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-raw-ftst-test: $(X87_RAW_FTST_TEST_BIN)
	./$(X87_RAW_FTST_TEST_BIN)

$(X87_RAW_FTST_TEST_BIN): tests/hb_x87_raw_ftst_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-raw-fcomi-test: $(X87_RAW_FCOMI_TEST_BIN)
	./$(X87_RAW_FCOMI_TEST_BIN)

$(X87_RAW_FCOMI_TEST_BIN): tests/hb_x87_raw_fcomi_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-raw-fcom-test: $(X87_RAW_FCOM_TEST_BIN)
	./$(X87_RAW_FCOM_TEST_BIN)

$(X87_RAW_FCOM_TEST_BIN): tests/hb_x87_raw_fcom_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-mixed-cache-compare-test: $(X87_MIXED_CACHE_COMPARE_TEST_BIN)
	./$(X87_MIXED_CACHE_COMPARE_TEST_BIN)

$(X87_MIXED_CACHE_COMPARE_TEST_BIN): tests/hb_x87_mixed_cache_compare_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-raw-memory-compare-test: $(X87_RAW_MEMORY_COMPARE_TEST_BIN)
	./$(X87_RAW_MEMORY_COMPARE_TEST_BIN)

$(X87_RAW_MEMORY_COMPARE_TEST_BIN): tests/hb_x87_raw_memory_compare_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-infinity-compare-test: $(X87_INFINITY_COMPARE_TEST_BIN)
	./$(X87_INFINITY_COMPARE_TEST_BIN)

$(X87_INFINITY_COMPARE_TEST_BIN): tests/hb_x87_infinity_compare_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-masked-precision-test: $(X87_MASKED_PRECISION_TEST_BIN)
	./$(X87_MASKED_PRECISION_TEST_BIN)

$(X87_MASKED_PRECISION_TEST_BIN): tests/hb_x87_masked_precision_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-finite-bridge-test: $(X87_FINITE_BRIDGE_TEST_BIN)
	./$(X87_FINITE_BRIDGE_TEST_BIN)

$(X87_FINITE_BRIDGE_TEST_BIN): tests/hb_x87_finite_bridge_test.c src/hb_x87_exact.h $(STATIC_LIB)
	$(CC) $(CFLAGS) -I./src $< $(STATIC_LIB) -o $@

.PHONY: x87-finite-sqrt-bridge-test
x87-finite-sqrt-bridge-test: $(X87_FINITE_SQRT_BRIDGE_TEST_BIN)
	./$(X87_FINITE_SQRT_BRIDGE_TEST_BIN)

$(X87_FINITE_SQRT_BRIDGE_TEST_BIN): tests/hb_x87_finite_sqrt_bridge_test.c src/hb_x87_exact.h $(STATIC_LIB)
	$(CC) $(CFLAGS) -I./src $< $(STATIC_LIB) -o $@

.PHONY: x87-finite-sqrt-test
x87-finite-sqrt-test: $(X87_FINITE_SQRT_TEST_BIN)
	./$(X87_FINITE_SQRT_TEST_BIN)

$(X87_FINITE_SQRT_TEST_BIN): tests/hb_x87_finite_sqrt_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-finite-fxam-test
x87-finite-fxam-test: $(X87_FINITE_FXAM_TEST_BIN)
	./$(X87_FINITE_FXAM_TEST_BIN)

$(X87_FINITE_FXAM_TEST_BIN): tests/hb_x87_finite_fxam_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-finite-fxtract-test
x87-finite-fxtract-test: $(X87_FINITE_FXTRACT_TEST_BIN)
	./$(X87_FINITE_FXTRACT_TEST_BIN)

$(X87_FINITE_FXTRACT_TEST_BIN): tests/hb_x87_finite_fxtract_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-finite-sign-test
x87-cached-finite-sign-test: $(X87_CACHED_FINITE_SIGN_TEST_BIN)
	./$(X87_CACHED_FINITE_SIGN_TEST_BIN)

$(X87_CACHED_FINITE_SIGN_TEST_BIN): tests/hb_x87_cached_finite_sign_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-finite-fscale-test
x87-cached-finite-fscale-test: $(X87_CACHED_FINITE_FSCALE_TEST_BIN)
	./$(X87_CACHED_FINITE_FSCALE_TEST_BIN)

$(X87_CACHED_FINITE_FSCALE_TEST_BIN): tests/hb_x87_cached_finite_fscale_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-tiny-fsin-test
x87-cached-tiny-fsin-test: $(X87_CACHED_TINY_FSIN_TEST_BIN)
	./$(X87_CACHED_TINY_FSIN_TEST_BIN)

$(X87_CACHED_TINY_FSIN_TEST_BIN): tests/hb_x87_cached_tiny_fsin_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-tiny-fsincos-test
x87-cached-tiny-fsincos-test: $(X87_CACHED_TINY_FSINCOS_TEST_BIN)
	./$(X87_CACHED_TINY_FSINCOS_TEST_BIN)

$(X87_CACHED_TINY_FSINCOS_TEST_BIN): tests/hb_x87_cached_tiny_fsincos_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-tiny-fcos-test
x87-cached-tiny-fcos-test: $(X87_CACHED_TINY_FCOS_TEST_BIN)
	./$(X87_CACHED_TINY_FCOS_TEST_BIN)

$(X87_CACHED_TINY_FCOS_TEST_BIN): tests/hb_x87_cached_tiny_fcos_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-tiny-fptan-test
x87-cached-tiny-fptan-test: $(X87_CACHED_TINY_FPTAN_TEST_BIN)
	./$(X87_CACHED_TINY_FPTAN_TEST_BIN)

$(X87_CACHED_TINY_FPTAN_TEST_BIN): tests/hb_x87_cached_tiny_fptan_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-exact-fyl2x-test
x87-cached-exact-fyl2x-test: $(X87_CACHED_EXACT_FYL2X_TEST_BIN)
	./$(X87_CACHED_EXACT_FYL2X_TEST_BIN)

$(X87_CACHED_EXACT_FYL2X_TEST_BIN): tests/hb_x87_cached_exact_fyl2x_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

.PHONY: x87-cached-exact-fyl2xp1-test
x87-transcendental-guest-test: $(X87_TRANSCENDENTAL_GUEST_TEST_BIN)
	./$(X87_TRANSCENDENTAL_GUEST_TEST_BIN)

$(X87_TRANSCENDENTAL_GUEST_TEST_BIN): tests/hb_x87_transcendental_guest_test.c tests/transcendental_guest_test_reference.h tests/transcendental_guest_vectors.h tests/transcendental_guest_quadrants.h tests/transcendental_guest_rows.h tests/transcendental_guest_support.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-transcendental-component-test: $(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN)
	./$(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN)

$(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN): tests/transcendental_component/transcendental_component_test.c tests/transcendental_component/test_support.h tests/transcendental_component/reference_vectors.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) -Isrc $< $(STATIC_LIB) -o $@

x87-cached-exact-fyl2xp1-test: $(X87_CACHED_EXACT_FYL2XP1_TEST_BIN)
	./$(X87_CACHED_EXACT_FYL2XP1_TEST_BIN)

$(X87_CACHED_EXACT_FYL2XP1_TEST_BIN): tests/hb_x87_cached_exact_fyl2xp1_test.c tests/transcendental_guest_test_reference.h src/hb_x87_transcendental.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-exact-memory-arithmetic-test: $(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN)
	./$(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN)

$(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN): tests/hb_x87_exact_memory_arithmetic_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-exact-nonpop-muldiv-test: $(X87_EXACT_NONPOP_MULDIV_TEST_BIN)
	./$(X87_EXACT_NONPOP_MULDIV_TEST_BIN)

$(X87_EXACT_NONPOP_MULDIV_TEST_BIN): tests/hb_x87_exact_nonpop_muldiv_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-exact-muldiv-test: $(X87_EXACT_MULDIV_TEST_BIN)
	./$(X87_EXACT_MULDIV_TEST_BIN)

$(X87_EXACT_MULDIV_TEST_BIN): tests/hb_x87_exact_muldiv_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

fxstate-x87-test: $(FXSTATE_X87_TEST_BIN)
	./$(FXSTATE_X87_TEST_BIN)

$(FXSTATE_X87_TEST_BIN): tests/hb_fxstate_x87_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-integer-test: $(X87_INTEGER_TEST_BIN)
	./$(X87_INTEGER_TEST_BIN)

$(X87_INTEGER_TEST_BIN): tests/hb_x87_integer_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

x87-environment-test: $(X87_ENVIRONMENT_TEST_BIN)
	./$(X87_ENVIRONMENT_TEST_BIN)

$(X87_ENVIRONMENT_TEST_BIN): tests/hb_x87_environment_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

ripmap-index-test: $(RIPMAP_INDEX_TEST_BIN)
	./$(RIPMAP_INDEX_TEST_BIN)

logical-imm-test: $(LOGICAL_IMM_TEST_BIN)
	./$(LOGICAL_IMM_TEST_BIN)

$(LOGICAL_IMM_TEST_BIN): tests/hb_logical_imm_test.c include/hb_arm64_logical_imm.h
	$(CC) $(CFLAGS) $< -o $@

$(RIPMAP_INDEX_TEST_BIN): tests/ripmap_index.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# ★ 06.09.2026, лейн СЦЕПЛЕНИЕ — ПОСЕЩЕНО ПРОТИВ ИЗМЕНЕНО у обхода отзыва.
# Стенд, а НЕ часть цели test: у него две руки (обычная и отрицательный контроль
# MACRUNNER_HB_TEST_NO_TRAMP_REVOKE=1), и вторая НАМЕРЕННО исполняет мёртвое тело —
# такому не место в приёмке, которая обязана быть зелёной. Число приёмки от него
# не меняется. Гонять: make unchain-probe.
UNCHAIN_PROBE_BIN = tests/unchain_walk_probe

unchain-probe: $(UNCHAIN_PROBE_BIN)
	@echo "=== рука A: отзыв включён (ожидание: старых тел 0) ==="
	MACRUNNER_HB_UNCHAIN_STATS=1 ./$(UNCHAIN_PROBE_BIN)
	@echo "=== рука B: ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ, отзыв отключён ==="
	MACRUNNER_HB_UNCHAIN_STATS=1 MACRUNNER_HB_TEST_NO_TRAMP_REVOKE=1 ./$(UNCHAIN_PROBE_BIN)
	@echo "=== рука C: обход СНЯТ, отзыв включён (ожидание: старых тел 0) ==="
	MACRUNNER_HB_UNCHAIN_STATS=1 MACRUNNER_HB_UNCHAIN_WALK=0 ./$(UNCHAIN_PROBE_BIN)

$(UNCHAIN_PROBE_BIN): tests/unchain_walk_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПЕРЕПИСИ ПРИЧИН.
# В отличие от unchain-probe, эта повозка мёртвого кода НЕ исполняет и обязана быть
# зелёной, поэтому она ВХОДИТ в приёмку (цель povtor-probe зовётся из test).

povtor-probe: $(POVTOR_PROBE_BIN)
	MACRUNNER_HB_POVTOR_STATS=1 ./$(POVTOR_PROBE_BIN)

$(POVTOR_PROBE_BIN): tests/povtor_prichina_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — кеш косвенных после повторного перевода.
# Обе руки зелёные (рука B ПРОВЕРЯЕТ дефект, а не исполняет мёртвый код), поэтому
# цель входит в приёмку.

ic-retranslate-probe: $(IC_RETRANS_PROBE_BIN)
	@echo "=== рука A: правка включена (ожидание: занятость упала) ==="
	MACRUNNER_HB_INDIRECT_IC=1 MACRUNNER_HB_POVTOR_STATS=1 ./$(IC_RETRANS_PROBE_BIN)
	@echo "=== рука B: ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ, гашение подавлено ==="
	MACRUNNER_HB_INDIRECT_IC=1 MACRUNNER_HB_POVTOR_STATS=1 MACRUNNER_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE=1 ./$(IC_RETRANS_PROBE_BIN)

$(IC_RETRANS_PROBE_BIN): tests/ic_retranslate_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

probe-test: $(PROBE_TEST_BIN)
	./$(PROBE_TEST_BIN)

$(PROBE_TEST_BIN): tests/hb_probe_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

probe-zero-test: $(PROBE_ZERO_TEST_BIN)
	./$(PROBE_ZERO_TEST_BIN)

$(PROBE_ZERO_TEST_BIN): tests/hb_probe_zero_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# ★ 07.09.2026 — подопытный для scripts/тест-перепись-при-убийстве.sh. Сам по себе
# он ничего не проверяет: печатает «ГОТОВ» и виснет, пока его не снимут KILL. Обе руки
# A/B — этот ОДИН двоичный, рука выбирается аргументом (правило проекта об A/B).
# В цель test не подключён нарочно: `make test` не должен убивать процессы.
PROBE_KILL_BIN = tests/hb_probe_kill_probe

probe-kill-probe: $(PROBE_KILL_BIN)

$(PROBE_KILL_BIN): tests/hb_probe_kill_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

cache-stamp-test: $(CACHE_STAMP_TEST_BIN)
	./$(CACHE_STAMP_TEST_BIN)

$(CACHE_STAMP_TEST_BIN): tests/hb_cache_build_stamp_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

$(TEST_BIN): tests/hb_test_runner.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@

contract-telemetry-test: $(CONTRACT_TELEMETRY_TEST_BIN)
	./$(CONTRACT_TELEMETRY_TEST_BIN)

# ★ 06.09.2026, лейн КЕШ — ЦЕЛЬ НЕ СОБИРАЛАСЬ, И ЭТОГО НИКТО НЕ ВИДЕЛ.
#
# С 04.09, когда таблица гейтов уехала в hb_gates_tbl.c, здесь оставался ОДИН объект, и
# линковка падала на _hb_gate_tbl. В `make test` цель не входит — приёмка была зелёной, а
# сторож телеметрии мёртвым. Линковка починена (против $(STATIC_LIB)).
#
# ОСТАВШИЙСЯ ДЕФЕКТ, НАЗЫВАЮ ВСЛУХ, А НЕ ЗАМАЛЧИВАЮ: сам тест теперь СОБИРАЕТСЯ и ПАДАЕТ
# тремя проверками. Причина не в телеметрии, а в том же переезде: тест переключает режим
# через setenv() посреди прогона, а таблица гейтов снимает окружение ОДИН раз при
# заполнении, и hb_contract_telemetry_enabled() кеширует результат. То есть тест написан
# под hb_env() и под таблицу не переписан. Чинится переносом двух режимов в два процесса
# (fork либо два запуска с разным окружением) — отдельная работа, здесь не сделана.
$(CONTRACT_TELEMETRY_TEST_BIN): tests/hb_contract_telemetry_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

bench: $(STATIC_LIB) $(BENCH_BIN)
	./$(BENCH_BIN) > reports/hyperbridge-bench.json 2>&1 || true
	@echo "Benchmark results in reports/hyperbridge-bench.json"

report:
	python3 tools/hb_report.py

# --- ПЕРЕПИСЬ ПРИЧИН ОТКАЗА ПРЯМОГО ПУТИ К ПАМЯТИ (04.09.2026) ------------------------------
# Зачем отдельный стенд. Сводки семей DM/DL считают решения КОДОГЕНЕРАЦИИ, а hb_test_runner
# принимает их всего полторы сотни — по такой популяции доли не читаются. Здесь тот же декодер,
# тот же лифтер и тот же выпуск гоняются по исполняемой секции настоящих PE из fixtures/:
# 43 тыс. решений на x64 и 28 тыс. на i386, и прогон игры для этого не нужен.
#
# Обе семьи печатают итог НА ВЫХОДЕ, поэтому «ноль отказов» отличимо от «не считалось».
PEREPIS_BIN = tests/dm_perepis
$(PEREPIS_BIN): tests/dm_perepis.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

perepis-directmem: $(PEREPIS_BIN)
	@echo "--- x64 ---"
	@MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_JCC_CC_CENSUS=1 \
	 MACRUNNER_HB_DIRECT_MEM_STATS=100000000 ./$(PEREPIS_BIN) \
	 ../../fixtures/x64/*.exe ../../fixtures/x64/*.dll 2>&1 | \
	 grep -E 'перепись:|причины\(выход\)|directmem: |directload: '
	@echo "--- i386 ---"
	@MACRUNNER_HB_JIT_DIRECT_MEM=1 MACRUNNER_HB_NATIVE_MEM_I386=1 MACRUNNER_HB_JCC_CC_CENSUS=1 \
	 MACRUNNER_HB_DIRECT_MEM_STATS=100000000 ./$(PEREPIS_BIN) ../../fixtures/x86/*.exe 2>&1 | \
	 grep -E 'перепись:|причины\(выход\)|directmem: |directload: '

clean:
	rm -f $(BIT_STRING_TEST_BIN) $(SEGMENT_ADDRESS_TEST_BIN) $(ABI_X64_STATE_TEST_BIN) $(ABI_X64_FRAME_TEST_BIN) $(ABI_X64_V1_TEST_BIN) $(ABI_NATIVE_V1_TEST_BIN) $(MXCSR_TEST_BIN) $(FXSTATE_MXCSR_TEST_BIN) $(SSE_INTEGER_ROUNDING_TEST_BIN) $(FXSTATE_X87_TEST_BIN) $(X87_INTEGER_TEST_BIN) $(X87_ENVIRONMENT_TEST_BIN) $(VEX_UPPER_STATE_TEST_BIN) $(ROUND_INSTRUCTION_TEST_BIN) $(HALF_CONVERSION_TEST_BIN) $(X87_FRNDINT_TEST_BIN) $(DIAGNOSTIC_FENV_TEST_BIN) $(X87_FPREM_TEST_BIN) $(X87_BCD_TEST_BIN) $(X87_BCD_LOAD_TEST_BIN) $(X87_LOADED_STATUS_TEST_BIN) $(CONTEXT_RESET_FAULT_TEST_BIN) $(FXSTATE_ALIGNMENT_TEST_BIN) $(X87_FLOATING_LOAD_STATUS_TEST_BIN) $(X87_RAW_LOAD_TEST_BIN) $(X87_SHORT_ENVIRONMENT_TEST_BIN) $(XSAVE_STATE_TEST_BIN) $(XGETBV_INDEX_TEST_BIN) $(X87_REGISTER_TRANSFER_TEST_BIN) $(XSTATE_ADMISSION_TEST_BIN) $(X87_EXACT_ADDSUB_TEST_BIN) $(X87_ARITHMETIC_DESTINATION_TEST_BIN) $(X87_FIP_CLASSIFICATION_TEST_BIN) $(X87_EXACT_NONPOP_ADDSUB_TEST_BIN) $(X87_COMPARISON_FLAGS_TEST_BIN) $(X87_FTST_FLAGS_TEST_BIN) $(X87_ORDERED_COMPARISON_FLAGS_TEST_BIN) $(X87_BCD_SUCCESS_FIP_TEST_BIN) $(X87_RAW_FTST_TEST_BIN) $(X87_RAW_FCOMI_TEST_BIN) $(X87_RAW_FCOM_TEST_BIN) $(X87_MIXED_CACHE_COMPARE_TEST_BIN) $(X87_RAW_MEMORY_COMPARE_TEST_BIN) $(X87_INFINITY_COMPARE_TEST_BIN) $(X87_EXACT_MULDIV_TEST_BIN) $(X87_EXACT_NONPOP_MULDIV_TEST_BIN) $(X87_EXACT_MEMORY_ARITHMETIC_TEST_BIN) $(X87_FINITE_BRIDGE_TEST_BIN) $(X87_MASKED_PRECISION_TEST_BIN) $(X87_FINITE_SQRT_BRIDGE_TEST_BIN) $(X87_FINITE_SQRT_TEST_BIN) $(X87_FINITE_FXAM_TEST_BIN) $(X87_FINITE_FXTRACT_TEST_BIN) $(X87_CACHED_FINITE_SIGN_TEST_BIN) $(X87_CACHED_FINITE_FSCALE_TEST_BIN) $(X87_CACHED_TINY_FSIN_TEST_BIN) $(X87_CACHED_TINY_FSINCOS_TEST_BIN) $(X87_CACHED_TINY_FCOS_TEST_BIN) $(X87_CACHED_TINY_FPTAN_TEST_BIN) $(X87_CACHED_EXACT_FYL2X_TEST_BIN) $(X87_CACHED_EXACT_FYL2XP1_TEST_BIN) $(X87_TRANSCENDENTAL_COMPONENT_TEST_BIN) $(X87_TRANSCENDENTAL_GUEST_TEST_BIN)
	rm -f $(OBJS) $(DEPS) $(STATIC_LIB) $(SHARED_LIB) $(TEST_BIN) $(CONTRACT_TELEMETRY_TEST_BIN) $(BENCH_BIN) $(RIPMAP_INDEX_TEST_BIN) $(PEREPIS_BIN)
	rm -rf reports/*.json reports/*.md

-include $(DEPS)

# --- сторож природы отказа исполнения (лейн ЛЕСТНИЦА, итерация 772) ---
# Пометка #DE против перехода по нулю стоит в 26 местах ДВУХ исполнителей; по ней
# macrunner_hb.c решает, какое исключение доставить гостю. Тест ловит тихую потерю пометки
# без прогона игры. У него есть отрицательный контроль: HB_FAULT_TEST_NEGATIVE=1 переворачивает
# ожидания, и тогда он ОБЯЗАН вернуть 1 (проверено: 0 против 1, отказов 4 из 6).
FAULT_KIND_TEST_BIN = tests/hb_fault_kind_test
fault-kind-test: $(FAULT_KIND_TEST_BIN)
	./$(FAULT_KIND_TEST_BIN)
	@HB_FAULT_TEST_NEGATIVE=1 ./$(FAULT_KIND_TEST_BIN) >/dev/null 2>&1 && \
	  { echo "ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ НЕ СРАБОТАЛ: тест прошёл с неверными ожиданиями"; exit 1; } || \
	  echo "отрицательный контроль: тест отказывает на неверных ожиданиях — ok"
$(FAULT_KIND_TEST_BIN): tests/hb_fault_kind_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- стенд самосогласованности слоя памяти (лейн ПАМЯТЬ, ступень 7) -------------------------
# Предикат и операция на одном диапазоне обязаны давать один ответ.  Эталон снаружи не нужен,
# виртуалка и прогон игры не нужны.  Отрицательный контроль обязателен: HB_MEMCONTRACT_NEGATIVE=1
# переворачивает ожидания, и стенд ОБЯЗАН отказать — иначе он не измеряет ничего.
MEMORY_CONTRACT_TEST_BIN = tests/hb_memory_contract_test
SMC_REVERIFY_CONTROL_BIN = tests/hb_smc_reverify_control
# Лейн ВЫПУСК, итерация 8: порядок памяти — пробы herdtools7 (ступень 8).
# herd7 — проверка МОДЕЛЬЮ, litmus7 — прогон на ЖИВОМ ядре. Оба из ~/.opam; если их нет,
# цель говорит об этом и не притворяется, что проверка прошла.
litmus-tso:
	@command -v herd7 >/dev/null || { echo "herd7 НЕ УСТАНОВЛЕН: opam install herdtools7"; exit 1; }
	@echo "--- модель: чего требует САМ x86"
	@cd tests/litmus && for f in MP-x86 LB-x86 SB-x86; do herd7 $$f.litmus 2>&1 | grep '^Observation'; done
	@echo "--- модель: что даёт НАШ выпускаемый узор (STLR + LDR;DMB ISHLD)"
	@cd tests/litmus && for f in MP-ours LB-ours SB-ours; do herd7 $$f.litmus 2>&1 | grep '^Observation'; done
	@echo "--- модель: окно (тот же узор БЕЗ барьеров)"
	@cd tests/litmus && for f in MP-plain LB-plain SB-plain; do herd7 $$f.litmus 2>&1 | grep '^Observation'; done

# Прогон на живом ядре: 4 млн исполнений каждой пробы. Долго и грузит машину — держи замок.
litmus-tso-hw:
	@command -v litmus7 >/dev/null || { echo "litmus7 НЕ УСТАНОВЛЕН: opam install herdtools7"; exit 1; }
	@rm -rf /tmp/hb-litmus && mkdir -p /tmp/hb-litmus
	@cd tests/litmus && litmus7 -avail 4 -o /tmp/hb-litmus \
		MP-plain.litmus MP-ours.litmus LB-plain.litmus LB-ours.litmus \
		SB-plain.litmus SB-ours.litmus >/dev/null
	@cd /tmp/hb-litmus && sh comp.sh >/dev/null 2>&1; \
		for t in MP-plain MP-ours LB-plain LB-ours SB-plain SB-ours; do \
			./$$t.exe -s 5000 -r 400 2>&1 | grep '^Observation'; done

# Лейн ВЫПУСК, итерация 7: цена барьеров памяти на НАШЕМ ядре (ступень 8).
BARRIER_COST_PROBE_BIN = tests/hb_barrier_cost_probe

$(BARRIER_COST_PROBE_BIN): tests/hb_barrier_cost_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $(ARCH_FLAGS) tests/hb_barrier_cost_probe.c $(STATIC_LIB) -o $@

barrier-cost-probe: $(BARRIER_COST_PROBE_BIN)
	./$(BARRIER_COST_PROBE_BIN) 200000

# Лейн ВЫПУСК, итерация 5: порог окупаемости «свой выпуск против помощника».
# Гейт кешируется на процесс, поэтому руки — ДВА запуска, и они чередуются, а не «сначала все A».
NATIVE_BMI_BENCH_BIN = tests/hb_native_bmi_bench

$(NATIVE_BMI_BENCH_BIN): tests/hb_native_bmi_bench.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $(ARCH_FLAGS) tests/hb_native_bmi_bench.c $(STATIC_LIB) -o $@

native-bmi-bench: $(NATIVE_BMI_BENCH_BIN)
	@echo "--- свидетель гейта: карта выпуска обеих рук"
	@MACRUNNER_HB_EMIT_MAP=1 MACRUNNER_HB_NATIVE_BMI=0 ./$(NATIVE_BMI_BENCH_BIN) 1 2>&1 | grep 'emit-map' || true
	@MACRUNNER_HB_EMIT_MAP=1 MACRUNNER_HB_NATIVE_BMI=1 ./$(NATIVE_BMI_BENCH_BIN) 1 2>&1 | grep 'emit-map' || true
	@echo "--- рука ПОМОЩНИК"
	@MACRUNNER_HB_NATIVE_BMI=0 ./$(NATIVE_BMI_BENCH_BIN) 5
	@echo "--- рука СВОЙ ВЫПУСК"
	@MACRUNNER_HB_NATIVE_BMI=1 ./$(NATIVE_BMI_BENCH_BIN) 5
	@echo "--- петля CRC32: помощник против своей команды ARM64"
	@MACRUNNER_HB_NATIVE_CRC32=0 ./$(NATIVE_BMI_BENCH_BIN) 5 crc
	@MACRUNNER_HB_NATIVE_CRC32=1 ./$(NATIVE_BMI_BENCH_BIN) 5 crc

# Лейн ВЫПУСК, итерация 4: почему плавает `interp_x64_control_state_setjmp_family`.
# Отдельный двоичный, потому что в наборе отказ появляется примерно в половине прогонов, а
# изолированно не воспроизводится ни разу — проба это и показывает числом.
CTRLSTATE_PROBE_BIN = tests/hb_ctrlstate_frame_probe

$(CTRLSTATE_PROBE_BIN): tests/hb_ctrlstate_frame_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $(ARCH_FLAGS) tests/hb_ctrlstate_frame_probe.c $(STATIC_LIB) -o $@

ctrlstate-frame-probe: $(CTRLSTATE_PROBE_BIN)
	./$(CTRLSTATE_PROBE_BIN) 24

# Лейн ПАМЯТЬ, итерация 8: стенд границы вызовов (вторая половина ступени 7).
THUNK_CONTRACT_TEST_BIN = tests/hb_thunk_contract_test

$(THUNK_CONTRACT_TEST_BIN): tests/hb_thunk_contract_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $(ARCH_FLAGS) tests/hb_thunk_contract_test.c $(STATIC_LIB) -o $@

thunk-contract-test: $(THUNK_CONTRACT_TEST_BIN)
	./$(THUNK_CONTRACT_TEST_BIN)
	@echo "--- отрицательный контроль: стенд ОБЯЗАН отказать"
	@HB_THUNKCONTRACT_NEGATIVE=1 ./$(THUNK_CONTRACT_TEST_BIN) > /dev/null 2>&1 \
	  && { echo "ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ НЕ СРАБОТАЛ"; exit 1; } \
	  || echo "отрицательный контроль: стенд отказал — ok"

memory-contract-test: $(MEMORY_CONTRACT_TEST_BIN)
	./$(MEMORY_CONTRACT_TEST_BIN)
	@HB_MEMCONTRACT_NEGATIVE=1 ./$(MEMORY_CONTRACT_TEST_BIN) >/dev/null 2>&1 && \
	  { echo "ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ НЕ СРАБОТАЛ: стенд прошёл с перевёрнутыми ожиданиями"; exit 1; } || \
	  echo "отрицательный контроль: стенд отказывает на перевёрнутых ожиданиях — ok"
$(MEMORY_CONTRACT_TEST_BIN): tests/hb_memory_contract_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- direct-mem cross-thread coherence reproducer (Lane A vector 3) ---
COHERENCE_REPRO = tests/hb_direct_mem_coherence_repro
coherence-repro: $(STATIC_LIB) $(COHERENCE_REPRO)
	@echo "Build OK: $(COHERENCE_REPRO)"
$(COHERENCE_REPRO): tests/hb_direct_mem_coherence_repro.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread

# --- XMM logic pair: second memory operand must not clobber src1.hi in x22 (HK black frame, 26.09) ---
# Отрицательный контроль: против ядра до правки emit_load_xmm_operand_to_pair даёт TOTAL_BAD=6.
xmm-pair-x22-test: $(XMM_PAIR_X22_TEST_BIN)
	./$(XMM_PAIR_X22_TEST_BIN)
$(XMM_PAIR_X22_TEST_BIN): tests/hb_xmm_pair_x22_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- adjacent-mem64 LDP fusion stale-base reproducer (HK mono hash-chain walk) ---
ADJ_CLOBBER_REPRO = tests/hb_adjacent_mem64_clobber_repro
adjacent-clobber-repro: $(STATIC_LIB) $(ADJ_CLOBBER_REPRO)
	@echo "Build OK: $(ADJ_CLOBBER_REPRO)"
$(SMC_FASTPATH_TEST_BIN): tests/hb_smc_fastpath_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- VEX.128 MOVD/MOVQ: native emission must zero ymm_hi of the destination (26.09) ---
# Отрицательный контроль: против ядра до правки JIT даёт TOTAL_BAD=4 (xmm0..3), интерпретатор чист.
$(VEX_MOVD_YMM_TEST_BIN): tests/hb_vex_movd_ymm_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- Native SSE FP emission must match the interpreter bit for bit on special values (26.09) ---
# Контроль: MACRUNNER_HB_TEST_SSE_FP_NO_SLOW=1 снимает медленный путь по NaN -> 1410 расхождений.
$(SSE_FP_NATIVE_TEST_BIN): tests/hb_sse_fp_native_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- Native BT with pending lazy flags (26.09); control: ZF_INVERT -> 10240 differences ---
$(BT_PENDING_NATIVE_TEST_BIN): tests/hb_bt_pending_native_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- VEX.256 load/store and VEX.128 load upper state (26.09); old core fails the VEX.128 load ---
$(VEX_YMM_MOVE_TEST_BIN): tests/hb_vex_ymm_move_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- Jcc/CMOVcc/SETcc from pending lazy flags without a helper call (26.09); controls: FLIP -> 1280
# differences, gate off -> no native emission, codegen without the materialized_mask check -> 646 ---
$(LAZY_COND_NATIVE_TEST_BIN): tests/hb_lazy_cond_native_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- Vector upper state (Astra, 26.09): x86 corpus of 784 programs x 3 seeds, 32 x 512-bit registers.
# Without the U01 patch the fused pair differs in 33 of 63; the EVEX opmask class (M01) is excluded. ---
$(UPPER_STATE_TEST_BIN): tests/hb_upper_audit/hb_upper_state_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- EVEX disp8*N (26.09): the decoder against a table generated from capstone by
# tests/hb_evex_disp8/sweep.py; before the fix 956 of 962 x64 forms had a wrong address ---
$(EVEX_DISP8_TEST_BIN): tests/hb_evex_disp8_test.c tests/hb_evex_disp8/table64.inc tests/hb_evex_disp8/table32.inc $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

# --- Hardware SSE oracle (Astra, 26.09): runner extension + x86-recorded corpora ---
$(SSE_ORACLE_RUNNER_BIN): tests/hb_diff_case_runner.c tests/hb_sse_oracle/runner_extension.h $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@

$(ADJ_CLOBBER_REPRO): tests/hb_adjacent_mem64_clobber_repro.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread

# MacRunner 19.08, лейн ЛЕСТНИЦА итерация 2596.
# У ../../tools/hb_smc_reverify_control.c НЕ БЫЛО цели make — поэтому он был красным
# минимум с 11.08 и этого никто не видел. Цель добавлена вместе с ОБЕИМИ руками:
# гейт по умолчанию и MACRUNNER_HB_SMC_REVERIFY=0. Рука «выключено» здесь и есть
# отрицательный контроль: она обязана показать tracked=0 evicted=0, иначе гейт не работает.
smc-reverify-control: $(SMC_REVERIFY_CONTROL_BIN)
	./$(SMC_REVERIFY_CONTROL_BIN)
	@MACRUNNER_HB_SMC_REVERIFY=0 ./$(SMC_REVERIFY_CONTROL_BIN) disabled
$(SMC_REVERIFY_CONTROL_BIN): ../../tools/hb_smc_reverify_control.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@
# ─── ОПОРА ПРИЁМКИ ───────────────────────────────────────────────────────────
# 485/0 достижимо ТОЛЬКО с MACRUNNER_HB_PROMOTE_FAMILIES=1. Без него ровно
# девять тестов падают (циклы/строковые), и это НЕ регресс — это другой режим
# движка: промоция семейств выключена по умолчанию, потому что стоит -3x к
# старту (см. память nine-of-thirteen-acceptance-failures-are-a-disabled-gate).
#
# 29.08.2026 я потерял полчаса, объявив 476/9 регрессом и не проверив гейт.
# Цель ниже не даёт повторить: она сама ставит гейт и сверяет число.
BASELINE_TESTS := 485

опора: $(STATIC_LIB) $(TEST_BIN)
	@echo "── приёмка на ОПОРЕ (MACRUNNER_HB_PROMOTE_FAMILIES=1) ──"
	@MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 MACRUNNER_HB_PROMOTE_FAMILIES=1 ./$(TEST_BIN) 2>&1 | grep -a "passed" | tail -1 | \
	  awk -v want=$(BASELINE_TESTS) '{ print "  " $$0; \
	    if ($$1 == want && $$3 == 0) print "  ✅ ОПОРА ДЕРЖИТСЯ: " want "/0"; \
	    else { print "  ❌ ОПОРА СЪЕХАЛА: ждали " want "/0, вышло " $$1 "/" $$3; exit 1 } }'

.PHONY: опора

# ★★★★ 2026-09-14 — СТОРОЖ КОНТРАКТА ПАМЯТИ И ОТКАЗОВ (outputs/memory-fault-batch-assessment.md).
# Пять приборов лежали вне сборки и вне приёмки; pamyat_mt_race при этом был КРАСНЫМ
# (986/850/932 порванных слов — нарушение single-copy-атомарности на пути помощника,
# outputs/memory-fault-guard-01..02). Теперь все пять — предпосылка цели test.
MEMORY_FAULT_GUARD_BINS = tests/kraya_otkazov tests/fault_precision_probe tests/hb_memory_protect_range_test tests/pamyat_smc_exec_restore tests/pamyat_mt_race tests/zhizn_kesha_matrix
tests/kraya_otkazov: tests/kraya_otkazov.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
tests/fault_precision_probe: tests/fault_precision_probe.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
tests/hb_memory_protect_range_test: tests/hb_memory_protect_range_test.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
tests/pamyat_smc_exec_restore: tests/pamyat_smc_exec_restore.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
tests/pamyat_mt_race: tests/pamyat_mt_race.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
# 14.09.2026, пункт 6 карты (SMC / время жизни кеша): матрица К/Р1/Р2/Р4/Р5 — своя среда,
# чужая среда (как зовёт клей Wine), процесс-широкое кольцо, в полёте. Стадии
# outputs/cache-lifetime-01..02.
tests/zhizn_kesha_matrix: tests/zhizn_kesha_matrix.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< $(STATIC_LIB) -o $@ -lpthread
.PHONY: memory-fault-guard
memory-fault-guard: $(MEMORY_FAULT_GUARD_BINS)
	@echo "Running memory/fault + cache-lifetime contract guard (6 instruments)..."
	./tests/kraya_otkazov
	./tests/fault_precision_probe
	./tests/hb_memory_protect_range_test
	./tests/pamyat_smc_exec_restore
	./tests/pamyat_mt_race
	./tests/zhizn_kesha_matrix
