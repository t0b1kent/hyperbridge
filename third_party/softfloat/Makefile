# Explicit independently linked subset of the retained SoftFloat-derived fork.
# All104 source files remain; orphan f128_to_f16/f128_mulAdd/f128_to_ui32 are unavailable.
SOFTFLOAT_ROOT := third_party/softfloat
SOFTFLOAT_SRCS := \
  $(SOFTFLOAT_ROOT)/src/extF80_add.c \
  $(SOFTFLOAT_ROOT)/src/extF80_div.c \
  $(SOFTFLOAT_ROOT)/src/extF80_sub.c \
  $(SOFTFLOAT_ROOT)/src/extF80_mul.c \
  $(SOFTFLOAT_ROOT)/src/extF80_rem.c \
  $(SOFTFLOAT_ROOT)/src/extF80_sqrt.c \
  $(SOFTFLOAT_ROOT)/src/extF80_le.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_i32.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_i64.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_ui64.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_f32.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_f64.c \
  $(SOFTFLOAT_ROOT)/src/i32_to_extF80.c \
  $(SOFTFLOAT_ROOT)/src/ui64_to_extF80.c \
  $(SOFTFLOAT_ROOT)/src/extF80_to_f128.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_extF80.c \
  $(SOFTFLOAT_ROOT)/src/f128_add.c \
  $(SOFTFLOAT_ROOT)/src/f128_div.c \
  $(SOFTFLOAT_ROOT)/src/f128_eq.c \
  $(SOFTFLOAT_ROOT)/src/f128_eq_signaling.c \
  $(SOFTFLOAT_ROOT)/src/f128_isSignalingNaN.c \
  $(SOFTFLOAT_ROOT)/src/f128_le.c \
  $(SOFTFLOAT_ROOT)/src/f128_le_quiet.c \
  $(SOFTFLOAT_ROOT)/src/f128_lt.c \
  $(SOFTFLOAT_ROOT)/src/f128_lt_quiet.c \
  $(SOFTFLOAT_ROOT)/src/f128_mul.c \
  $(SOFTFLOAT_ROOT)/src/f128_rem.c \
  $(SOFTFLOAT_ROOT)/src/f128_sqrt.c \
  $(SOFTFLOAT_ROOT)/src/f128_sub.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_f32.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_f64.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_i32.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_i64.c \
  $(SOFTFLOAT_ROOT)/src/f128_to_ui64.c \
  $(SOFTFLOAT_ROOT)/src/s_addMagsF128.c \
  $(SOFTFLOAT_ROOT)/src/s_subMagsF128.c \
  $(SOFTFLOAT_ROOT)/src/s_normRoundPackToF128.c \
  $(SOFTFLOAT_ROOT)/src/s_roundPackToF128.c \
  $(SOFTFLOAT_ROOT)/src/s_propagateNaNF128UI.c \
  $(SOFTFLOAT_ROOT)/src/f32_to_f128.c \
  $(SOFTFLOAT_ROOT)/src/i32_to_f128.c \
  $(SOFTFLOAT_ROOT)/src/s_roundToUI64.c \
  $(SOFTFLOAT_ROOT)/src/s_f128UIToCommonNaN.c \
  $(SOFTFLOAT_ROOT)/src/s_commonNaNToF128UI.c \
  $(SOFTFLOAT_ROOT)/src/s_normSubnormalF128Sig.c \
  $(SOFTFLOAT_ROOT)/src/s_roundToI32.c \
  $(SOFTFLOAT_ROOT)/src/s_roundToI64.c \
  $(SOFTFLOAT_ROOT)/src/s_roundPackToF32.c \
  $(SOFTFLOAT_ROOT)/src/s_addMagsExtF80.c \
  $(SOFTFLOAT_ROOT)/src/s_extF80UIToCommonNaN.c \
  $(SOFTFLOAT_ROOT)/src/s_commonNaNToF32UI.c \
  $(SOFTFLOAT_ROOT)/src/s_commonNaNToF64UI.c \
  $(SOFTFLOAT_ROOT)/src/s_roundPackToF64.c \
  $(SOFTFLOAT_ROOT)/src/s_propagateNaNExtF80UI.c \
  $(SOFTFLOAT_ROOT)/src/s_roundPackToExtF80.c \
  $(SOFTFLOAT_ROOT)/src/s_normSubnormalExtF80Sig.c \
  $(SOFTFLOAT_ROOT)/src/s_subMagsExtF80.c \
  $(SOFTFLOAT_ROOT)/src/s_shiftRightJam128.c \
  $(SOFTFLOAT_ROOT)/src/s_shiftRightJam128Extra.c \
  $(SOFTFLOAT_ROOT)/src/s_normRoundPackToExtF80.c \
  $(SOFTFLOAT_ROOT)/src/s_approxRecip_1Ks.c \
  $(SOFTFLOAT_ROOT)/src/s_approxRecipSqrt32_1.c \
  $(SOFTFLOAT_ROOT)/src/s_approxRecipSqrt_1Ks.c \
  $(SOFTFLOAT_ROOT)/src/softfloat_raiseFlags.c \
  $(SOFTFLOAT_ROOT)/src/f64_to_extF80.c \
  $(SOFTFLOAT_ROOT)/src/s_commonNaNToExtF80UI.c \
  $(SOFTFLOAT_ROOT)/src/s_normSubnormalF64Sig.c \
  $(SOFTFLOAT_ROOT)/src/s_f64UIToCommonNaN.c \
  $(SOFTFLOAT_ROOT)/src/extF80_roundToInt.c \
  $(SOFTFLOAT_ROOT)/src/extF80_eq.c \
  $(SOFTFLOAT_ROOT)/src/extF80_lt.c \
  $(SOFTFLOAT_ROOT)/src/f32_to_extF80.c \
  $(SOFTFLOAT_ROOT)/src/s_normSubnormalF32Sig.c \
  $(SOFTFLOAT_ROOT)/src/s_f32UIToCommonNaN.c
SOFTFLOAT_OBJS := $(SOFTFLOAT_SRCS:.c=.o)
SOFTFLOAT_HEADERS := $(wildcard $(SOFTFLOAT_ROOT)/include/SoftFloat-3e/*.h) $(wildcard $(SOFTFLOAT_ROOT)/src/*.h)
SOFTFLOAT_CONFIG := -DFEXCORE_PRESERVE_ALL_ATTR= -DFEXCORE_HAS_PRESERVE_ALL_ATTR=0 \
  -DSOFTFLOAT_BUILTIN_CLZ=1 '-DINLINE=static inline' -DINLINE_LEVEL=4 \
  -DSOFTFLOAT_FAST_INT64=1 -DSOFTFLOAT_FAST_DIV32TO16=1 -DSOFTFLOAT_FAST_DIV64TO32=1 \
  -I$(SOFTFLOAT_ROOT)/include -I$(SOFTFLOAT_ROOT)/include/SoftFloat-3e

# Keep component floating arithmetic independent of ambient host FP assumptions.
# Ordinary C ABI; no FEX headers, archive, runtime, architecture detection or thunks.
$(SOFTFLOAT_OBJS) src/hb_x87_exact.o: third_party/softfloat/Makefile

$(SOFTFLOAT_OBJS): %.o: %.c
	$(CC) $(filter-out -std=c11,$(CFLAGS)) -std=gnu11 -fno-fast-math -fno-lto $(SOFTFLOAT_CONFIG) -c $< -o $@

src/hb_x87_exact.o: src/hb_x87_exact.c
	$(CC) $(CFLAGS) -fno-fast-math -fno-lto $(SOFTFLOAT_CONFIG) -c $< -o $@
