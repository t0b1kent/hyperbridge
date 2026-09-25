/* Canonical infinity register/memory comparisons, with literal represented values.
 * Normal/zero controls retain exact raw authority; inactive shadows are poison.
 * Pending, raw/source denormal and IM0-empty cases assert inherited compatibility.
 * No NaN/unsupported exception, FIP timing, enabled-host-trap or full-PC claim.
 * All 74 guest forms run through x86/x64 interpreter/JIT with private memory. */
#pragma STDC FENV_ACCESS ON
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


enum { PAGE_BYTES=16384 };
enum { LESS,EQUAL,GREATER };
enum { MAIN,PENDING,EMPTY,RAW_DENORMAL,SOURCE_DENORMAL,EDGE,NO_READ,TRUNCATED,UNMAPPED };
enum { REGISTER,REAL32,REAL64,INT16,INT32 };
enum { X87_STATUS,INTEGER_FLAGS,STATE,EXECUTION,HOST,DECODE,MEMORY,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x7100000),DATA=UINT64_C(0x7120000),DENIED=UINT64_C(0x7128000);
static unsigned checks,failures,executions,register_main,memory_main,pending_cases,empty_cases,raw_denormal_cases,source_denormal_cases,span_cases,integer_cases,ordinary_cases;
static unsigned category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag,valid;} raw_t;
typedef struct {const char *name;raw_t a,b;uint64_t memory[4];unsigned relation,preview_relation;} sample_t;
static const sample_t register_samples[]={
    {"huge_raw_inf",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"raw_inf_huge",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_huge_raw_inf",{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_raw_inf_huge",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"huge_uncached_inf",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"uncached_inf_huge",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_huge_uncached_inf",{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_uncached_inf_huge",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"extreme_raw_inf",{0x7e7f,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"raw_inf_extreme",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x7e7f,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_extreme_raw_inf",{0xfe7f,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL},
    {"negative_raw_inf_extreme",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0xfe7f,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,EQUAL},
    {"positive_inf_equal",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_inf_equal",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_positive_inf",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS},
    {"positive_negative_inf",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"positive_mixed_inf_equal",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_mixed_inf_equal",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"positive_inf_negative_zero",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x8000000000000000),1,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"negative_inf_positive_zero",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS},
    {"uncached_positive_negative_inf",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"uncached_negative_positive_inf",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS},
    {"mixed_signed_zeros",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000000),1,0},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"retained_low_raw_bit",{0x3fff,UINT64_C(0x8000000000000001),UINT64_C(0x3ff0000000000000),0,1},{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x3ff0000000000000),0,0},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,EQUAL}
};
static const sample_t real_samples[]={
    {"huge_positive_positive_inf",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000007f800000),UINT64_C(0x7ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},LESS,EQUAL},
    {"huge_positive_negative_inf",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000ff800000),UINT64_C(0xfff0000000000000),UINT64_C(0xffffffffffffffff),UINT64_C(0xffffffffffffffff)},GREATER,GREATER},
    {"huge_negative_positive_inf",{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000007f800000),UINT64_C(0x7ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},LESS,LESS},
    {"huge_negative_negative_inf",{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000ff800000),UINT64_C(0xfff0000000000000),UINT64_C(0xffffffffffffffff),UINT64_C(0xffffffffffffffff)},GREATER,EQUAL},
    {"extreme_positive_positive_inf",{0x7e7f,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000007f800000),UINT64_C(0x7ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},LESS,EQUAL},
    {"extreme_negative_negative_inf",{0xfe7f,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000ff800000),UINT64_C(0xfff0000000000000),UINT64_C(0xffffffffffffffff),UINT64_C(0xffffffffffffffff)},GREATER,EQUAL},
    {"positive_positive_inf",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000007f800000),UINT64_C(0x7ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},EQUAL,EQUAL},
    {"positive_negative_inf",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000ff800000),UINT64_C(0xfff0000000000000),UINT64_C(0xffffffffffffffff),UINT64_C(0xffffffffffffffff)},GREATER,GREATER},
    {"negative_positive_inf",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000007f800000),UINT64_C(0x7ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},LESS,LESS},
    {"negative_negative_inf",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000ff800000),UINT64_C(0xfff0000000000000),UINT64_C(0xffffffffffffffff),UINT64_C(0xffffffffffffffff)},EQUAL,EQUAL},
    {"positive_inf_positive_one",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x000000003f800000),UINT64_C(0x3ff0000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000001)},GREATER,GREATER},
    {"negative_inf_negative_one",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x00000000bf800000),UINT64_C(0xbff0000000000000),UINT64_C(0x000000000000ffff),UINT64_C(0x00000000ffffffff)},LESS,LESS},
    {"uncached_positive_inf_zero",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"uncached_negative_inf_zero",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS},
    {"positive_negative_zero",{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000080000000),UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_positive_zero",{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL}
};
static const sample_t integer_samples[]={
    {"ip_min",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000008000),UINT64_C(0x0000000080000000)},GREATER,GREATER},
    {"ip_max",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000007fff),UINT64_C(0x000000007fffffff)},GREATER,GREATER},
    {"ip_mi",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x000000000000ffff),UINT64_C(0x00000000ffffffff)},GREATER,GREATER},
    {"ip_zp",{0x7fff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"in_min",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000008000),UINT64_C(0x0000000080000000)},LESS,LESS},
    {"in_max",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000007fff),UINT64_C(0x000000007fffffff)},LESS,LESS},
    {"in_mi",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x000000000000ffff),UINT64_C(0x00000000ffffffff)},LESS,LESS},
    {"in_zp",{0xffff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS},
    {"up_min",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000008000),UINT64_C(0x0000000080000000)},GREATER,GREATER},
    {"up_max",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000007fff),UINT64_C(0x000000007fffffff)},GREATER,GREATER},
    {"up_mi",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x000000000000ffff),UINT64_C(0x00000000ffffffff)},GREATER,GREATER},
    {"up_zp",{0x7fff,UINT64_C(0x8000000000000001),UINT64_C(0x7ff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},GREATER,GREATER},
    {"un_min",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000008000),UINT64_C(0x0000000080000000)},LESS,LESS},
    {"un_max",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000007fff),UINT64_C(0x000000007fffffff)},LESS,LESS},
    {"un_mi",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x000000000000ffff),UINT64_C(0x00000000ffffffff)},LESS,LESS},
    {"un_zp",{0x4000,UINT64_C(0x0000000000000001),UINT64_C(0xfff0000000000000),2,0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},LESS,LESS}
};
static const sample_t raw_denormals[]={
    {"positive_raw_denormal_compatibility",{0x0000,UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000000),2,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_raw_denormal_compatibility",{0x8000,UINT64_C(0x0000000000000001),UINT64_C(0x8000000000000000),2,1},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL}
};
static const sample_t source_denormals[]={
    {"positive_m32_denormal",{0x3f6a,UINT64_C(0x8000000000000001),UINT64_C(0x36a0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_m32_denormal",{0xbf6a,UINT64_C(0x8000000000000001),UINT64_C(0xb6a0000000000000),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000080000001),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"positive_m64_denormal",{0x3bcd,UINT64_C(0x8000000000000001),UINT64_C(0x0000000000000001),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000001),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL},
    {"negative_m64_denormal",{0xbbcd,UINT64_C(0x8000000000000001),UINT64_C(0x8000000000000001),0,1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1,1},{UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000001),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000)},EQUAL,EQUAL}
};
typedef struct {const char *name;uint8_t bytes[2];unsigned index,integer_flags,ordered,pops,two;int decoded;hb_ir_op_t ir;unsigned format,width;} form_t;
#define F(N,P,B,I,IF,ORD,POP,D,IR) {N #I,{P,(B)+(I)},I,IF,ORD,POP,0,HB_INS_X87_##D,HB_IR_X87_##IR,REGISTER,0}
#define EIGHT(N,P,B,IF,ORD,POP,D,IR) F(N,P,B,0,IF,ORD,POP,D,IR),F(N,P,B,1,IF,ORD,POP,D,IR),F(N,P,B,2,IF,ORD,POP,D,IR),F(N,P,B,3,IF,ORD,POP,D,IR),F(N,P,B,4,IF,ORD,POP,D,IR),F(N,P,B,5,IF,ORD,POP,D,IR),F(N,P,B,6,IF,ORD,POP,D,IR),F(N,P,B,7,IF,ORD,POP,D,IR)
static const form_t forms[]={
    EIGHT("FCOMI ST0,ST",0xdb,0xf0,1,0,0,FCOMI,FCOMI),
    EIGHT("FUCOMI ST0,ST",0xdb,0xe8,1,0,0,FUCOMI,FUCOMI),
    EIGHT("FCOMIP ST0,ST",0xdf,0xf0,1,0,1,FCOMPI,FCOMIP),
    EIGHT("FUCOMIP ST0,ST",0xdf,0xe8,1,0,1,FUCOMPI,FUCOMIP),
    EIGHT("FCOM ST",0xd8,0xd0,0,1,0,FCOM,FCOM),
    EIGHT("FCOMP ST",0xd8,0xd8,0,1,1,FCOMP,FCOMP),
    EIGHT("FUCOM ST",0xdd,0xe0,0,0,0,FUCOM,FUCOM),
    EIGHT("FUCOMP ST",0xdd,0xe8,0,0,1,FUCOMP,FUCOMP),
    {"FCOMPP",{0xde,0xd9},1,0,1,2,1,HB_INS_X87_FCOMPP,HB_IR_X87_FCOMPP,REGISTER,0},
    {"FUCOMPP",{0xda,0xe9},1,0,0,2,1,HB_INS_X87_FCOMPP,HB_IR_X87_FCOMPP,REGISTER,0},
    {"FCOM m32",{0xd8,0x11},0,0,1,0,0,HB_INS_X87_FCOM,HB_IR_X87_FCOM,REAL32,4},
    {"FCOMP m32",{0xd8,0x19},0,0,1,1,0,HB_INS_X87_FCOMP,HB_IR_X87_FCOMP,REAL32,4},
    {"FCOM m64",{0xdc,0x11},0,0,1,0,0,HB_INS_X87_FCOM,HB_IR_X87_FCOM,REAL64,8},
    {"FCOMP m64",{0xdc,0x19},0,0,1,1,0,HB_INS_X87_FCOMP,HB_IR_X87_FCOMP,REAL64,8},
    {"FICOM m16",{0xde,0x11},0,0,1,0,0,HB_INS_X87_FI,HB_IR_X87_FI,INT16,2},
    {"FICOMP m16",{0xde,0x19},0,0,1,1,0,HB_INS_X87_FI,HB_IR_X87_FI,INT16,2},
    {"FICOM m32",{0xda,0x11},0,0,1,0,0,HB_INS_X87_FI,HB_IR_X87_FI,INT32,4},
    {"FICOMP m32",{0xda,0x19},0,0,1,1,0,HB_INS_X87_FI,HB_IR_X87_FI,INT32,4}
};
#undef EIGHT
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;hb_ir_instr_t *comparison;} fixture_t;
static int memory_fault(unsigned kind){return kind==NO_READ||kind==TRUNCATED||kind==UNMAPPED;}
static void install(hb_x87_state_t *x,unsigned p,const raw_t *v)
{memcpy(&x->st[p],&v->preview,8);put64(x->st_ext[p],v->sig);put16(x->st_ext[p]+8,v->se);if(v->valid)x->st_ext_valid|=(uint8_t)(1u<<p);else x->st_ext_valid&=(uint8_t)~(1u<<p);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*p)))|(v->tag<<(2*p)));}
static void seed(fixture_t *f,const sample_t *s,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned empty,unsigned kind,uint64_t address)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));memset(&c->x87_64,0x56,sizeof(c->x87_64));
    hb_x87_state_t *x=hb_context_x87(c);memset(x,0,sizeof(*x));x->top=top;x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x0024|((cc&1)<<8)|((cc&2)<<8)|((cc&4)<<8)|((cc&8)<<11));
    if(top&1)x->status_word|=0x0040;x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p){raw_t v={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)p*UINT64_C(0x0800000000000000),UINT64_C(0x4020000000000000)+(uint64_t)p*UINT64_C(0x0001000000000000),0,1};install(x,p,&v);}
    unsigned other=(top+f->form->index)&7;install(x,other,&s->b);install(x,top,&s->a);
    unsigned neighbor=(top+6)&7;if(neighbor!=top&&neighbor!=other)x->tag_word|=(uint16_t)(3u<<(2*neighbor));
    if(empty){unsigned p=empty==1?top:other;x->tag_word|=(uint16_t)(3u<<(2*p));x->control_word&=(uint16_t)~1u;}
    if(kind==PENDING){x->control_word&=(uint16_t)~1u;x->status_word|=0x8081u;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=(cc&1)!=0,.pf=(cc&2)!=0,.af=true,.zf=(cc&4)!=0,.sf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    if(f->form->width){if(c->arch==HB_ARCH_X86)c->regs.x86.ecx=(uint32_t)address;else c->regs.x64.rcx=address;}
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void check_state(fixture_t *f,const hb_context_t *before,unsigned relation,unsigned kind)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    if(kind==EMPTY)e->status_word=(uint16_t)((e->status_word|0x80c1u)&~0x0200u);
    else if(!memory_fault(kind)){
        if(f->form->integer_flags){
            e->status_word&=(uint16_t)~0x0200u;
            expected.flags=(hb_flags_t){.cf=relation==LESS,.zf=relation==EQUAL};
        }else{
            e->status_word=(uint16_t)((e->status_word&~0x4500u)|(relation==LESS?0x0100u:relation==EQUAL?0x4000u:0));
            if(f->form->ordered)e->status_word&=(uint16_t)~0x0200u;
        }
        for(unsigned n=0;n<f->form->pops;++n){e->tag_word|=(uint16_t)(3u<<(2*e->top));e->top=(e->top+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));}
    }
    check_kind(x->status_word==e->status_word,"x87 relation/C1, TOP and sticky status",X87_STATUS);
    check_kind(!memcmp(&f->ctx->flags,&expected.flags,sizeof(expected.flags))&&!memcmp(&f->ctx->lazy_flags,&expected.lazy_flags,sizeof(expected.lazy_flags)),"canonical integer flags and lazy state",INTEGER_FLAGS);
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"physical raw/cache/preview, tags, control and optional pop");
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and nonarithmetic flag-image state preserved");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr,"MXCSR preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned host,unsigned kind,unsigned side)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint64_t address=DATA+64,window=DATA+48;uint8_t expected_mem[32],source[8];unsigned n=f->form->width,offset=16;
    snprintf(phase,sizeof(phase),"%s %s %s %s TOP=%u cc=%u PC=%u RC=%u host=%u kind=%u side=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,s->name,top,cc,pc,rc,host,kind,side);
    if(f->form->width){
        memset(expected_mem,0xa5,sizeof(expected_mem));put64(source,s->memory[f->form->format-1]);
        if(kind==EDGE||kind==TRUNCATED){window=DATA+PAGE_BYTES-32;offset=32-f->form->width+(kind==TRUNCATED);address=window+offset;if(kind==TRUNCATED)--n;}
        else if(kind==UNMAPPED){window=DATA+PAGE_BYTES-32;address=DATA+PAGE_BYTES+64;n=0;}
        else if(kind==NO_READ){window=DENIED+48;address=DENIED+64;}
        if(n)memcpy(expected_mem+offset,source,n);
        if(!check_kind(hb_memory_protect(f->ctx->memory,DENIED,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f->ctx->memory,window,expected_mem,sizeof(expected_mem))==HB_OK,"seed source bytes and guards",MEMORY))return;
        if(kind==NO_READ&&!check_kind(hb_memory_protect(f->ctx->memory,DENIED,PAGE_BYTES,HB_PERM_WRITE)==HB_OK,"deny source read",MEMORY))return;
    }
    seed(f,s,top,cc,pc,rc,kind==EMPTY?side:0,kind,address);hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;
    if(kind==EMPTY)++empty_cases;else if(kind==PENDING)++pending_cases;else if(kind==RAW_DENORMAL)++raw_denormal_cases;else if(kind==SOURCE_DENORMAL)++source_denormal_cases;else if(kind!=MAIN)++span_cases;else if(f->form->width)++memory_main;else ++register_main;
    if(f->form->integer_flags)++integer_cases;else ++ordinary_cases;
    check_kind(actual_rc==modes[host]&&actual_flags==wanted,"host RC/status preserved",HOST);
    hb_result_t error=kind==EMPTY?HB_ERR_EXEC_FAULT:memory_fault(kind)?HB_ERR_MEMORY_FAULT:HB_OK;
    if(error!=HB_OK)check_kind((result==HB_OK||result==error)&&out.result==error&&out.faulted&&!out.timed_out,"expected early empty/memory error",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"actual comparison completes",EXECUTION);
    unsigned relation=kind==PENDING?s->preview_relation:s->relation;
    check_state(f,&before,(f->form->width||f->form->index)?relation:EQUAL,kind);
    if(f->form->width){uint8_t actual[32];check_kind(hb_memory_protect(f->ctx->memory,DENIED,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_read(f->ctx->memory,window,actual,sizeof(actual))==HB_OK&&!memcmp(actual,expected_mem,sizeof(actual)),"source/guards unchanged and permissions restored",MEMORY);}
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void check_ir(fixture_t *f)
{
    unsigned count=0;if(!check_kind(f->func->cfg!=NULL,"IR container present",DECODE))return;
    for(size_t b=0;b<f->func->cfg->block_count;++b){hb_ir_block_t *block=f->func->cfg->blocks[b];
        for(size_t i=0;i<block->instr_count;++i){hb_ir_instr_t *ir=&block->instrs[i];if(ir->op!=f->form->ir)continue;++count;
            if(f->form->width){
                hb_size_t width=f->form->width==2?HB_SIZE_16:f->form->width==4?HB_SIZE_32:HB_SIZE_64;
                check_kind(ir->guest_addr==CODE&&ir->src1.type==HB_OP_MEM&&ir->src1.size==width&&ir->dst.type==HB_OP_NONE,"memory IR width and implicit destination",DECODE);
                if(f->form->format>=INT16)check_kind(ir->src2.type==HB_OP_IMM&&ir->src2.imm==(int64_t)(2+f->form->pops),"integer memory suboperation",DECODE);
            }else check_kind(ir->guest_addr==CODE&&ir->src1.type==HB_OP_IMM&&ir->src1.imm==(int64_t)f->form->index&&ir->dst.type==HB_OP_NONE,"register IR source/index and implicit destination",DECODE);
            f->comparison=ir;
            if(f->form->two)check_kind(ir->src2.type==HB_OP_IMM&&ir->src2.imm==(int64_t)f->form->ordered,"fresh two-pop family marker",DECODE);
        }
    }
    check_kind(count==1,"exactly one expected comparison IR",DECODE);
}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable comparison context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.ctx->memory,DENIED,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,form->bytes,2)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned code/data"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->bytes,2,CODE,&d):hb_decode_x64(form->bytes,2,CODE,&d);
    if(!check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==form->decoded,"decode actual comparison opcode",DECODE))goto done;
    if(form->width){
        check_kind(d.op1.present&&d.op1.is_mem&&d.op1.size==form->width,"decoded exact memory width",DECODE);
        if(form->format>=INT16)check_kind(d.op2.present&&d.op2.is_imm&&d.op2.imm==(int64_t)(2+form->pops),"decoded integer suboperation",DECODE);
    }else check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decoded logical comparison operand",DECODE);
    if(form->two)check_kind(d.op2.present&&d.op2.is_imm&&d.op2.imm==(int64_t)form->ordered,"decoded two-pop family marker",DECODE);
    f.decoder=hb_decoder_create(arch,form->bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift comparison",EXECUTION))goto done;
    check_ir(&f);
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3},small_cc[]={0,2,13,15},spans[]={EDGE,NO_READ,TRUNCATED,UNMAPPED};
    unsigned profile=(arch==HB_ARCH_X64?2u:0u)+(backend==HB_BACKEND_JIT?1u:0u);
    if(!form->width){
        for(unsigned si=0;si<24;++si)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)run_case(&f,&register_samples[si],t?7:0,cc,pcs[(t+profile)%3],cc>>2,cc&3,MAIN,0);
        if(f.jit)check_kind(native_present(&f),"main register native entry; helper lowering allowed",EXECUTION);
        if(form->index==3||form->index==7||form->two){
            for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned ci=0;ci<4;++ci)for(unsigned host=0;host<4;++host){
                run_case(&f,&register_samples[si],t?7:0,small_cc[ci],3,3-host,host,PENDING,0);
                run_case(&f,&register_samples[0],t?7:0,small_cc[ci],3,3-host,host,EMPTY,si+1);
                run_case(&f,&raw_denormals[si],t?7:0,small_cc[ci],3,3-host,host,RAW_DENORMAL,0);
            }
        }
    }else{
        const sample_t *table=form->format<=REAL64?real_samples:integer_samples;
        for(unsigned si=0;si<16;++si)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)run_case(&f,&table[si],t?7:0,cc,pcs[(t+profile)%3],cc>>2,cc&3,MAIN,0);
        if(f.jit)check_kind(native_present(&f),"main memory native entry; helper lowering allowed",EXECUTION);
        for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned ci=0;ci<4;++ci)for(unsigned host=0;host<4;++host){
            run_case(&f,&table[si],t?7:0,small_cc[ci],3,3-host,host,PENDING,0);
            run_case(&f,&table[si],t?7:0,small_cc[ci],3,3-host,host,EMPTY,1);
        }
        for(unsigned k=0;k<4;++k)for(unsigned origin=0;origin<2;++origin)for(unsigned t=0;t<2;++t)for(unsigned host=0;host<4;++host){
            unsigned si=origin?(form->format<=REAL64?12u:8u):0u;
            run_case(&f,&table[si],t?7:0,15,3,3-host,host,spans[k],0);
        }
        if(form->format<=REAL64)for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)
            run_case(&f,&source_denormals[2*(form->format-REAL32)+si],t?7:0,cc,3,cc>>2,cc&3,SOURCE_DENORMAL,0);
    }
    uint8_t actual[2];check(hb_memory_read(f.ctx->memory,CODE,actual,2)==HB_OK&&!memcmp(actual,form->bytes,2),"code unchanged");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select private helper policy"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective gate"))goto done;}
    if(!check(fegetenv(&original)==0,"save caller fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host traps"))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned i=0;i<sizeof(forms)/sizeof(forms[0]);++i)run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
    check(executions==240128u&&register_main==202752u&&memory_main==16384u&&pending_cases==6656u&&empty_cases==6656u&&raw_denormal_cases==4608u&&source_denormal_cases==1024u&&span_cases==2048u&&integer_cases==104448u&&ordinary_cases==135680u,"planned actual call counts");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_infinity_compare_test: %u executions (%u register main, %u memory main, %u pending compatibility, %u IM0 empty, %u raw-denormal compatibility, %u source-denormal compatibility, %u memory spans; %u integer-flag executions, %u ordinary executions), %u checks, %u failures\n",executions,register_main,memory_main,pending_cases,empty_cases,raw_denormal_cases,source_denormal_cases,span_cases,integer_cases,ordinary_cases,checks,failures);
    printf("failure categories: x87_status=%u integer_flags=%u state=%u execution=%u host=%u decode=%u memory=%u\n",category_failures[X87_STATUS],category_failures[INTEGER_FLAGS],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE],category_failures[MEMORY]);return failures?1:0;
}
