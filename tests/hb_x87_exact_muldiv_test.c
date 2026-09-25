/* M46 preparation: exact canonical normal/zero DE FMULP/FDIVP/FDIVRP.
 * Inputs are a=old ST0 and b=old STi; results are a*b, b/a and a/b.
 * Literal raw80/nearest-preview answers use independent integer/rational math.
 * M50 admits PM1 inexact controls and PC64 precision MUL aliases; their new
 * guest-RC answers supersede old fallback literals. FDIVRP zero aliases are not executed (0/0);
 * their unused self field is a zero placeholder with self_exact=0.
 * Compatibility cases retain legacy behavior, not architectural exception parity.
 * C0/C2/C3, inherited FIP and popped payload/cache are excluded. No component
 * calls, memory arithmetic, non-pop admission or host exception allowance. */
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
enum { MUL, DIV, REVERSE_DIV };
enum { NORMAL, PENDING, RESERVED, INEXACT, EMPTY_ST0, EMPTY_STI };
enum { COMMON, CROSS, PRECISION, PRECISION_ALIAS, ZERO, UNCACHED,
       PENDING_GROUP, RESERVED_GROUP, INEXACT_GROUP, EMPTY_GROUP, GROUPS };
enum { RAW, STATE, EXECUTION, HOST, CATEGORIES };
static const uint64_t CODE=UINT64_C(0x6300000);
static unsigned checks,failures,executions,exact_cases,legacy_cases,empty_cases;
static unsigned category_failures[CATEGORIES],group_cases[GROUPS];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag;} raw_t;
typedef struct {const char *name;raw_t st0,sti,result,self;unsigned self_exact;} sample_t;
#define R(se,sig,preview,tag) {UINT16_C(se),UINT64_C(sig),UINT64_C(preview),tag}
static const sample_t common[3][8]={
    {
        {"common_0_0",R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_0_1",R(0xbfff,0x8000000000000000,0xbff0000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_1_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3ffe,0xc000000000000000,0x3fe8000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),1},
        {"common_1_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x3ffe,0xc000000000000000,0x3fe8000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),1},
        {"common_2_0",R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x495f,0x8000000000000000,0x7ff0000000000000,0),R(0x495f,0x8000000000000000,0x7ff0000000000000,0),1},
        {"common_2_1",R(0xc4af,0x8000000000000000,0xfff0000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0xc95f,0x8000000000000000,0xfff0000000000000,0),R(0x495f,0x8000000000000000,0x7ff0000000000000,0),1},
        {"common_3_0",R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x369f,0x8000000000000000,0x0000000000000000,0),R(0x369f,0x8000000000000000,0x0000000000000000,0),1},
        {"common_3_1",R(0xbb4f,0x8000000000000000,0x8000000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0xb69f,0x8000000000000000,0x8000000000000000,0),R(0x369f,0x8000000000000000,0x0000000000000000,0),1}
    },
    {
        {"common_0_0",R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_0_1",R(0xbfff,0x8000000000000000,0xbff0000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_1_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_1_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_2_0",R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x369f,0x8000000000000000,0x0000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_2_1",R(0xc4af,0x8000000000000000,0xfff0000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0xb69f,0x8000000000000000,0x8000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_3_0",R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x495f,0x8000000000000000,0x7ff0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_3_1",R(0xbb4f,0x8000000000000000,0x8000000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0xc95f,0x8000000000000000,0xfff0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    },
    {
        {"common_0_0",R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3ffe,0x8000000000000000,0x3fe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_0_1",R(0xbfff,0x8000000000000000,0xbff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0xbffe,0x8000000000000000,0xbfe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_1_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),R(0x3ffe,0x8000000000000000,0x3fe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_1_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),R(0xbffe,0x8000000000000000,0xbfe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_2_0",R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x495f,0x8000000000000000,0x7ff0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_2_1",R(0xc4af,0x8000000000000000,0xfff0000000000000,0),R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0xc95f,0x8000000000000000,0xfff0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_3_0",R(0x3b4f,0x8000000000000000,0x0000000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0x369f,0x8000000000000000,0x0000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"common_3_1",R(0xbb4f,0x8000000000000000,0x8000000000000000,0),R(0x44af,0x8000000000000000,0x7ff0000000000000,0),R(0xb69f,0x8000000000000000,0x8000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    }
};
static const sample_t precision[3][4]={
    {
        {"precision_0_0",R(0x3fff,0x8000000000000001,0x3ff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4000,0x8000000000000001,0x4000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),0},
        {"precision_0_1",R(0xbfff,0x8000000000000001,0xbff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0xc000,0x8000000000000001,0xc000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),0},
        {"precision_1_0",R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x4069,0x8000000000000000,0x4690000000000000,0),0},
        {"precision_1_1",R(0xc034,0x8000000000000400,0xc340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0xc034,0x8000000000000400,0xc340000000000000,0),R(0x4069,0x8000000000000000,0x4690000000000000,0),0}
    },
    {
        {"precision_0_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3fff,0x8000000000000001,0x3ff0000000000000,0),R(0x3ffe,0x8000000000000001,0x3fe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_0_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x3fff,0x8000000000000001,0x3ff0000000000000,0),R(0xbffe,0x8000000000000001,0xbfe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_1_0",R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_1_1",R(0xbfff,0x8000000000000000,0xbff0000000000000,0),R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0xc034,0x8000000000000400,0xc340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    },
    {
        {"precision_0_0",R(0x3fff,0x8000000000000001,0x3ff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3ffe,0x8000000000000001,0x3fe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_0_1",R(0xbfff,0x8000000000000001,0xbff0000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0xbffe,0x8000000000000001,0xbfe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_1_0",R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x4034,0x8000000000000400,0x4340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"precision_1_1",R(0xc034,0x8000000000000400,0xc340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0xc034,0x8000000000000400,0xc340000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    }
};
static const sample_t zeros[3][4]={
    {
        {"zero_0_0",R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),1},
        {"zero_0_1",R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),1},
        {"zero_1_0",R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),1},
        {"zero_1_1",R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),1}
    },
    {
        {"zero_0_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"zero_0_1",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"zero_1_0",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"zero_1_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    },
    {
        {"zero_0_0",R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),0},
        {"zero_0_1",R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),0},
        {"zero_1_0",R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),0},
        {"zero_1_1",R(0x8000,0x0000000000000000,0x8000000000000000,1),R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x0000,0x0000000000000000,0x0000000000000000,1),R(0x0000,0x0000000000000000,0x0000000000000000,1),0}
    }
};
static const sample_t uncached[3][2]={
    {
        {"uncached_0",R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0x4000,0x9000000000000000,0x4002000000000000,0),1},
        {"uncached_1",R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0xc000,0xc000000000000000,0xc008000000000000,0),R(0x4000,0x9000000000000000,0x4002000000000000,0),1}
    },
    {
        {"uncached_0",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"uncached_1",R(0xc000,0x8000000000000000,0xc000000000000000,0),R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    },
    {
        {"uncached_0",R(0x4000,0xc000000000000000,0x4008000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3fff,0xc000000000000000,0x3ff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"uncached_1",R(0xc000,0xc000000000000000,0xc008000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0xbfff,0xc000000000000000,0xbff8000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    }
};
static const sample_t inexact[3][2]={
    {
        {"inexact_0",R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000010000008000,0x3ff0000020000010,0),0},
        {"inexact_1",R(0xbfff,0x8000008000000000,0xbff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0xbfff,0x8000008000000000,0xbff0000010000000,0),R(0x3fff,0x8000010000008000,0x3ff0000020000010,0),0}
    },
    {
        {"inexact_0",R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"inexact_1",R(0xbfff,0x8000000000000000,0xbff0000000000000,0),R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0xbfff,0x8000008000000000,0xbff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    },
    {
        {"inexact_0",R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0x3fff,0x8000008000000000,0x3ff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
        {"inexact_1",R(0xbfff,0x8000008000000000,0xbff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),R(0xbfff,0x8000008000000000,0xbff0000010000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
    }
};
static const sample_t compatibility[3]={
    {"compatibility",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),R(0x4002,0x8000000000000000,0x4020000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),1},
    {"compatibility",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1},
    {"compatibility",R(0x4000,0x8000000000000000,0x4000000000000000,0),R(0x4001,0x8000000000000000,0x4010000000000000,0),R(0x3ffe,0x8000000000000000,0x3fe0000000000000,0),R(0x3fff,0x8000000000000000,0x3ff0000000000000,0),1}
};
#undef R
typedef struct {const char *name;uint8_t bytes[2];unsigned operation,index;} form_t;
#define F(n,op,byte,i) {n " ST" #i,{0xde,byte+i},op,i}
#define EIGHT(n,op,byte) F(n,op,byte,0),F(n,op,byte,1),F(n,op,byte,2),F(n,op,byte,3),F(n,op,byte,4),F(n,op,byte,5),F(n,op,byte,6),F(n,op,byte,7)
static const form_t forms[]={EIGHT("FMULP",MUL,0xc8),EIGHT("FDIVP",DIV,0xf8),EIGHT("FDIVRP",REVERSE_DIV,0xf0)};
#undef EIGHT
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static void install(hb_x87_state_t *x,unsigned phys,const raw_t *r,int invalidate)
{
    memcpy(&x->st[phys],&r->preview,8);put64(x->st_ext[phys],r->sig);put16(x->st_ext[phys]+8,r->se);
    x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|(r->tag<<(2*phys)));
    if(invalidate){
        /* Inactive raw poison resembles a special/noncanonical value. */
        put64(x->st_ext[phys],UINT64_C(0x5a5a000000000001)+(uint64_t)phys);
        put16(x->st_ext[phys]+8,(uint16_t)(0x7fff|(phys&1u)<<15));
        x->st_ext_valid&=(uint8_t)~(1u<<phys);
    }else x->st_ext_valid|=(uint8_t)(1u<<phys);
}
typedef struct {int rc,flags;uint64_t fpcr,fpsr;} host_t;
static host_t host_state(void)
{
    host_t h={.rc=fegetround(),.flags=fetestexcept(FE_ALL_EXCEPT),.fpcr=0,.fpsr=0};
#if defined(__aarch64__)
    __asm__ volatile("mrs %0, fpcr":"=r"(h.fpcr));
    __asm__ volatile("mrs %0, fpsr":"=r"(h.fpsr));
#endif
    return h;
}
static void seed(fixture_t *f,const sample_t *s,unsigned top,unsigned pc,unsigned rc,unsigned invalid,unsigned control)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else{c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x4704|((top&1)?0x20:0)|((top&2)?0x40:0));x->last_x87_ip=0x12345678;
    for(unsigned i=0;i<8;++i){raw_t n={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000),0};install(x,(top+i)&7,&n,0);}
    x->tag_word|=(uint16_t)(3u<<(2*((top+6)&7)));
    unsigned dst=(top+f->form->index)&7;
    /* Logical STi first, ST0 last: an alias has ST0's final validity. */
    install(x,dst,&s->sti,(invalid&2u)!=0);install(x,top,&s->st0,(invalid&1u)!=0);
    if(control==EMPTY_ST0||control==EMPTY_STI){unsigned p=control==EMPTY_ST0?top:dst;x->tag_word|=(uint16_t)(3u<<(2*p));x->control_word&=(uint16_t)~1u;}
    if(control==PENDING){x->control_word&=(uint16_t)~1u;x->status_word|=0x8081u;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
/* M50: the historical legacy/exact counters retain their input-group meaning.
 * The explicitly selected old precision rows now require guest-PC/RC raw results,
 * sticky PE and C1 from discarded-bit magnitude increment. All loops/check counts
 * and unrelated-state, host-state and fault assertions remain unchanged.
 * These literals were derived with integer/Fraction arithmetic, without the bridge.
 */
typedef struct {raw_t raw;unsigned status_bits;} precision_answer_t;
static const precision_answer_t masked_inexact[3][2][4]={
    {
    {{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000010000000000),UINT64_C(0x3ff0000020000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000010000000000),UINT64_C(0xbff0000020000000),0},0x0220u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u}}
},
    {
    {{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000010000000000),UINT64_C(0x3ff0000020000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000010000000000),UINT64_C(0xbff0000020000000),0},0x0220u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u}}
},
    {
    {{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000010000000000),UINT64_C(0x3ff0000020000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000010000000000),UINT64_C(0xbff0000020000000),0},0x0220u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0020u}}
}
};
static const precision_answer_t masked_alias[4][4]={
    {{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000003),UINT64_C(0x3ff0000000000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000003),UINT64_C(0x3ff0000000000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u},{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u},{{0x4069,UINT64_C(0x8000000000000801),UINT64_C(0x4690000000000001),0},0x0220u},{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u}},
    {{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u},{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u},{{0x4069,UINT64_C(0x8000000000000801),UINT64_C(0x4690000000000001),0},0x0220u},{{0x4069,UINT64_C(0x8000000000000800),UINT64_C(0x4690000000000001),0},0x0020u}}
};
static void check_state(fixture_t *f,const hb_context_t *before,const raw_t *expected_answer,int exact,int empty,unsigned precision_status)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    unsigned source=e->top,dst=(source+f->form->index)&7;
    if(empty)e->status_word=(uint16_t)((e->status_word|0x80c1u)&~0x200u);
    else{
        if(dst!=source){
            raw_t r=*expected_answer;
            if(exact||precision_status){install(e,dst,&r,0);check_kind((x->st_ext_valid&(1u<<dst))&&!memcmp(x->st_ext[dst],e->st_ext[dst],10),"exact surviving destination ten-byte raw result/cache",RAW);}
            else{
                memcpy(&e->st[dst],&r.preview,8);e->st_ext_valid&=(uint8_t)~(1u<<dst);e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*dst)))|(r.tag<<(2*dst)));
                check_kind(!(x->st_ext_valid&(1u<<dst)),"declined case retains legacy invalid-cache representation",RAW);
            }
            check_kind(!memcmp(&x->st[dst],&e->st[dst],8),"surviving destination preview",RAW);
            check_kind(((x->tag_word>>(2*dst))&3u)==((e->tag_word>>(2*dst))&3u),"surviving destination classification",RAW);
        }
        e->tag_word|=(uint16_t)(3u<<(2*source));e->top=(source+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));
        if(exact||precision_status)e->status_word=(uint16_t)((e->status_word&~0x200u)|precision_status);
        /* No surviving numerical value exists in the popped physical source. */
        memcpy(&e->st[source],&x->st[source],8);memcpy(e->st_ext[source],x->st_ext[source],10);e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<source))|(x->st_ext_valid&(1u<<source)));
    }
    e->status_word=(uint16_t)((e->status_word&~0x4500u)|(x->status_word&0x4500u));e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"status, exact C1, pre-pop destination, TOP and all other physical x87 state");
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and register state preserved");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr&&!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR/integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned top,unsigned pc,unsigned rc,unsigned host,unsigned invalid,unsigned control,unsigned group)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    int empty=control==EMPTY_ST0||control==EMPTY_STI;
    int exact=control==NORMAL&&(f->form->index!=0||s->self_exact);
    const raw_t *expected=f->form->index==0?&s->self:&s->result;
    unsigned precision_status=0,operation=f->form->operation;const precision_answer_t *pe=NULL;
    if(control==INEXACT)pe=&masked_inexact[operation][s-inexact[operation]][rc];
    else if(control==NORMAL&&operation==MUL&&f->form->index==0&&!s->self_exact)
        pe=&masked_alias[s-precision[MUL]][rc];
    if(pe){expected=&pe->raw;precision_status=pe->status_bits;}
    snprintf(phase,sizeof(phase),"%s %s %s %s TOP=%u PC=%u RC=%u host=%u invalid=%u control=%u group=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,s->name,top,pc,rc,host,invalid,control,group);
    seed(f,s,top,pc,rc,invalid,control);hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    host_t wanted=host_state();hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    host_t actual=host_state();
    ++executions;++group_cases[group];if(empty)++empty_cases;else if(exact)++exact_cases;else ++legacy_cases;
    check_kind(actual.rc==modes[host]&&actual.rc==wanted.rc&&actual.flags==wanted.flags&&actual.fpcr==wanted.fpcr&&actual.fpsr==wanted.fpsr,"host RC/status and ARM64 FPCR/FPSR preserved",HOST);
    if(empty)check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"IM0 empty compatibility fault without store/pop",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"DE instruction completes",EXECUTION);
    check_state(f,&before,expected,exact,empty,precision_status);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};uint8_t code_page[PAGE_BYTES],actual_page[PAGE_BYTES];memset(code_page,0xa5,sizeof(code_page));memcpy(code_page,form->bytes,2);
    f.form=form;f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable DE context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,code_page,sizeof(code_page))==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned guarded code"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->bytes,2,CODE,&d):hb_decode_x64(form->bytes,2,CODE,&d);
    int opcode=form->operation==MUL?HB_INS_X87_FMULP:form->operation==DIV?HB_INS_X87_FDIVP:HB_INS_X87_FDIVRP;
    check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==opcode,"decode actual DE pop arithmetic",EXECUTION);
    check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decoded logical ST destination",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift DE arithmetic",EXECUTION))goto done;
    unsigned count=0;hb_ir_op_t expected_ir=form->operation==MUL?HB_IR_X87_FMULP:form->operation==DIV?HB_IR_X87_FDIVP:HB_IR_X87_FDIVRP;
    for(size_t b=0;b<f.func->cfg->block_count;++b){hb_ir_block_t *block=f.func->cfg->blocks[b];for(size_t i=0;i<block->instr_count;++i){hb_ir_instr_t *ir=&block->instrs[i];if(ir->op!=expected_ir)continue;++count;check_kind(ir->guest_addr==CODE&&ir->src1.type==HB_OP_IMM&&ir->src1.imm==(int64_t)form->index,"IR operation address and logical destination",EXECUTION);}}
    check_kind(count==1,"exactly one intended arithmetic IR instruction",EXECUTION);
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};unsigned op=form->operation;
    for(unsigned si=0;si<8;++si)for(unsigned top=0;top<8;++top)for(unsigned pi=0;pi<3;++pi)for(unsigned rc=0;rc<4;++rc)
        run_case(&f,&common[op][si],top,pcs[pi],rc,rc,0,NORMAL,COMMON);
    if(form->index==0||form->index==3)for(unsigned si=0;si<8;++si)for(unsigned t=0;t<2;++t)for(unsigned pi=0;pi<3;++pi)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)
        run_case(&f,&common[op][si],t?7:0,pcs[pi],rc,host,0,NORMAL,CROSS);
    for(unsigned si=0;si<4;++si)for(unsigned top=0;top<8;++top)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)
        run_case(&f,&precision[op][si],top,3,rc,host,0,NORMAL,form->index==0?PRECISION_ALIAS:PRECISION);
    /* Exclude FDIVRP's zero/zero alias cases explicitly. */
    if(!(op==REVERSE_DIV&&form->index==0))for(unsigned si=0;si<4;++si)for(unsigned top=0;top<8;++top)for(unsigned pi=0;pi<3;++pi)for(unsigned rc=0;rc<4;++rc)
        run_case(&f,&zeros[op][si],top,pcs[pi],rc,rc,0,NORMAL,ZERO);
    if(form->index==0||form->index==3||form->index==7)for(unsigned si=0;si<2;++si)for(unsigned invalid=1;invalid<=3;++invalid)for(unsigned t=0;t<2;++t)for(unsigned pi=0;pi<3;++pi)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)
        run_case(&f,&uncached[op][si],t?7:0,pcs[pi],rc,host,invalid,NORMAL,UNCACHED);
    if(f.jit)check_kind(native_present(&f),"main guest runtime has a compiled entry before compatibility/error controls; helper lowering allowed",EXECUTION);
    for(unsigned t=0;t<2;++t)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host){
        run_case(&f,&compatibility[op],t?7:0,3,rc,host,0,PENDING,PENDING_GROUP);
        run_case(&f,&compatibility[op],t?7:0,1,rc,host,0,RESERVED,RESERVED_GROUP);
    }
    if(form->index==3||form->index==7)for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)
        run_case(&f,&inexact[op][si],t?7:0,0,rc,host,0,INEXACT,INEXACT_GROUP);
    for(unsigned side=0;side<2;++side)for(unsigned t=0;t<2;++t)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)
        run_case(&f,&compatibility[op],t?7:0,3,rc,host,0,side?EMPTY_STI:EMPTY_ST0,EMPTY_GROUP);
    check(hb_memory_read(f.ctx->memory,CODE,actual_page,sizeof(actual_page))==HB_OK&&!memcmp(actual_page,code_page,sizeof(code_page)),"entire owned code page and guards unchanged");
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
    check(executions==211200u&&exact_cases==195328u&&legacy_cases==9728u&&empty_cases==6144u,"planned exact/legacy/error actual call counts");
    static const unsigned planned[GROUPS]={73728,18432,43008,6144,35328,20736,3072,3072,1536,6144};
    for(unsigned i=0;i<GROUPS;++i)check(group_cases[i]==planned[i],"planned partition count");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_exact_muldiv_test: %u executions (%u exact, %u legacy completions, %u IM0 empty), %u checks, %u failures\n",executions,exact_cases,legacy_cases,empty_cases,checks,failures);
    printf("partitions: common=%u cross=%u precision=%u precision_alias=%u zero=%u uncached=%u pending=%u reserved=%u inexact=%u empty=%u\n",group_cases[COMMON],group_cases[CROSS],group_cases[PRECISION],group_cases[PRECISION_ALIAS],group_cases[ZERO],group_cases[UNCACHED],group_cases[PENDING_GROUP],group_cases[RESERVED_GROUP],group_cases[INEXACT_GROUP],group_cases[EMPTY_GROUP]);
    printf("failure categories: raw=%u state=%u execution=%u host=%u\n",category_failures[RAW],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}

