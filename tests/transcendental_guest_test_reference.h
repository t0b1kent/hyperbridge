#ifndef HB_TRANSCENDENTAL_GUEST_TEST_REFERENCE_H
#define HB_TRANSCENDENTAL_GUEST_TEST_REFERENCE_H
/* Test-only transport/commit reference. Admission belongs to the reviewed
 * static row inventory, never to a copy of the production predicate here.
 * Component arithmetic is not an independent mathematical oracle. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "hb_x87.h"
#if __has_include("../src/hb_x87_transcendental.h")
#include "../src/hb_x87_transcendental.h"
#else
#include "../component/hb_x87_transcendental.h"
#endif

typedef struct {
    hb_x87_transcendental_result_t numerical;
    hb_result_t expected_return;
} gt_reference;

static inline uint64_t gt_read64(const uint8_t *p)
{
    uint64_t n=0;for(unsigned i=0;i<8;++i)n|=(uint64_t)p[i]<<(8*i);return n;
}
static inline uint16_t gt_read16(const uint8_t *p)
{return (uint16_t)((unsigned)p[0]|((unsigned)p[1]<<8));}
static inline void gt_raw(uint8_t out[10],uint16_t se,uint64_t sig)
{
    for(unsigned i=0;i<8;++i)out[i]=(uint8_t)(sig>>(8*i));
    out[8]=(uint8_t)se;out[9]=(uint8_t)(se>>8);
}
static inline void gt_widen_binary64(uint8_t out[10],uint64_t bits)
{
    unsigned sign=(unsigned)(bits>>63),exp=(unsigned)((bits>>52)&0x7ffu);
    uint64_t frac=bits&UINT64_C(0x000fffffffffffff),sig=0;unsigned e=0;
    if(exp==0x7ffu){e=0x7fffu;sig=UINT64_C(0x8000000000000000)|(frac<<11);}
    else if(exp){e=exp+15360u;sig=UINT64_C(0x8000000000000000)|(frac<<11);}
    else if(frac){unsigned highest=0;for(uint64_t n=frac;n>>=1;)++highest;
        e=15309u+highest;sig=frac<<(63u-highest);}
    gt_raw(out,(uint16_t)((sign<<15)|e),sig);
}
static inline void gt_authoritative(const hb_x87_state_t *x,unsigned relative,uint8_t out[10])
{
    unsigned slot=(x->top+relative)&7u;
    if(x->st_ext_valid&(1u<<slot))memcpy(out,x->st_ext[slot],10);
    else{uint64_t bits;memcpy(&bits,&x->st[slot],8);gt_widen_binary64(out,bits);}
}
static inline uint64_t gt_nearest_shift(uint64_t n,unsigned shift)
{
    if(!shift)return n;
    if(shift>64u)return 0;
    if(shift==64u)return n>UINT64_C(0x8000000000000000);
    uint64_t q=n>>shift,r=n&((UINT64_C(1)<<shift)-1),half=UINT64_C(1)<<(shift-1);
    return q+(r>half||(r==half&&(q&1u)));
}
static inline uint64_t gt_preview(const uint8_t raw[10])
{
    uint64_t n=gt_read64(raw),sign=(uint64_t)(gt_read16(raw+8)&0x8000u)<<48;
    unsigned e=gt_read16(raw+8)&0x7fffu;
    if(!e)return sign; /* Every ext80 subnormal is too small for binary64. */
    if(e==0x7fffu&&n==UINT64_C(0x8000000000000000))return sign|UINT64_C(0x7ff0000000000000);
    if(e==0x7fffu||!(n&UINT64_C(0x8000000000000000)))
        return sign|UINT64_C(0x7ff8000000000000)|((n>>11)&UINT64_C(0x000fffffffffffff));
    int power=(int)e-16383;
    if(power>1023)return sign|UINT64_C(0x7ff0000000000000);
    if(power< -1022)return sign|gt_nearest_shift(n,(unsigned)(-1011-power));
    uint64_t rounded=gt_nearest_shift(n,11);
    if(rounded==(UINT64_C(1)<<53)){rounded>>=1;++power;}
    if(power>1023)return sign|UINT64_C(0x7ff0000000000000);
    return sign|((uint64_t)(power+1023)<<52)|(rounded&UINT64_C(0x000fffffffffffff));
}
static inline unsigned gt_raw_tag(const uint8_t raw[10])
{
    unsigned exp=gt_read16(raw+8)&0x7fffu;uint64_t sig=gt_read64(raw);
    if(!exp&&!sig)return 1;
    return exp&&exp!=0x7fffu&&(sig&UINT64_C(0x8000000000000000))?0:2;
}
static inline void gt_tag(hb_x87_state_t *x,unsigned physical,unsigned tag)
{x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*physical)))|(tag<<(2*physical)));}
static inline void gt_top(hb_x87_state_t *x,unsigned top)
{x->top=(uint8_t)top;x->status_word=(uint16_t)((x->status_word&~0x3800u)|(top<<11));}
static inline void gt_store(hb_x87_state_t *x,unsigned physical,const uint8_t raw[10])
{
    uint64_t bits=gt_preview(raw);memcpy(&x->st[physical],&bits,8);
    memcpy(x->st_ext[physical],raw,10);x->st_ext_valid|=(uint8_t)(1u<<physical);
    gt_tag(x,physical,gt_raw_tag(raw));
}
static inline bool gt_binary(hb_x87_transcendental_op_t op)
{return op==HB_X87_TRANS_FYL2X||op==HB_X87_TRANS_FYL2XP1||op==HB_X87_TRANS_FPATAN||op==HB_X87_TRANS_FSCALE;}
static inline bool gt_pops(hb_x87_transcendental_op_t op)
{return op==HB_X87_TRANS_FYL2X||op==HB_X87_TRANS_FYL2XP1||op==HB_X87_TRANS_FPATAN;}
static inline bool gt_pushes(hb_x87_transcendental_op_t op)
{return op==HB_X87_TRANS_FSINCOS||op==HB_X87_TRANS_FPTAN;}

/* Independently model the guest commit contract for a marked admitted row.
 * The supplied raw numerical answer may be a fixed independent literal or
 * the component-backed integration reference below. No guest setter/pop/push
 * or production status helper is called. */
static inline bool gt_commit(hb_x87_state_t *expected,hb_x87_transcendental_op_t op,
                             const hb_x87_transcendental_result_t *numerical,
                             hb_result_t *result)
{
    bool push=gt_pushes(op),pop=gt_pops(op);unsigned old=expected->top;
    unsigned cleared=(op==HB_X87_TRANS_FSIN||op==HB_X87_TRANS_FCOS||push)?0x0400u:0;
    unsigned raised=(numerical->component_flags&0x10u)?1u:0;
    if(numerical->result_count!=(push?2u:1u)||(numerical->component_flags&~0x1fu)||
       numerical->status_set!=raised||numerical->status_clear!=cleared)return false;
    expected->status_word=(uint16_t)((expected->status_word&~cleared)|raised);
    gt_store(expected,pop?(old+1u)&7u:old,numerical->raw[0]);
    *result=HB_OK;
    if(pop){gt_tag(expected,old,3);gt_top(expected,(old+1u)&7u);}
    if(push){unsigned dest=(old+7u)&7u;bool occupied=((expected->tag_word>>(2*dest))&3u)!=3u;
        if(occupied){
            expected->status_word|=0x0241u;
            if(!(expected->control_word&1u)){expected->status_word|=0x8080u;*result=HB_ERR_EXEC_FAULT;return true;}
            gt_top(expected,dest);uint64_t indefinite=UINT64_C(0xfff8000000000000);
            memcpy(&expected->st[dest],&indefinite,8);
            expected->st_ext_valid&=(uint8_t)~(1u<<dest);gt_tag(expected,dest,2);
        }else{gt_top(expected,dest);gt_store(expected,dest,numerical->raw[1]);}
    }
    return true;
}

/* Caller must choose this only through the static reviewed row inventory,
 * before host seeding/capture. No admission/empty/pending gate lives here. */
static inline bool gt_transport_reference(const hb_x87_state_t *before,
                                          hb_x87_state_t *expected,
                                          hb_x87_transcendental_op_t op,
                                          gt_reference *reference)
{
    uint8_t a[10],b[10];gt_authoritative(before,0,a);
    if(gt_binary(op))gt_authoritative(before,1,b);
    if(!hb_x87_transcendental(op,a,gt_binary(op)?b:NULL,before->control_word,&reference->numerical))return false;
    memcpy(expected,before,sizeof(*expected));
    return gt_commit(expected,op,&reference->numerical,&reference->expected_return);
}
#endif
