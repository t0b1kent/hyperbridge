/* SPDX-License-Identifier: MIT; generated */
typedef void (*Fn)(struct Ctx*);
struct Op {const char *name; Fn fn; int w,e,ie,n,scale;};
extern void gather_0(struct Ctx*);
extern void gather_1(struct Ctx*);
extern void gather_2(struct Ctx*);
extern void gather_3(struct Ctx*);
extern void gather_4(struct Ctx*);
extern void gather_5(struct Ctx*);
extern void gather_6(struct Ctx*);
extern void gather_7(struct Ctx*);
extern void gather_8(struct Ctx*);
extern void gather_9(struct Ctx*);
extern void gather_10(struct Ctx*);
extern void gather_11(struct Ctx*);
extern void gather_12(struct Ctx*);
extern void gather_13(struct Ctx*);
extern void gather_14(struct Ctx*);
extern void gather_15(struct Ctx*);
extern void gather_16(struct Ctx*);
extern void gather_17(struct Ctx*);
extern void gather_18(struct Ctx*);
extern void gather_19(struct Ctx*);
extern void gather_20(struct Ctx*);
extern void gather_21(struct Ctx*);
extern void gather_22(struct Ctx*);
extern void gather_23(struct Ctx*);
extern void gather_24(struct Ctx*);
extern void gather_25(struct Ctx*);
extern void gather_26(struct Ctx*);
extern void gather_27(struct Ctx*);
extern void gather_28(struct Ctx*);
extern void gather_29(struct Ctx*);
extern void gather_30(struct Ctx*);
extern void gather_31(struct Ctx*);
extern void gather_32(struct Ctx*);
extern void gather_33(struct Ctx*);
extern void gather_34(struct Ctx*);
extern void gather_35(struct Ctx*);
extern void gather_36(struct Ctx*);
extern void gather_37(struct Ctx*);
extern void gather_38(struct Ctx*);
extern void gather_39(struct Ctx*);
extern void gather_40(struct Ctx*);
extern void gather_41(struct Ctx*);
extern void gather_42(struct Ctx*);
extern void gather_43(struct Ctx*);
extern void gather_44(struct Ctx*);
extern void gather_45(struct Ctx*);
extern void gather_46(struct Ctx*);
extern void gather_47(struct Ctx*);
extern void gather_48(struct Ctx*);
extern void gather_49(struct Ctx*);
extern void gather_50(struct Ctx*);
extern void gather_51(struct Ctx*);
extern void gather_52(struct Ctx*);
extern void gather_53(struct Ctx*);
extern void gather_54(struct Ctx*);
extern void gather_55(struct Ctx*);
extern void gather_56(struct Ctx*);
extern void gather_57(struct Ctx*);
extern void gather_58(struct Ctx*);
extern void gather_59(struct Ctx*);
extern void gather_60(struct Ctx*);
extern void gather_61(struct Ctx*);
extern void gather_62(struct Ctx*);
extern void gather_63(struct Ctx*);
static const struct Op ops[]={
{"vgatherdps",gather_0,16,4,4,4,1},
{"vgatherdps",gather_1,16,4,4,4,2},
{"vgatherdps",gather_2,16,4,4,4,4},
{"vgatherdps",gather_3,16,4,4,4,8},
{"vgatherdps",gather_4,32,4,4,8,1},
{"vgatherdps",gather_5,32,4,4,8,2},
{"vgatherdps",gather_6,32,4,4,8,4},
{"vgatherdps",gather_7,32,4,4,8,8},
{"vgatherqps",gather_8,16,4,8,2,1},
{"vgatherqps",gather_9,16,4,8,2,2},
{"vgatherqps",gather_10,16,4,8,2,4},
{"vgatherqps",gather_11,16,4,8,2,8},
{"vgatherqps",gather_12,32,4,8,4,1},
{"vgatherqps",gather_13,32,4,8,4,2},
{"vgatherqps",gather_14,32,4,8,4,4},
{"vgatherqps",gather_15,32,4,8,4,8},
{"vgatherdpd",gather_16,16,8,4,2,1},
{"vgatherdpd",gather_17,16,8,4,2,2},
{"vgatherdpd",gather_18,16,8,4,2,4},
{"vgatherdpd",gather_19,16,8,4,2,8},
{"vgatherdpd",gather_20,32,8,4,4,1},
{"vgatherdpd",gather_21,32,8,4,4,2},
{"vgatherdpd",gather_22,32,8,4,4,4},
{"vgatherdpd",gather_23,32,8,4,4,8},
{"vgatherqpd",gather_24,16,8,8,2,1},
{"vgatherqpd",gather_25,16,8,8,2,2},
{"vgatherqpd",gather_26,16,8,8,2,4},
{"vgatherqpd",gather_27,16,8,8,2,8},
{"vgatherqpd",gather_28,32,8,8,4,1},
{"vgatherqpd",gather_29,32,8,8,4,2},
{"vgatherqpd",gather_30,32,8,8,4,4},
{"vgatherqpd",gather_31,32,8,8,4,8},
{"vpgatherdd",gather_32,16,4,4,4,1},
{"vpgatherdd",gather_33,16,4,4,4,2},
{"vpgatherdd",gather_34,16,4,4,4,4},
{"vpgatherdd",gather_35,16,4,4,4,8},
{"vpgatherdd",gather_36,32,4,4,8,1},
{"vpgatherdd",gather_37,32,4,4,8,2},
{"vpgatherdd",gather_38,32,4,4,8,4},
{"vpgatherdd",gather_39,32,4,4,8,8},
{"vpgatherqd",gather_40,16,4,8,2,1},
{"vpgatherqd",gather_41,16,4,8,2,2},
{"vpgatherqd",gather_42,16,4,8,2,4},
{"vpgatherqd",gather_43,16,4,8,2,8},
{"vpgatherqd",gather_44,32,4,8,4,1},
{"vpgatherqd",gather_45,32,4,8,4,2},
{"vpgatherqd",gather_46,32,4,8,4,4},
{"vpgatherqd",gather_47,32,4,8,4,8},
{"vpgatherdq",gather_48,16,8,4,2,1},
{"vpgatherdq",gather_49,16,8,4,2,2},
{"vpgatherdq",gather_50,16,8,4,2,4},
{"vpgatherdq",gather_51,16,8,4,2,8},
{"vpgatherdq",gather_52,32,8,4,4,1},
{"vpgatherdq",gather_53,32,8,4,4,2},
{"vpgatherdq",gather_54,32,8,4,4,4},
{"vpgatherdq",gather_55,32,8,4,4,8},
{"vpgatherqq",gather_56,16,8,8,2,1},
{"vpgatherqq",gather_57,16,8,8,2,2},
{"vpgatherqq",gather_58,16,8,8,2,4},
{"vpgatherqq",gather_59,16,8,8,2,8},
{"vpgatherqq",gather_60,32,8,8,4,1},
{"vpgatherqq",gather_61,32,8,8,4,2},
{"vpgatherqq",gather_62,32,8,8,4,4},
{"vpgatherqq",gather_63,32,8,8,4,8},
};
