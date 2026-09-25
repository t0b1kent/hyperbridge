/* Guest-only independent FPATAN negative-X quadrant references.
 * Generated with bounded rational atan series; no component/native oracle.
 * Include the unchanged component reference_vectors.h before this file. */
#ifndef HB_TRANSCENDENTAL_GUEST_QUADRANT_VECTORS_H
#define HB_TRANSCENDENTAL_GUEST_QUADRANT_VECTORS_H
static const ct_vector gt_quadrant_vectors[] = {
 {"fpatan_negative_x_positive_y",HB_X87_TRANS_FPATAN,{UINT16_C(0xc000),UINT64_C(0x8000000000000000)},{UINT16_C(0x3fff),UINT64_C(0x8000000000000000)},1u,{{{UINT16_C(0x4000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0x4000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0x4000),UINT64_C(0xab63739cbfad72cd)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0x4000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}}},0x10u,0x0u,"independent_mathematical_interval"},
 {"fpatan_negative_x_negative_y",HB_X87_TRANS_FPATAN,{UINT16_C(0xc000),UINT64_C(0x8000000000000000)},{UINT16_C(0xbfff),UINT64_C(0x8000000000000000)},1u,{{{UINT16_C(0xc000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0xc000),UINT64_C(0xab63739cbfad72cd)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0xc000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}},{{UINT16_C(0xc000),UINT64_C(0xab63739cbfad72cc)},{UINT16_C(0x0000),UINT64_C(0x0000000000000000)}}},0x10u,0x0u,"independent_mathematical_interval"},
};
#endif
