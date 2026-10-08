// SPDX-License-Identifier: MIT
#include "fixed-fixture.h"
cbuffer Params : register(b0) { uint rotation; uint reverse_order; uint color_shift; uint geometry;
    uint unused0; uint unused1; uint tag; uint cap; };
RWByteAddressBuffer Recorder : register(u0);
RWByteAddressBuffer Fragment : register(u1);
struct Pixel { float4 position : SV_Position; float4 color : COLOR0; };
uint source_index(uint vid, uint shift) {
    uint local = (vid % 3 + rotation + shift) % 3;
    if (reverse_order != 0 && local != 0) local = 3-local;
    return FixedIndices[vid / 3 * 3 + local];
}
Pixel vs_main(uint vid : SV_VertexID) {
    uint pi=source_index(vid,0), ci=source_index(vid,color_shift);
    Pixel result;
    result.position=asfloat(uint4(FixedPositions[geometry][pi][0],FixedPositions[geometry][pi][1],FixedPositions[geometry][pi][2],FixedPositions[geometry][pi][3]));
    result.color=asfloat(uint4(FixedColors[geometry][ci][0],FixedColors[geometry][ci][1],FixedColors[geometry][ci][2],FixedColors[geometry][ci][3]));
    uint index; Recorder.InterlockedAdd(0,1,index);
    if (index < cap) {
        Recorder.Store4(16+index*48,uint4(vid,pi,ci,tag));
        Recorder.Store4(32+index*48,asuint(result.position));
        Recorder.Store4(48+index*48,asuint(result.color));
    } else { uint prior; Recorder.InterlockedAdd(4,1,prior); }
    return result;
}
float4 ps_main(Pixel input) : SV_Target0 { return input.color; }
float4 ps_observe(Pixel input) : SV_Target0 {
    uint2 xy=uint2(input.position.xy);
    if (xy.x>=128 || xy.y>=128) { uint prior; Fragment.InterlockedAdd(0,1,prior); return input.color; }
    uint address=16+(xy.y*128+xy.x)*64;
    uint previous; Fragment.InterlockedAdd(address,1,previous);
    if (previous==0) {
        Fragment.Store4(address+16,asuint(input.color));
        Fragment.Store4(address+32,asuint(input.color));
        Fragment.Store4(address+48,asuint(input.position));
    }
    return input.color;
}
