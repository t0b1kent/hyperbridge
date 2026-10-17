// SPDX-License-Identifier: MIT
// MacRunner fixture gs-instance (17.10.2026): vertex pass-through for a point list.
// Input: POSITION float2 in clip space. Output: SV_Position (z = 0.5, w = 1) and a constant COLOR.
struct VSOut {
    float4 pos : SV_Position;
    float4 color : COLOR0;
};

VSOut main(float2 position : POSITION) {
    VSOut o;
    o.pos = float4(position, 0.5, 1.0);
    o.color = float4(0.2, 0.8, 0.4, 1.0);
    return o;
}
