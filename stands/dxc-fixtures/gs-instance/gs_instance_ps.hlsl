// SPDX-License-Identifier: MIT
// MacRunner fixture gs-instance (17.10.2026): pixel shader writes the interpolated colour.
struct GSOut {
    float4 pos : SV_Position;
    float4 color : COLOR0;
};

float4 main(GSOut input) : SV_Target0 {
    return input.color;
}
