// Public synthetic VS/PS paired with the unchanged tri/quad HS/DS.
struct CP { float4 position : SV_Position; };
struct Pixel { float4 position : SV_Position; float4 color : COLOR0; };
CP vs_main(uint id : SV_VertexID) { CP r; r.position=float4(0,0,0,1); return r; }
float4 ps_main(Pixel input) : SV_Target0 { return input.color; }

// Per pixel: counter/reserved16, input16, output16, SV_Position16.
// Header16 contains the out-of-bounds count; no interpolation arithmetic added.
RWByteAddressBuffer Fragment : register(u1);
float4 ps_observe(Pixel input) : SV_Target0 {
    uint2 xy = uint2(input.position.xy);
    if (xy.x >= 128 || xy.y >= 128) {
        uint ignored; Fragment.InterlockedAdd(0, 1, ignored);
        return input.color;
    }
    uint address = 16 + (xy.y * 128 + xy.x) * 64;
    uint previous; Fragment.InterlockedAdd(address, 1, previous);
    float4 result = input.color;
    if (previous == 0) {
        Fragment.Store4(address + 16, asuint(input.color));
        Fragment.Store4(address + 32, asuint(result));
        Fragment.Store4(address + 48, asuint(input.position));
    }
    return result;
}
