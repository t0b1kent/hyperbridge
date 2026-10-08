// Public synthetic cross-term fixture; no game input or private implementation.
cbuffer Params : register(b0) { float4 outer; float2 inner; uint tag; uint cap; };
RWByteAddressBuffer Recorder : register(u0);
struct CP { float4 position : SV_Position; };
struct Patch { float edges[4] : SV_TessFactor; float inside[2] : SV_InsideTessFactor; };
struct Pixel { float4 position : SV_Position; float4 color : COLOR0; };
[domain("quad")]
Pixel ds_main(Patch patch, float2 uv : SV_DomainLocation, const OutputPatch<CP,1> cp) {
    uint index; Recorder.InterlockedAdd(0,1,index);
    Pixel result;
    precise float x=-0.875+uv.x*1.75;
    precise float y=-0.875+uv.y*1.75;
    precise float red=uv.x*uv.y;
    precise float green=uv.x*uv.x;
    result.position=float4(x,y,0,1);
    result.color=float4(red,green,0.25,1);
    // Observe the exact DS outputs before the rasterizer interpolates them.
    // One logical record: UV/tag16 + SV_Position16 + COLOR16; no extra shader math.
    if (index < cap) {
        Recorder.Store4(16+index*48,uint4(asuint(uv),0,tag));
        Recorder.Store4(32+index*48,asuint(result.position));
        Recorder.Store4(48+index*48,asuint(result.color));
    } else { uint prior; Recorder.InterlockedAdd(4,1,prior); }
    return result;
}
