// Own public synthetic fixture. No game data or Apple implementation.
#ifndef TRI
#define TRI 0
#endif
#ifndef PARTITION
#define PARTITION "integer"
#endif
#ifndef TOPOLOGY
#define TOPOLOGY "triangle_cw"
#endif
#if TRI
#define DOMAIN "tri"
#define EDGE_COUNT 3
#define INNER_COUNT 1
#else
#define DOMAIN "quad"
#define EDGE_COUNT 4
#define INNER_COUNT 2
#endif
cbuffer Params : register(b0) { float4 outer; float2 inner; uint tag; uint cap; };
RWByteAddressBuffer Recorder : register(u0);
struct CP { float4 position : SV_Position; };
struct Patch { float edges[EDGE_COUNT] : SV_TessFactor; float inside[INNER_COUNT] : SV_InsideTessFactor; };
struct Pixel { float4 position : SV_Position; float4 color : COLOR0; };
Patch patch_main(OutputPatch<CP,1> cp) {
    Patch p;
    [unroll] for(uint i=0;i<EDGE_COUNT;i++) p.edges[i]=outer[i];
    [unroll] for(uint j=0;j<INNER_COUNT;j++) p.inside[j]=inner[j];
    return p;
}
[domain(DOMAIN)][outputcontrolpoints(1)][partitioning(PARTITION)]
[outputtopology(TOPOLOGY)][patchconstantfunc("patch_main")]
CP hs_main(InputPatch<CP,1> points) { CP p; p.position=float4(0,0,0,1); return p; }
[domain(DOMAIN)]
Pixel ds_main(Patch p,
#if TRI
              float3 uv : SV_DomainLocation,
#else
              float2 uv : SV_DomainLocation,
#endif
              const OutputPatch<CP,1> cp) {
    uint index; Recorder.InterlockedAdd(0,1,index);
    if(index<cap) {
#if TRI
        Recorder.Store4(16+index*16,uint4(asuint(uv),tag));
#else
        Recorder.Store4(16+index*16,uint4(asuint(uv),0,tag));
#endif
    } else { uint prior; Recorder.InterlockedAdd(4,1,prior); }
    Pixel result;
    precise float x=-0.875+uv.x*1.75;
    precise float y=-0.875+uv.y*1.75;
    precise float red=uv.x*uv.x;
    precise float green=uv.y*uv.y;
    result.position=float4(x,y,0,1);
    result.color=float4(red,green,0.25,1);
    return result;
}
