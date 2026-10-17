// SPDX-License-Identifier: MIT
// MacRunner fixture gs-instance (17.10.2026): geometry shader with five instances; only instance 3 emits a
// quad (two triangles as a strip) of half-size 0.25 (clip space) around the input point; every other instance
// emits nothing. A wrong or missing SV_GSInstanceID therefore draws nothing (id always 0, 1, 2, 4) or draws the
// quad five times over itself (id always 3) - the second case is caught by the instance-colour probe below:
// instance 3 keeps the vertex colour, so a correct result is exactly one green square.
struct VSOut {
    float4 pos : SV_Position;
    float4 color : COLOR0;
};

struct GSOut {
    float4 pos : SV_Position;
    float4 color : COLOR0;
};

[maxvertexcount(4)]
[instance(5)]
void main(point VSOut input[1], uint instance_id : SV_GSInstanceID, inout TriangleStream<GSOut> output) {
    if (instance_id != 3)
        return;
    const float half_size = 0.25;
    const float2 center = input[0].pos.xy;
    GSOut v;
    v.color = input[0].color;
    v.pos = float4(center + float2(-half_size, -half_size), input[0].pos.z, 1.0); output.Append(v);
    v.pos = float4(center + float2(-half_size,  half_size), input[0].pos.z, 1.0); output.Append(v);
    v.pos = float4(center + float2( half_size, -half_size), input[0].pos.z, 1.0); output.Append(v);
    v.pos = float4(center + float2( half_size,  half_size), input[0].pos.z, 1.0); output.Append(v);
    output.RestartStrip();
}
