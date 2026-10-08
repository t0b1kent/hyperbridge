// Public synthetic VS/PS paired with the unchanged tri/quad HS/DS.
struct CP { float4 position : SV_Position; };
struct Pixel { float4 position : SV_Position; float4 color : COLOR0; };
CP vs_main(uint id : SV_VertexID) { CP r; r.position=float4(0,0,0,1); return r; }
float4 ps_main(Pixel input) : SV_Target0 { return input.color; }
