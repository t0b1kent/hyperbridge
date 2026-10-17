# gs-instance — expected result (MIT; MacRunner, 17.10.2026)

Pipeline: VS `gs_instance_vs` + GS `gs_instance_gs` (`[instance(5)]`, point input, triangle strip output, 4 vertices) + PS `gs_instance_ps`;
empty root signature (no resources); primitive topology POINT; one vertex at POSITION = (0.0, 0.0); render target 64×64 RGBA8_UNORM,
cleared to (0, 0, 0, 0); depth test off; cull mode NONE; viewport 64×64.

Only GS instance 3 emits: a quad of half-size 0.25 in clip space around the point → pixels x, y ∈ [24, 40) (16 × 16 = 256 pixels)
of colour (0.2, 0.8, 0.4, 1.0) = RGBA8 (51, 204, 102, 255). Everything else stays (0, 0, 0, 0).

Probe points (x, y from the top-left corner, D3D convention):
- (32, 32) = (51, 204, 102, 255)   centre, inside the square
- (24, 24) = (51, 204, 102, 255)   top-left corner pixel of the square
- (39, 39) = (51, 204, 102, 255)   bottom-right corner pixel of the square
- (23, 32) = (0, 0, 0, 0), (40, 32) = (0, 0, 0, 0), (32, 23) = (0, 0, 0, 0), (32, 40) = (0, 0, 0, 0)   just outside
- (8, 8) = (0, 0, 0, 0), (56, 56) = (0, 0, 0, 0)
- lit pixels (non-zero RGBA8) in the whole target: exactly 256.

Failure signatures: nothing lit → instance id never equals 3 (instancing not dispatched or id not delivered);
256 lit but the GS ran once per instance id ≠ 3 → impossible with this shader; any lit pixel outside the square → wrong geometry.
