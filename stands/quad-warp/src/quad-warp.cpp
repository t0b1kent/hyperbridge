// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
// Public fixed triangle-list readback. WARP only; no adapter fallback.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;
constexpr UINT Width = 128, Height = 128, Capacity = 64;
constexpr UINT RecordWords = 12; // UV/tag + DS position + DS color, each uint4.
constexpr UINT RecordBytes = 16 + 4 * RecordWords * Capacity + 256;
constexpr UINT FragmentBytes = 16 + Width * Height * 64 + 256;
void check(HRESULT hr, const char *where) {
    if (FAILED(hr)) {
        std::ostringstream out;
        out << where << " HRESULT=0x" << std::hex << uint32_t(hr);
        throw std::runtime_error(out.str());
    }
}
void require(bool value, const char *where) {
    if (!value) throw std::runtime_error(where);
}
void bytes(const fs::path &path, const void *data, size_t size) {
    std::ofstream f(path, std::ios::binary);
    f.write(static_cast<const char *>(data), static_cast<std::streamsize>(size));
    f.close();
    require(bool(f), "write readback");
}
struct Case {
    std::string name, winding;
    std::array<uint32_t, 8> words{};
};
std::vector<Case> read_cases(const fs::path &path) {
    std::ifstream f(path);
    require(bool(f), "open cases");
    std::string line;
    std::getline(f, line); // Header is fixed and checked below.
    if (!line.empty() && line.back() == '\r') line.pop_back();
    require(line == "name,rotation,reverse,color_shift,tag", "CSV header");
    std::vector<Case> result;
    std::set<std::string> names;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::istringstream row(line);
        std::vector<std::string> values;
        std::string v;
        while (std::getline(row, v, ',')) values.push_back(v);
        require(values.size() == 5, "CSV width");
        Case c;
        c.name = values[0];
        require(c.name.size() == 5 && c.name[0] == 'c' &&
                c.name.find_first_not_of("0123456789", 1) == std::string::npos &&
                names.insert(c.name).second, "case name");
        for (size_t i = 0; i < 4; ++i) {
            size_t end = 0;
            auto number = std::stoull(values[i + 1], &end, 0);
            require(end == values[i + 1].size() && number <= UINT32_MAX, "case word");
            c.words[i == 3 ? 6 : i] = uint32_t(number);
        }
        require(c.words[0]<3 && c.words[1]<2 && c.words[2]<2, "permutation limits");
        c.winding = c.words[1] ? "ccw" : "cw";
        c.words[7] = Capacity;
        result.push_back(c);
    }
    require(result.size() == 12, "twelve cases required");
    return result;
}
ComPtr<ID3DBlob> shader(const fs::path &dir, const wchar_t *name) {
    ComPtr<ID3DBlob> b;
    check(D3DReadFileToBlob((dir / name).c_str(), &b), "read shader");
    return b;
}
D3D12_SHADER_BYTECODE code(const ComPtr<ID3DBlob> &b) {
    return {b->GetBufferPointer(), b->GetBufferSize()};
}
D3D12_RESOURCE_DESC buffer_desc(UINT64 size) {
    D3D12_RESOURCE_DESC d{};
    d.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    d.Width = size; d.Height = 1; d.DepthOrArraySize = 1; d.MipLevels = 1;
    d.SampleDesc.Count = 1; d.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    return d;
}
ComPtr<ID3D12Resource> resource(ID3D12Device *d, D3D12_HEAP_TYPE heap,
        const D3D12_RESOURCE_DESC &desc, D3D12_RESOURCE_STATES state,
        const D3D12_CLEAR_VALUE *clear = nullptr) {
    D3D12_HEAP_PROPERTIES hp{};
    hp.Type = heap; hp.CreationNodeMask = 1; hp.VisibleNodeMask = 1;
    ComPtr<ID3D12Resource> r;
    check(d->CreateCommittedResource(&hp, D3D12_HEAP_FLAG_NONE, &desc, state,
                                    clear, IID_PPV_ARGS(&r)), "create resource");
    return r;
}
void transition(ID3D12GraphicsCommandList *cl, ID3D12Resource *r,
                D3D12_RESOURCE_STATES before, D3D12_RESOURCE_STATES after) {
    D3D12_RESOURCE_BARRIER b{};
    b.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    b.Transition.pResource = r; b.Transition.StateBefore = before;
    b.Transition.StateAfter = after;
    b.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    cl->ResourceBarrier(1, &b);
}
struct Event {
    HANDLE value = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    Event() { require(value != nullptr, "fence event"); }
    ~Event() { CloseHandle(value); }
    Event(const Event &) = delete;
    Event &operator=(const Event &) = delete;
};
int main(int argc, char **argv) {
    try {
        require(argc >= 4 && argc <= 6, "usage: quad-warp SHADERS CASES.csv NEW-OUT [rgba8|float32] [observe]");
        require(argc == 4 || std::string(argv[4]) == "float32" || std::string(argv[4]) == "rgba8", "unknown target format");
        require(argc < 6 || std::string(argv[5]) == "observe", "unknown observer mode");
        const bool float_target = argc >= 5 && std::string(argv[4]) == "float32";
        const bool observe = argc == 6;
        const DXGI_FORMAT target_format = float_target ? DXGI_FORMAT_R32G32B32A32_FLOAT : DXGI_FORMAT_R8G8B8A8_UNORM;
        const UINT bytes_per_pixel = float_target ? 16u : 4u;
        const fs::path shader_dir(argv[1]), out(argv[3]);
        const auto cases = read_cases(argv[2]);
        require(!fs::exists(out) && fs::create_directories(out), "fresh output directory");
        ComPtr<IDXGIFactory4> factory;
        check(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)), "DXGI factory");
        ComPtr<IDXGIAdapter1> adapter;
        check(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter)), "EnumWarpAdapter");
        DXGI_ADAPTER_DESC1 ad{};
        check(adapter->GetDesc1(&ad), "adapter description");
        require((ad.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0, "WARP software flag");
        ComPtr<ID3D12Device> device;
        check(D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_12_1,
                               IID_PPV_ARGS(&device)), "WARP D3D12 feature level 12_1");
        D3D12_FEATURE_DATA_SHADER_MODEL sm{D3D_SHADER_MODEL_6_0};
        check(device->CheckFeatureSupport(D3D12_FEATURE_SHADER_MODEL, &sm, sizeof(sm)), "shader model");
        require(sm.HighestShaderModel >= D3D_SHADER_MODEL_6_0, "SM6 required");
        std::ofstream meta(out / "device.json");
        meta << "{\"backend\":\"WARP, not hardware\",\"software\":true,"
             << "\"feature_level\":\"12_1\",\"shader_model\":\"6_0\","
             << "\"format\":\"" << (float_target ? "RGBA32_FLOAT" : "RGBA8_UNORM") << "\","
             << "\"observer\":" << (observe ? "true" : "false") << ","
             << "\"vendor_id\":" << ad.VendorId << ",\"device_id\":" << ad.DeviceId << "}\n";
        meta.close(); require(bool(meta), "device receipt");

        D3D12_ROOT_PARAMETER rp[3]{};
        rp[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
        rp[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
        rp[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
        rp[2].Descriptor.ShaderRegister = 1;
        for (auto &p : rp) p.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        D3D12_ROOT_SIGNATURE_DESC rd{};
        rd.NumParameters = 3; rd.pParameters = rp;
        rd.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;
        ComPtr<ID3DBlob> root_blob, root_error;
        check(D3D12SerializeRootSignature(&rd, D3D_ROOT_SIGNATURE_VERSION_1,
                                          &root_blob, &root_error), "serialize root signature");
        ComPtr<ID3D12RootSignature> root;
        check(device->CreateRootSignature(0, root_blob->GetBufferPointer(), root_blob->GetBufferSize(),
                                         IID_PPV_ARGS(&root)), "root signature");
        auto vs = shader(shader_dir, L"vs.dxil"), ps = shader(shader_dir, observe ? L"ps-observe.dxil" : L"ps.dxil");
        ComPtr<ID3D12PipelineState> pipelines[2][2];
        for (int winding = 0; winding < 2; ++winding) for (int cull = 0; cull < 2; ++cull) {
            D3D12_GRAPHICS_PIPELINE_STATE_DESC pd{};
            pd.pRootSignature = root.Get();
            pd.VS = code(vs); pd.PS = code(ps);
            pd.BlendState.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;
            pd.BlendState.RenderTarget[0].DestBlend = D3D12_BLEND_ZERO;
            pd.BlendState.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
            pd.BlendState.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
            pd.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_ZERO;
            pd.BlendState.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
            pd.BlendState.RenderTarget[0].LogicOp = D3D12_LOGIC_OP_NOOP;
            pd.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
            pd.SampleMask = UINT_MAX;
            pd.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
            pd.RasterizerState.CullMode = cull ? D3D12_CULL_MODE_BACK : D3D12_CULL_MODE_NONE;
            pd.RasterizerState.FrontCounterClockwise = FALSE;
            pd.RasterizerState.DepthClipEnable = TRUE;
            pd.DepthStencilState.DepthFunc = D3D12_COMPARISON_FUNC_ALWAYS;
            pd.DepthStencilState.FrontFace.StencilFailOp = D3D12_STENCIL_OP_KEEP;
            pd.DepthStencilState.FrontFace.StencilDepthFailOp = D3D12_STENCIL_OP_KEEP;
            pd.DepthStencilState.FrontFace.StencilPassOp = D3D12_STENCIL_OP_KEEP;
            pd.DepthStencilState.FrontFace.StencilFunc = D3D12_COMPARISON_FUNC_ALWAYS;
            pd.DepthStencilState.BackFace = pd.DepthStencilState.FrontFace;
            pd.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
            pd.NumRenderTargets = 1; pd.RTVFormats[0] = target_format;
            pd.SampleDesc.Count = 1;
            check(device->CreateGraphicsPipelineState(&pd, IID_PPV_ARGS(&pipelines[winding][cull])), "PSO");
        }
        D3D12_COMMAND_QUEUE_DESC qd{};
        ComPtr<ID3D12CommandQueue> queue;
        check(device->CreateCommandQueue(&qd, IID_PPV_ARGS(&queue)), "queue");
        ComPtr<ID3D12CommandAllocator> allocator;
        check(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator)), "allocator");
        ComPtr<ID3D12GraphicsCommandList> cl;
        check(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator.Get(), nullptr,
                                       IID_PPV_ARGS(&cl)), "command list");
        check(cl->Close(), "initial close");
        ComPtr<ID3D12Fence> fence;
        check(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence)), "fence");
        Event event;
        UINT64 serial = 0;
        auto execute = [&]() {
            check(cl->Close(), "close");
            ID3D12CommandList *lists[] = {cl.Get()};
            queue->ExecuteCommandLists(1, lists);
            check(queue->Signal(fence.Get(), ++serial), "signal");
            check(fence->SetEventOnCompletion(serial, event.value), "fence event registration");
            require(WaitForSingleObject(event.value, 5000) == WAIT_OBJECT_0, "fence timeout 5s");
            check(device->GetDeviceRemovedReason(), "device removed");
        };
        D3D12_DESCRIPTOR_HEAP_DESC hd{};
        hd.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV; hd.NumDescriptors = 1;
        ComPtr<ID3D12DescriptorHeap> heap;
        check(device->CreateDescriptorHeap(&hd, IID_PPV_ARGS(&heap)), "RTV heap");
        const auto rtv = heap->GetCPUDescriptorHandleForHeapStart();
        D3D12_RESOURCE_DESC td{};
        td.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D; td.Width = Width; td.Height = Height;
        td.DepthOrArraySize = 1; td.MipLevels = 1; td.Format = target_format;
        td.SampleDesc.Count = 1; td.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;
        D3D12_CLEAR_VALUE clear{}; clear.Format = td.Format;
        auto target = resource(device.Get(), D3D12_HEAP_TYPE_DEFAULT, td, D3D12_RESOURCE_STATE_RENDER_TARGET, &clear);
        device->CreateRenderTargetView(target.Get(), nullptr, rtv);
        D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
        UINT rows = 0; UINT64 row_size = 0, pixel_bytes = 0;
        device->GetCopyableFootprints(&td, 0, 1, 0, &footprint, &rows, &row_size, &pixel_bytes);
        require(rows == Height && row_size == Width * bytes_per_pixel, "RGBA footprint");
        auto pixels_rb = resource(device.Get(), D3D12_HEAP_TYPE_READBACK, buffer_desc(pixel_bytes), D3D12_RESOURCE_STATE_COPY_DEST);
        auto records_rb = resource(device.Get(), D3D12_HEAP_TYPE_READBACK, buffer_desc(RecordBytes), D3D12_RESOURCE_STATE_COPY_DEST);
        auto fragments_rb = resource(device.Get(), D3D12_HEAP_TYPE_READBACK, buffer_desc(FragmentBytes), D3D12_RESOURCE_STATE_COPY_DEST);
        std::ofstream results(out / "results.jsonl");
        require(bool(results), "results file");
        for (const auto &c : cases) {
            const fs::path dir = out / c.name;
            require(fs::create_directory(dir), "case directory");
            auto params = resource(device.Get(), D3D12_HEAP_TYPE_UPLOAD, buffer_desc(256), D3D12_RESOURCE_STATE_GENERIC_READ);
            auto init = resource(device.Get(), D3D12_HEAP_TYPE_UPLOAD, buffer_desc(RecordBytes), D3D12_RESOURCE_STATE_GENERIC_READ);
            auto ud = buffer_desc(RecordBytes); ud.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
            auto recorder = resource(device.Get(), D3D12_HEAP_TYPE_DEFAULT, ud, D3D12_RESOURCE_STATE_COPY_DEST);
            auto fragment_init = resource(device.Get(), D3D12_HEAP_TYPE_UPLOAD, buffer_desc(FragmentBytes), D3D12_RESOURCE_STATE_GENERIC_READ);
            auto fd = buffer_desc(FragmentBytes); fd.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
            auto fragments = resource(device.Get(), D3D12_HEAP_TYPE_DEFAULT, fd, D3D12_RESOURCE_STATE_COPY_DEST);
            void *mapped = nullptr;
            D3D12_RANGE no_read{0, 0};
            check(params->Map(0, &no_read, &mapped), "map constants");
            std::memset(mapped, 0, 256); std::memcpy(mapped, c.words.data(), 32);
            params->Unmap(0, nullptr);
            check(init->Map(0, &no_read, &mapped), "map initialization");
            std::memset(mapped, 0xa5, RecordBytes); std::memset(mapped, 0, 16);
            init->Unmap(0, nullptr);
            check(fragment_init->Map(0, &no_read, &mapped), "map fragment initialization");
            std::memset(mapped, 0xa5, FragmentBytes); std::memset(mapped, 0, 16);
            for (UINT i = 0; i < Width * Height; ++i)
                static_cast<uint32_t *>(mapped)[4 + 16*i] = 0;
            fragment_init->Unmap(0, nullptr);
            bytes(dir / "params.bin", c.words.data(), 32);
            for (int pass = 0; pass < 2; ++pass) {
                check(allocator->Reset(), "reset allocator");
                check(cl->Reset(allocator.Get(), pipelines[c.winding == "ccw"][pass].Get()), "reset list");
                if (pass) transition(cl.Get(), fragments.Get(), D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_COPY_DEST);
                cl->CopyBufferRegion(fragments.Get(), 0, fragment_init.Get(), 0, FragmentBytes);
                transition(cl.Get(), fragments.Get(), D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
                if (!pass) {
                    cl->CopyBufferRegion(recorder.Get(), 0, init.Get(), 0, RecordBytes);
                    transition(cl.Get(), recorder.Get(), D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
                } else {
                    transition(cl.Get(), recorder.Get(), D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
                    transition(cl.Get(), target.Get(), D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_RENDER_TARGET);
                }
                const float rgba[4] = {0, 0, 0, 0};
                cl->ClearRenderTargetView(rtv, rgba, 0, nullptr);
                cl->OMSetRenderTargets(1, &rtv, FALSE, nullptr);
                D3D12_VIEWPORT viewport{0, 0, float(Width), float(Height), 0, 1};
                D3D12_RECT scissor{0, 0, LONG(Width), LONG(Height)};
                cl->RSSetViewports(1, &viewport); cl->RSSetScissorRects(1, &scissor);
                cl->SetGraphicsRootSignature(root.Get());
                cl->SetGraphicsRootConstantBufferView(0, params->GetGPUVirtualAddress());
                cl->SetGraphicsRootUnorderedAccessView(1, recorder->GetGPUVirtualAddress());
                cl->SetGraphicsRootUnorderedAccessView(2, fragments->GetGPUVirtualAddress());
                cl->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
                cl->DrawInstanced(6, 1, 0, 0);
                transition(cl.Get(), target.Get(), D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_COPY_SOURCE);
                transition(cl.Get(), recorder.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_COPY_SOURCE);
                transition(cl.Get(), fragments.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_COPY_SOURCE);
                D3D12_TEXTURE_COPY_LOCATION src{}, dst{};
                src.pResource = target.Get(); src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
                dst.pResource = pixels_rb.Get(); dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
                dst.PlacedFootprint = footprint;
                cl->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
                cl->CopyBufferRegion(records_rb.Get(), 0, recorder.Get(), 0, RecordBytes);
                cl->CopyBufferRegion(fragments_rb.Get(), 0, fragments.Get(), 0, FragmentBytes);
                // Leave target ready for the next case after the second copy.
                if (pass) transition(cl.Get(), target.Get(), D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_RENDER_TARGET);
                execute();
                std::vector<uint8_t> rgba_out(Width * Height * bytes_per_pixel);
                D3D12_RANGE range{0, SIZE_T(pixel_bytes)};
                check(pixels_rb->Map(0, &range, &mapped), "map pixels");
                for (UINT y = 0; y < Height; ++y)
                    std::memcpy(rgba_out.data() + y * Width * bytes_per_pixel,
                        static_cast<const uint8_t *>(mapped) + footprint.Offset + y * footprint.Footprint.RowPitch, Width * bytes_per_pixel);
                pixels_rb->Unmap(0, &no_read);
                bytes(dir / (pass ? "front.pixels.bin" : "own.pixels.bin"), rgba_out.data(), rgba_out.size());
                UINT covered = 0;
                for (size_t i = 0; i < rgba_out.size(); i += bytes_per_pixel) {
                    if (float_target) {
                        float alpha = 0;
                        std::memcpy(&alpha, rgba_out.data() + i + 12, 4);
                        require(alpha == 0.f || alpha == 1.f, "float alpha");
                        covered += alpha != 0.f;
                    } else covered += rgba_out[i + 3] != 0;
                }
                require(pass || covered != 0, "empty uncull target");
                range.End = FragmentBytes;
                check(fragments_rb->Map(0, &range, &mapped), "map fragment records");
                bytes(dir / (pass ? "fragment.bin" : "fragment-uncull.bin"), mapped, FragmentBytes);
                fragments_rb->Unmap(0, &no_read);
                range.End = RecordBytes;
                check(records_rb->Map(0, &range, &mapped), "map recorder");
                std::vector<uint32_t> words(RecordBytes / 4);
                std::memcpy(words.data(), mapped, RecordBytes);
                records_rb->Unmap(0, &no_read);
                bytes(dir / (pass ? "recorder.bin" : "recorder-uncull.bin"), words.data(), RecordBytes);
                bool valid = words[0] > 0 && words[0] <= Capacity && words[1] == 0 && words[2] == 0 && words[3] == 0;
                for (UINT i = 0; i < words[0] && i < Capacity; ++i)
                    valid &= words[4 + i * RecordWords] < 6 && words[4 + i * RecordWords + 1] < 4 && words[4 + i * RecordWords + 2] < 4 && words[4 + i * RecordWords + 3] == c.words[6];
                for (size_t i = 4 + size_t(words[0]) * RecordWords; i < words.size(); ++i) valid &= words[i] == 0xa5a5a5a5u;
                results << "{\"name\":\"" << c.name << "\",\"winding\":\"" << c.winding
                        << "\",\"pass\":" << pass << ",\"covered\":" << covered
                        << ",\"invocations_cumulative\":" << words[0] << ",\"overflow\":" << words[1]
                        << ",\"record_words\":" << RecordWords
                        << ",\"guards_tags\":" << (valid ? "true" : "false") << "}\n";
                results.flush(); require(bool(results), "result receipt");
                require(valid, "recorder bounds tags guards");
            }
        }
        results.close(); require(bool(results), "close results");
        std::cout << "COMPLETE cases=12 draws=24 backend=WARP_NOT_HARDWARE\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAILED " << e.what() << '\n';
        return 1;
    }
}
