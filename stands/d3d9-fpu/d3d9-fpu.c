/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HyperBridge contributors
 *
 * d3d9-fpu: what IDirect3D9::CreateDevice / CreateDeviceEx and IDirect3DDevice9::Reset do to the x87 control word (and MXCSR) of the
 * calling thread and of another thread, with and without D3DCREATE_FPU_PRESERVE.  Direct3D 9 documents that without that flag it
 * "defaults to single-precision round-to-nearest mode"; both open re-implementations do cw = (cw & 0xF0C0) | 0x003F in device creation,
 * on the calling thread only.  This probe measures what the real d3d9.dll does, on real Windows.  32-bit (the x87 control word has no
 * effect on the x86-64 ABI, where Windows leaves it alone).  No window on screen (an off-screen tool window), no display-mode change,
 * no file or registry write.  Device types are tried in order HAL, REF, NULLREF: a machine with no 3D device still answers for the
 * types it has, and the output says which one answered.
 *
 * Output: d3d9fpu-out-<pid>.txt next to the executable, one line per fact:
 *   DX9FPU_CASE <name> devtype=<HAL|REF|NULLREF> hr=<hr> fcw_before=<x> fcw_after=<x> other_thread=<x> mxcsr_before/after=<x>
 *   DX9FPU_PREC <name> fcw=<x> third=<the double bits of 1.0/3.0 computed by fdiv> precision=<24|53-or-64|other>
 * The control word is set to the case's start value right before each call; the other thread waits on an event meanwhile. */
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include <string.h>

static FILE *fo; static HWND wnd;
/* x86 (32-bit) only.  mingw: i686-w64-mingw32-clang -O1 -mwindows -march=pentium4 d3d9-fpu.c -ld3d9 -luser32;
   MSVC (x86 Developer prompt): cl /O1 d3d9-fpu.c d3d9.lib user32.lib /link /subsystem:windows */
#ifdef _MSC_VER
/* braced __asm blocks: with the one-line form MSVC swallows the closing brace of the function as assembly text (C1075) */
static unsigned short get_fcw(void) { unsigned short c; __asm { fnstcw c } return c; }
static void set_fcw(unsigned short c) { __asm { fnclex
                                                fldcw c } }
static unsigned get_mxcsr(void) { unsigned m; __asm { stmxcsr m } return m; }
static unsigned long long third_bits(void) {
  double one = 1.0, three = 3.0, r; unsigned long long b;
  __asm { fld qword ptr one
          fdiv qword ptr three
          fstp qword ptr r }
  memcpy(&b, &r, 8); return b;
}
#else
static unsigned short get_fcw(void) { unsigned short c; __asm__ __volatile__("fnstcw %0" : "=m"(c)); return c; }
static void set_fcw(unsigned short c) { __asm__ __volatile__("fnclex; fldcw %0" : : "m"(c)); }
static unsigned get_mxcsr(void) { unsigned m; __asm__ __volatile__("stmxcsr %0" : "=m"(m)); return m; }
/* 1.0 / 3.0 by the x87 at the current precision, stored as a double */
static unsigned long long third_bits(void) {
  double one = 1.0, three = 3.0, r; unsigned long long b;
  __asm__ __volatile__("fldl %1; fdivl %2; fstpl %0" : "=m"(r) : "m"(one), "m"(three));
  memcpy(&b, &r, 8); return b;
}
#endif
static const char *prec_of(unsigned long long b) {
  return b == 0x3fd5555560000000ull ? "24" : b == 0x3fd5555555555555ull ? "53-or-64" : "other";
}
/* the other thread: reports its own FCW when signalled */
static HANDLE ev_go, ev_done; static volatile unsigned short other_fcw; static volatile LONG other_quit;
static DWORD WINAPI other(void *p) {
  (void)p; set_fcw(0x027f);
  for (;;) { WaitForSingleObject(ev_go, INFINITE); if (other_quit) return 0; other_fcw = get_fcw(); SetEvent(ev_done); }
}
static unsigned short ask_other(void) { SetEvent(ev_go); WaitForSingleObject(ev_done, 5000); return other_fcw; }

static void fill_pp(D3DPRESENT_PARAMETERS *pp) {
  memset(pp, 0, sizeof(*pp));
  pp->BackBufferWidth = 64; pp->BackBufferHeight = 64; pp->BackBufferFormat = D3DFMT_X8R8G8B8; pp->BackBufferCount = 1;
  pp->SwapEffect = D3DSWAPEFFECT_DISCARD; pp->Windowed = TRUE; pp->hDeviceWindow = wnd; pp->PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
}
static void report(const char *name, const char *dt, HRESULT hr, unsigned short before, unsigned short after, unsigned m0, unsigned m1) {
  unsigned short o = ask_other();
  fprintf(fo, "DX9FPU_CASE %s devtype=%s hr=%08lx fcw_before=%04x fcw_after=%04x other_thread=%04x mxcsr_before=%08x mxcsr_after=%08x\n",
          name, dt, (unsigned long)hr, before, after, o, m0, m1);
  fflush(fo);
}
static void prec(const char *name) {
  unsigned long long b = third_bits();
  fprintf(fo, "DX9FPU_PREC %s fcw=%04x third=%016llx precision=%s\n", name, get_fcw(), b, prec_of(b)); fflush(fo);
}
/* one CreateDevice with flags from start FCW s; tries HAL, then REF; returns the device (caller releases) */
static IDirect3DDevice9 *create(IDirect3D9 *d3d, const char *name, DWORD flags, unsigned short s) {
  static const struct { D3DDEVTYPE type; const char *name; } kinds[] = {{D3DDEVTYPE_HAL, "HAL"}, {D3DDEVTYPE_REF, "REF"}, {D3DDEVTYPE_NULLREF, "NULLREF"}};
  D3DPRESENT_PARAMETERS pp; IDirect3DDevice9 *dev = NULL; HRESULT hr = E_FAIL; unsigned short a = 0; unsigned m0 = 0, m1 = 0; const char *dt = "none";
  for (int k = 0; k < 3; k++) {
    DWORD f = k ? (flags & ~D3DCREATE_HARDWARE_VERTEXPROCESSING) | D3DCREATE_SOFTWARE_VERTEXPROCESSING : flags;
    fill_pp(&pp); set_fcw(s); m0 = get_mxcsr(); dt = kinds[k].name;
    hr = IDirect3D9_CreateDevice(d3d, 0, kinds[k].type, wnd, f, &pp, &dev);
    a = get_fcw(); m1 = get_mxcsr();
    if (SUCCEEDED(hr)) break;
  }
  report(name, dt, hr, s, a, m0, m1);
  if (SUCCEEDED(hr)) prec(name);
  return SUCCEEDED(hr) ? dev : NULL;
}
static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcW(h, m, w, l); }

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
  char path[MAX_PATH], *slash; WNDCLASSW cls; IDirect3D9 *d3d; IDirect3D9Ex *ex = NULL; IDirect3DDevice9 *dev;
  D3DPRESENT_PARAMETERS pp; HRESULT hr; unsigned short a; unsigned m0, m1; HANDLE th;
  (void)hp; (void)cmd; (void)show;
  GetModuleFileNameA(NULL, path, sizeof(path)); slash = strrchr(path, '\\');
  if (slash) sprintf(slash + 1, "d3d9fpu-out-%lu.txt", (unsigned long)GetCurrentProcessId());
  if (!(fo = fopen(path, "w"))) return 2;
  memset(&cls, 0, sizeof(cls)); cls.lpfnWndProc = wndproc; cls.hInstance = hi; cls.lpszClassName = L"D3d9FpuProbe";
  RegisterClassW(&cls);
  wnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, cls.lpszClassName, L"d3d9fpu", WS_POPUP, -16384, -16384, 64, 64, NULL, NULL, hi, NULL);
  ShowWindow(wnd, SW_SHOWNOACTIVATE);
  ev_go = CreateEventW(NULL, FALSE, FALSE, NULL); ev_done = CreateEventW(NULL, FALSE, FALSE, NULL);
  th = CreateThread(NULL, 0, other, NULL, 0, NULL);
  fprintf(fo, "DX9FPU_START process_fcw=%04x mxcsr=%08x other_thread=%04x\n", get_fcw(), get_mxcsr(), ask_other()); fflush(fo);
  set_fcw(0x027f); prec("baseline_027f"); set_fcw(0x007f); prec("baseline_007f"); set_fcw(0x037f); prec("baseline_037f");
  d3d = Direct3DCreate9(D3D_SDK_VERSION);
  if (!d3d) { fprintf(fo, "DX9FPU_FATAL no d3d9\n"); return 3; }
  /* 1-2: the default control word, without / with FPU_PRESERVE */
  if ((dev = create(d3d, "create_027f", D3DCREATE_HARDWARE_VERTEXPROCESSING, 0x027f))) {
    /* Reset and Present with the control word set back: does D3D9 apply it again? */
    fill_pp(&pp); set_fcw(0x027f); hr = IDirect3DDevice9_Reset(dev, &pp); a = get_fcw();
    report("reset_027f", "-", hr, 0x027f, a, 0, 0);
    set_fcw(0x027f); IDirect3DDevice9_Clear(dev, 0, NULL, D3DCLEAR_TARGET, 0xff000000, 1.0f, 0);
    hr = IDirect3DDevice9_Present(dev, NULL, NULL, NULL, NULL); a = get_fcw();
    report("present_027f", "-", hr, 0x027f, a, 0, 0);
    IDirect3DDevice9_Release(dev);
  }
  if ((dev = create(d3d, "create_027f_preserve", D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_FPU_PRESERVE, 0x027f))) IDirect3DDevice9_Release(dev);
  /* 3: a start word with 64-bit precision, round toward zero (which bits D3D9 replaces) */
  if ((dev = create(d3d, "create_0f7f", D3DCREATE_HARDWARE_VERTEXPROCESSING, 0x0f7f))) IDirect3DDevice9_Release(dev);
  /* 4: a start word with bit 6 clear and round up */
  if ((dev = create(d3d, "create_083f", D3DCREATE_HARDWARE_VERTEXPROCESSING, 0x083f))) IDirect3DDevice9_Release(dev);
  /* 5: MULTITHREADED (other creation path in some layers) */
  if ((dev = create(d3d, "create_027f_mt", D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_MULTITHREADED, 0x027f))) IDirect3DDevice9_Release(dev);
  IDirect3D9_Release(d3d);
  /* 6-7: CreateDeviceEx (Direct3D9Ex; HAL only - Ex has no reference device) */
  if (SUCCEEDED(Direct3DCreate9Ex(D3D_SDK_VERSION, &ex)) && ex) {
    IDirect3DDevice9Ex *dx = NULL;
    for (int k = 0; k < 2; k++) {
      DWORD fl = D3DCREATE_HARDWARE_VERTEXPROCESSING | (k ? D3DCREATE_FPU_PRESERVE : 0);
      fill_pp(&pp); set_fcw(0x027f); m0 = get_mxcsr();
      hr = IDirect3D9Ex_CreateDeviceEx(ex, 0, D3DDEVTYPE_HAL, wnd, fl, &pp, NULL, &dx);
      a = get_fcw(); m1 = get_mxcsr();
      report(k ? "createex_027f_preserve" : "createex_027f", "HAL", hr, 0x027f, a, m0, m1);
      if (SUCCEEDED(hr)) {
        if (!k) { fill_pp(&pp); set_fcw(0x027f); hr = IDirect3DDevice9Ex_ResetEx(dx, &pp, NULL); a = get_fcw(); report("resetex_027f", "-", hr, 0x027f, a, 0, 0); }
        IDirect3DDevice9Ex_Release(dx); dx = NULL;
      }
    }
    IDirect3D9Ex_Release(ex);
  } else fprintf(fo, "DX9FPU_CASE createex devtype=- hr=noex\n");
  other_quit = 1; SetEvent(ev_go); WaitForSingleObject(th, 2000);
  fprintf(fo, "DX9FPU_END\n"); fclose(fo);
  DestroyWindow(wnd);
  return 0;
}
