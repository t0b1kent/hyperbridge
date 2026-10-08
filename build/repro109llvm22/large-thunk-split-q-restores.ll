; RUN: llc -mtriple=arm64ec-pc-windows-msvc -arm64ec-generate-thunks=false -verify-machineinstrs < %s -o %t.default
; RUN: FileCheck %s --check-prefixes=CHECK,PAIRED < %t.default
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -arm64ec-generate-thunks=false -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=false < %s -o %t.off
; RUN: diff %t.default %t.off
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -arm64ec-generate-thunks=false -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true < %s | FileCheck %s --check-prefixes=CHECK,SPLIT
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -arm64ec-generate-thunks=false -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true -filetype=obj < %s | llvm-readobj --unwind - | FileCheck %s --check-prefix=UNWIND
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs < %s -o %t.native
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true < %s -o %t.native-on
; RUN: diff %t.native %t.native-on

; Dot0082 IR body unchanged. LEVEL4 requires an ARM64EC triple in addition
; to cc108. Disable automatic thunk generation to isolate this explicit thunk.

; Exercise the ARM64EC thunk calling convention directly. Preserving the full
; GPR set and frame record makes the CSR area exactly 256 bytes: an LDP Q can
; absorb that SP adjustment, but a single LDR Q cannot (its maximum is 255).
; The unchanged prologue stays paired and the split epilogue must emit add sp.
define cc 108 void @large_thunk() nounwind uwtable "frame-pointer"="all" {
; CHECK-LABEL: {{.*}}large_thunk{{.*}}:
; CHECK:       stp q6, q7, [sp, #-256]!
; CHECK-NEXT:  .seh_save_any_reg_px q6, 256
; CHECK:       stp x29, x30, [sp, #240]
; CHECK-NEXT:  .seh_save_fplr 240
; CHECK:       .seh_startepilogue
; CHECK-NEXT:  ldp x29, x30, [sp, #240]
; CHECK-NEXT:  .seh_save_fplr 240
; PAIRED:      ldp q6, q7, [sp], #256
; PAIRED-NEXT: .seh_save_any_reg_px q6, 256
; SPLIT:       ldr q7, [sp, #16]
; SPLIT-NEXT:  .seh_save_any_reg q7, 16
; SPLIT-NEXT:  ldr q6, [sp]
; SPLIT-NEXT:  .seh_save_any_reg q6, 0
; SPLIT-NEXT:  add sp, sp, #256
; SPLIT-NEXT:  .seh_stackalloc 256
; CHECK-NEXT:  .seh_endepilogue
; CHECK-NEXT:  br x0
  call void asm sideeffect "", "~{q6},~{q7},~{q8},~{q9},~{q10},~{q11},~{q12},~{q13},~{q14},~{q15},~{x19},~{x20},~{x21},~{x22},~{x23},~{x24},~{x25},~{x26},~{x27},~{x28}"()
  ret void
}

; UNWIND:      Function: {{.*}}large_thunk
; UNWIND:      {{Epilogue|EpilogueScopes}} [
; UNWIND:      0xe70781 {{.*}}ldr q7, [sp, #16]
; UNWIND-NEXT: 0xe70680 {{.*}}ldr q6, [sp{{(, #0)?}}]
; UNWIND-NEXT: {{.*}}add sp, #256
