; RUN: llc -mtriple=arm64ec-pc-windows-msvc -verify-machineinstrs < %s -o %t.default
; RUN: FileCheck %s --check-prefixes=CHECK,PAIRED,THUNKS < %t.default
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=false < %s -o %t.disabled
; RUN: diff %t.default %t.disabled
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true < %s | FileCheck %s --check-prefixes=CHECK,SPLIT,THUNKS
; RUN: llc -mtriple=arm64ec-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true -filetype=obj < %s | llvm-readobj --unwind - | FileCheck %s --check-prefix=UNWIND

; Input from Dot0082, adapted to LEVEL4's default-off boolean and exact scope.
; IR bodies unchanged. Nonzero pairs restore lower slot first; offset zero
; restores upper first so the final lower load may carry the SP writeback.

; On the same Arm64EC target, entry-thunk-only mode must leave a normal
; vector-PCS function unchanged. Internal linkage avoids creating another
; entry thunk. Four clobbers also exercise non-writeback restores without SEH
; instructions preventing late load/store pairing.
define internal aarch64_vector_pcs void @ordinary_preserve_all() nounwind {
; CHECK-LABEL: ordinary_preserve_all:
; CHECK-NOT:   .seh_
; CHECK:       stp q8, q9, [sp, #-64]!
; CHECK-NEXT:  stp q10, q11, [sp, #32]
; CHECK-NOT:   .seh_
; THUNKS:      ldp q10, q11, [sp, #32]
; THUNKS-NEXT: ldp q8, q9, [sp], #64
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{q8},~{q9},~{q10},~{q11}"()
  ret void
}

; Entry thunks preserve the full Q6-Q15 values, while their spills must remain
; paired. Only the offset-zero pair restores its high slot first for writeback.
define void @no_op() nounwind {
; CHECK-LABEL: .def $ientry_thunk$cdecl$v$v;
; CHECK:       stp q6, q7, [sp, #-176]!
; CHECK-NEXT:  .seh_save_any_reg_px q6, 176
; CHECK-NEXT:  stp q8, q9, [sp, #32]
; CHECK-NEXT:  .seh_save_any_reg_p q8, 32
; CHECK-NEXT:  stp q10, q11, [sp, #64]
; CHECK-NEXT:  .seh_save_any_reg_p q10, 64
; CHECK-NEXT:  stp q12, q13, [sp, #96]
; CHECK-NEXT:  .seh_save_any_reg_p q12, 96
; CHECK-NEXT:  stp q14, q15, [sp, #128]
; CHECK-NEXT:  .seh_save_any_reg_p q14, 128
; CHECK-NEXT:  stp x29, x30, [sp, #160]
; CHECK-NEXT:  .seh_save_fplr 160
; CHECK:       .seh_startepilogue
; CHECK-NEXT:  ldp x29, x30, [sp, #160]
; CHECK-NEXT:  .seh_save_fplr 160
; PAIRED-NEXT: ldp q14, q15, [sp, #128]
; PAIRED-NEXT: .seh_save_any_reg_p q14, 128
; PAIRED-NEXT: ldp q12, q13, [sp, #96]
; PAIRED-NEXT: .seh_save_any_reg_p q12, 96
; PAIRED-NEXT: ldp q10, q11, [sp, #64]
; PAIRED-NEXT: .seh_save_any_reg_p q10, 64
; PAIRED-NEXT: ldp q8, q9, [sp, #32]
; PAIRED-NEXT: .seh_save_any_reg_p q8, 32
; PAIRED-NEXT: ldp q6, q7, [sp], #176
; PAIRED-NEXT: .seh_save_any_reg_px q6, 176
; SPLIT-NEXT:  ldr q14, [sp, #128]
; SPLIT-NEXT:  .seh_save_any_reg q14, 128
; SPLIT-NEXT:  ldr q15, [sp, #144]
; SPLIT-NEXT:  .seh_save_any_reg q15, 144
; SPLIT-NEXT:  ldr q12, [sp, #96]
; SPLIT-NEXT:  .seh_save_any_reg q12, 96
; SPLIT-NEXT:  ldr q13, [sp, #112]
; SPLIT-NEXT:  .seh_save_any_reg q13, 112
; SPLIT-NEXT:  ldr q10, [sp, #64]
; SPLIT-NEXT:  .seh_save_any_reg q10, 64
; SPLIT-NEXT:  ldr q11, [sp, #80]
; SPLIT-NEXT:  .seh_save_any_reg q11, 80
; SPLIT-NEXT:  ldr q8, [sp, #32]
; SPLIT-NEXT:  .seh_save_any_reg q8, 32
; SPLIT-NEXT:  ldr q9, [sp, #48]
; SPLIT-NEXT:  .seh_save_any_reg q9, 48
; SPLIT-NEXT:  ldr q7, [sp, #16]
; SPLIT-NEXT:  .seh_save_any_reg q7, 16
; SPLIT-NEXT:  ldr q6, [sp], #176
; SPLIT-NEXT:  .seh_save_any_reg_x q6, 176
; CHECK-NEXT:  .seh_endepilogue
; CHECK-NEXT:  br x0
  ret void
}

; The aggregate signature makes the generated entry thunk use a local stack
; slot. Every Q pair has a nonzero offset and stack deallocation is explicit.
define [2 x i8] @small_array([2 x i8] %arg, [2 x float]) nounwind {
; CHECK-LABEL: .def $ientry_thunk$cdecl$m2$m2F8;
; CHECK:       sub sp, sp, #192
; CHECK-NEXT:  .seh_stackalloc 192
; CHECK-NEXT:  stp q6, q7, [sp, #16]
; CHECK-NEXT:  .seh_save_any_reg_p q6, 16
; CHECK:       stp q14, q15, [sp, #144]
; CHECK-NEXT:  .seh_save_any_reg_p q14, 144
; CHECK:       .seh_startepilogue
; CHECK-NEXT:  ldp x29, x30, [sp, #176]
; CHECK-NEXT:  .seh_save_fplr 176
; PAIRED-NEXT: ldp q14, q15, [sp, #144]
; PAIRED-NEXT: .seh_save_any_reg_p q14, 144
; PAIRED:      ldp q6, q7, [sp, #16]
; PAIRED-NEXT: .seh_save_any_reg_p q6, 16
; SPLIT-NEXT:  ldr q14, [sp, #144]
; SPLIT-NEXT:  .seh_save_any_reg q14, 144
; SPLIT-NEXT:  ldr q15, [sp, #160]
; SPLIT-NEXT:  .seh_save_any_reg q15, 160
; SPLIT:       ldr q6, [sp, #16]
; SPLIT-NEXT:  .seh_save_any_reg q6, 16
; SPLIT-NEXT:  ldr q7, [sp, #32]
; SPLIT-NEXT:  .seh_save_any_reg q7, 32
; CHECK-NEXT:  add sp, sp, #192
; CHECK-NEXT:  .seh_stackalloc 192
; CHECK-NEXT:  .seh_endepilogue
; CHECK-NEXT:  br x0
  ret [2 x i8] %arg
}

; Check that the encoded unwind program describes each restore instruction,
; including the different single-Q post-indexed encoding at the bottom.
; UNWIND:      Function: $ientry_thunk$cdecl$v$v
; UNWIND:      Prologue [
; UNWIND:      stp q14, q15, [sp, #128]
; UNWIND:      stp q6, q7, [sp, #-176]!
; UNWIND:      {{Epilogue|EpilogueScopes}} [
; UNWIND:      0xe70e88 {{.*}}ldr q14, [sp, #128]
; UNWIND-NEXT: 0xe70f89 {{.*}}ldr q15, [sp, #144]
; UNWIND:      ldr q7, [sp, #16]
; UNWIND-NEXT: {{.*}}ldr q6, [sp], #176
; UNWIND:      Function: $ientry_thunk$cdecl$m2$m2F8
; UNWIND:      {{Epilogue|EpilogueScopes}} [
; UNWIND:      0xe70e89 {{.*}}ldr q14, [sp, #144]
; UNWIND-NEXT: 0xe70f8a {{.*}}ldr q15, [sp, #160]
; UNWIND:      0xe70681 {{.*}}ldr q6, [sp, #16]
; UNWIND-NEXT: 0xe70782 {{.*}}ldr q7, [sp, #32]
; UNWIND:      add sp, #192
