; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs < %s -o %t.default
; RUN: FileCheck %s --check-prefixes=CHECK,PAIRED < %t.default
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=false < %s -o %t.disabled
; RUN: diff %t.default %t.disabled
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true < %s -o %t.thunks
; RUN: diff %t.default %t.thunks
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs -filetype=obj < %s -o %t.default.obj
; RUN: llc -mtriple=aarch64-pc-windows-msvc -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true -filetype=obj < %s -o %t.on.obj
; RUN: diff %t.default.obj %t.on.obj
; RUN: llc -mtriple=aarch64-unknown-linux-gnu -verify-machineinstrs < %s -o %t.elf-default
; RUN: llc -mtriple=aarch64-unknown-linux-gnu -verify-machineinstrs -aarch64-arm64ec-split-thunk-q-restores=true < %s -o %t.elf-thunks
; RUN: diff %t.elf-default %t.elf-thunks

; Dot0082 IR bodies unchanged. Every function here is outside LEVEL4's scope:
; the option must leave ordinary Windows/ELF functions byte-identical.
; No-unwind, GPR/D pairs, single Q and high-offset frames are controls.
define aarch64_vector_pcs void @q_pair_no_unwind() nounwind {
; CHECK-LABEL: q_pair_no_unwind:
; CHECK-NOT:   .seh_
; CHECK:       stp q8, q9, [sp, #-64]!
; CHECK-NEXT:  stp q10, q11, [sp, #32]
; CHECK-NOT:   .seh_
; PAIRED:      ldp q10, q11, [sp, #32]
; PAIRED-NEXT: ldp q8, q9, [sp], #64
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{q8},~{q9},~{q10},~{q11}"()
  ret void
}

; Q offsets follow a GPR pair. Its paired spill and reload must not change.
define aarch64_vector_pcs void @q_and_gpr_pairs() nounwind uwtable {
; CHECK-LABEL: q_and_gpr_pairs:
; CHECK:       stp x19, x20, [sp, #-48]!
; CHECK:       stp q8, q9, [sp, #16]
; CHECK-NEXT:  .seh_save_any_reg_p q8, 16
; CHECK:       .seh_startepilogue
; PAIRED-NEXT: ldp q8, q9, [sp, #16]
; PAIRED-NEXT: .seh_save_any_reg_p q8, 16
; CHECK-NEXT:  ldp x19, x20, [sp], #48
; CHECK:       .seh_endepilogue
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{x19},~{x20},~{q8},~{q9}"()
  ret void
}

; Single Q restores already exist and must remain single, with their original
; stack writeback. This also guards against accidentally doubling single loads.
define aarch64_vector_pcs void @single_q_no_unwind() nounwind {
; CHECK-LABEL: single_q_no_unwind:
; CHECK-NOT:   .seh_
; CHECK:       str q8, [sp, #-16]!
; CHECK-NOT:   .seh_
; CHECK:       ldr q8, [sp], #16
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{q8}"()
  ret void
}

; Full-Q splitting must not alter ordinary ABI D-register or GPR pairs.
define void @d_and_gpr_pairs() nounwind uwtable {
; CHECK-LABEL: d_and_gpr_pairs:
; CHECK:       stp x19, x20, [sp, #-32]!
; CHECK:       stp d8, d9, [sp, #16]
; CHECK-NEXT:  .seh_save_fregp d8, 16
; CHECK:       .seh_startepilogue
; CHECK-NEXT:  ldp d8, d9, [sp, #16]
; CHECK-NEXT:  .seh_save_fregp d8, 16
; CHECK-NEXT:  ldp x19, x20, [sp], #32
; CHECK:       .seh_endepilogue
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{x19},~{x20},~{d8},~{d9}"()
  ret void
}

; A large ordinary vector-PCS frame exercises high offsets and an explicit
; SP adjustment. LLVM also preserves x30 as its register-scavenging scratch.
define aarch64_vector_pcs void @large_q_frame() nounwind uwtable {
; CHECK-LABEL: large_q_frame:
; CHECK:       sub sp, sp, #272
; CHECK-NEXT:  .seh_stackalloc 272
; CHECK:       stp q8, q9, [sp, #16]
; CHECK-NEXT:  .seh_save_any_reg_p q8, 16
; CHECK:       stp q22, q23, [sp, #240]
; CHECK-NEXT:  .seh_save_any_reg_p q22, 240
; CHECK:       .seh_startepilogue
; PAIRED-NEXT: ldp q22, q23, [sp, #240]
; PAIRED-NEXT: .seh_save_any_reg_p q22, 240
; PAIRED:      ldp q8, q9, [sp, #16]
; PAIRED-NEXT: .seh_save_any_reg_p q8, 16
; CHECK-NEXT:  ldr x30, [sp]
; CHECK-NEXT:  .seh_save_reg x30, 0
; CHECK-NEXT:  add sp, sp, #272
; CHECK-NEXT:  .seh_stackalloc 272
; CHECK-NEXT:  .seh_endepilogue
; CHECK-NEXT:  ret
  call void asm sideeffect "", "~{q8},~{q9},~{q10},~{q11},~{q12},~{q13},~{q14},~{q15},~{q16},~{q17},~{q18},~{q19},~{q20},~{q21},~{q22},~{q23}"()
  ret void
}
