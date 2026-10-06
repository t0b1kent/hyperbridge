# SPDX-License-Identifier: MIT
.intel_syntax noprefix
.text
.p2align 4
.globl gather_0
.type gather_0, @function
gather_0:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_0,.-gather_0
.p2align 4
.globl gather_1
.type gather_1, @function
gather_1:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_1,.-gather_1
.p2align 4
.globl gather_2
.type gather_2, @function
gather_2:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_2,.-gather_2
.p2align 4
.globl gather_3
.type gather_3, @function
gather_3:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_3,.-gather_3
.p2align 4
.globl gather_4
.type gather_4, @function
gather_4:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps ymm0, [rsi+ymm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_4,.-gather_4
.p2align 4
.globl gather_5
.type gather_5, @function
gather_5:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps ymm0, [rsi+ymm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_5,.-gather_5
.p2align 4
.globl gather_6
.type gather_6, @function
gather_6:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps ymm0, [rsi+ymm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_6,.-gather_6
.p2align 4
.globl gather_7
.type gather_7, @function
gather_7:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdps ymm0, [rsi+ymm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_7,.-gather_7
.p2align 4
.globl gather_8
.type gather_8, @function
gather_8:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_8,.-gather_8
.p2align 4
.globl gather_9
.type gather_9, @function
gather_9:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_9,.-gather_9
.p2align 4
.globl gather_10
.type gather_10, @function
gather_10:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_10,.-gather_10
.p2align 4
.globl gather_11
.type gather_11, @function
gather_11:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_11,.-gather_11
.p2align 4
.globl gather_12
.type gather_12, @function
gather_12:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+ymm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_12,.-gather_12
.p2align 4
.globl gather_13
.type gather_13, @function
gather_13:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+ymm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_13,.-gather_13
.p2align 4
.globl gather_14
.type gather_14, @function
gather_14:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+ymm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_14,.-gather_14
.p2align 4
.globl gather_15
.type gather_15, @function
gather_15:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqps xmm0, [rsi+ymm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_15,.-gather_15
.p2align 4
.globl gather_16
.type gather_16, @function
gather_16:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_16,.-gather_16
.p2align 4
.globl gather_17
.type gather_17, @function
gather_17:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_17,.-gather_17
.p2align 4
.globl gather_18
.type gather_18, @function
gather_18:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_18,.-gather_18
.p2align 4
.globl gather_19
.type gather_19, @function
gather_19:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_19,.-gather_19
.p2align 4
.globl gather_20
.type gather_20, @function
gather_20:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd ymm0, [rsi+xmm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_20,.-gather_20
.p2align 4
.globl gather_21
.type gather_21, @function
gather_21:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd ymm0, [rsi+xmm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_21,.-gather_21
.p2align 4
.globl gather_22
.type gather_22, @function
gather_22:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd ymm0, [rsi+xmm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_22,.-gather_22
.p2align 4
.globl gather_23
.type gather_23, @function
gather_23:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherdpd ymm0, [rsi+xmm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_23,.-gather_23
.p2align 4
.globl gather_24
.type gather_24, @function
gather_24:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_24,.-gather_24
.p2align 4
.globl gather_25
.type gather_25, @function
gather_25:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_25,.-gather_25
.p2align 4
.globl gather_26
.type gather_26, @function
gather_26:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_26,.-gather_26
.p2align 4
.globl gather_27
.type gather_27, @function
gather_27:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_27,.-gather_27
.p2align 4
.globl gather_28
.type gather_28, @function
gather_28:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd ymm0, [rsi+ymm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_28,.-gather_28
.p2align 4
.globl gather_29
.type gather_29, @function
gather_29:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd ymm0, [rsi+ymm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_29,.-gather_29
.p2align 4
.globl gather_30
.type gather_30, @function
gather_30:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd ymm0, [rsi+ymm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_30,.-gather_30
.p2align 4
.globl gather_31
.type gather_31, @function
gather_31:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vgatherqpd ymm0, [rsi+ymm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_31,.-gather_31
.p2align 4
.globl gather_32
.type gather_32, @function
gather_32:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_32,.-gather_32
.p2align 4
.globl gather_33
.type gather_33, @function
gather_33:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_33,.-gather_33
.p2align 4
.globl gather_34
.type gather_34, @function
gather_34:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_34,.-gather_34
.p2align 4
.globl gather_35
.type gather_35, @function
gather_35:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_35,.-gather_35
.p2align 4
.globl gather_36
.type gather_36, @function
gather_36:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd ymm0, [rsi+ymm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_36,.-gather_36
.p2align 4
.globl gather_37
.type gather_37, @function
gather_37:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd ymm0, [rsi+ymm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_37,.-gather_37
.p2align 4
.globl gather_38
.type gather_38, @function
gather_38:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd ymm0, [rsi+ymm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_38,.-gather_38
.p2align 4
.globl gather_39
.type gather_39, @function
gather_39:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdd ymm0, [rsi+ymm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_39,.-gather_39
.p2align 4
.globl gather_40
.type gather_40, @function
gather_40:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_40,.-gather_40
.p2align 4
.globl gather_41
.type gather_41, @function
gather_41:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_41,.-gather_41
.p2align 4
.globl gather_42
.type gather_42, @function
gather_42:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_42,.-gather_42
.p2align 4
.globl gather_43
.type gather_43, @function
gather_43:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_43,.-gather_43
.p2align 4
.globl gather_44
.type gather_44, @function
gather_44:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+ymm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_44,.-gather_44
.p2align 4
.globl gather_45
.type gather_45, @function
gather_45:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+ymm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_45,.-gather_45
.p2align 4
.globl gather_46
.type gather_46, @function
gather_46:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+ymm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_46,.-gather_46
.p2align 4
.globl gather_47
.type gather_47, @function
gather_47:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqd xmm0, [rsi+ymm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_47,.-gather_47
.p2align 4
.globl gather_48
.type gather_48, @function
gather_48:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_48,.-gather_48
.p2align 4
.globl gather_49
.type gather_49, @function
gather_49:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_49,.-gather_49
.p2align 4
.globl gather_50
.type gather_50, @function
gather_50:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_50,.-gather_50
.p2align 4
.globl gather_51
.type gather_51, @function
gather_51:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_51,.-gather_51
.p2align 4
.globl gather_52
.type gather_52, @function
gather_52:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq ymm0, [rsi+xmm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_52,.-gather_52
.p2align 4
.globl gather_53
.type gather_53, @function
gather_53:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq ymm0, [rsi+xmm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_53,.-gather_53
.p2align 4
.globl gather_54
.type gather_54, @function
gather_54:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq ymm0, [rsi+xmm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_54,.-gather_54
.p2align 4
.globl gather_55
.type gather_55, @function
gather_55:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherdq ymm0, [rsi+xmm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_55,.-gather_55
.p2align 4
.globl gather_56
.type gather_56, @function
gather_56:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq xmm0, [rsi+xmm1*1], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_56,.-gather_56
.p2align 4
.globl gather_57
.type gather_57, @function
gather_57:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq xmm0, [rsi+xmm1*2], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_57,.-gather_57
.p2align 4
.globl gather_58
.type gather_58, @function
gather_58:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq xmm0, [rsi+xmm1*4], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_58,.-gather_58
.p2align 4
.globl gather_59
.type gather_59, @function
gather_59:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq xmm0, [rsi+xmm1*8], xmm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_59,.-gather_59
.p2align 4
.globl gather_60
.type gather_60, @function
gather_60:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq ymm0, [rsi+ymm1*1], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_60,.-gather_60
.p2align 4
.globl gather_61
.type gather_61, @function
gather_61:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq ymm0, [rsi+ymm1*2], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_61,.-gather_61
.p2align 4
.globl gather_62
.type gather_62, @function
gather_62:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq ymm0, [rsi+ymm1*4], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_62,.-gather_62
.p2align 4
.globl gather_63
.type gather_63, @function
gather_63:
mov r11,rdi
mov rsi,[r11+160]
vmovdqu ymm0,[r11]
vmovdqu ymm1,[r11+32]
vmovdqu ymm2,[r11+64]
vpgatherqq ymm0, [rsi+ymm1*8], ymm2
vmovdqu [r11+96],ymm0
vmovdqu [r11+128],ymm2
vzeroupper
ret
.size gather_63,.-gather_63
.section .note.GNU-stack,"",@progbits
