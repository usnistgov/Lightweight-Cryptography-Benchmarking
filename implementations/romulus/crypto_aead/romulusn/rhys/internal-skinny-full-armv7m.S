#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal-skinny-plus-config.h"
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL
	.syntax unified
	.thumb
	.text

	.align	2
	.global	skinny_plus_init_without_tk1
	.thumb
	.thumb_func
	.type	skinny_plus_init_without_tk1, %function
skinny_plus_init_without_tk1:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r3, [r1, #0]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #4]
	ldr	r6, [r1, #12]
	ldr	r7, [r2, #0]
	ldr	r8, [r2, #8]
	ldr	r9, [r2, #4]
	ldr	r2, [r2, #12]
	eor	r10, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	lr, r5, r5, lsr #3
	eor	fp, r6, r6, lsr #3
	and	r10, r10, #168430090
	and	ip, ip, #168430090
	and	lr, lr, #168430090
	and	fp, fp, #168430090
	eor	r3, r10
	eor	r4, ip
	eor	r5, lr
	eor	r6, fp
	eor	r3, r3, r10, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, lr, lsl #3
	eor	r6, r6, fp, lsl #3
	eor	r10, r3, r5, lsr #2
	and	r10, r10, #808464432
	eor	r3, r10
	eor	r5, r5, r10, lsl #2
	eor	r10, r3, r4, lsr #4
	and	r10, r10, #202116108
	eor	r3, r10
	eor	r4, r4, r10, lsl #4
	eor	r10, r3, r6, lsr #6
	and	r10, r10, #50529027
	eor	r3, r10
	eor	r6, r6, r10, lsl #6
	eor	r10, r5, r4, lsr #2
	and	r10, r10, #202116108
	eor	r5, r10
	eor	r4, r4, r10, lsl #2
	eor	r10, r5, r6, lsr #4
	and	r10, r10, #50529027
	eor	r5, r10
	eor	r6, r6, r10, lsl #4
	eor	r10, r4, r6, lsr #2
	and	r10, r10, #50529027
	eor	r4, r10
	eor	r6, r6, r10, lsl #2
	eor	r10, r7, r7, lsr #3
	eor	ip, r8, r8, lsr #3
	eor	lr, r9, r9, lsr #3
	eor	fp, r2, r2, lsr #3
	and	r10, r10, #168430090
	and	ip, ip, #168430090
	and	lr, lr, #168430090
	and	fp, fp, #168430090
	eor	r7, r10
	eor	r8, ip
	eor	r9, lr
	eor	r2, fp
	eor	r7, r7, r10, lsl #3
	eor	r8, r8, ip, lsl #3
	eor	r9, r9, lr, lsl #3
	eor	r2, r2, fp, lsl #3
	eor	r10, r7, r9, lsr #2
	and	r10, r10, #808464432
	eor	r7, r10
	eor	r9, r9, r10, lsl #2
	eor	r10, r7, r8, lsr #4
	and	r10, r10, #202116108
	eor	r7, r10
	eor	r8, r8, r10, lsl #4
	eor	r10, r7, r2, lsr #6
	and	r10, r10, #50529027
	eor	r7, r10
	eor	r2, r2, r10, lsl #6
	eor	r10, r9, r8, lsr #2
	and	r10, r10, #202116108
	eor	r9, r10
	eor	r8, r8, r10, lsl #2
	eor	r10, r9, r2, lsr #4
	and	r10, r10, #50529027
	eor	r9, r10
	eor	r2, r2, r10, lsl #4
	eor	r10, r8, r2, lsr #2
	and	r10, r10, #50529027
	eor	r8, r10
	eor	r2, r2, r10, lsl #2
	movs	r1, #5
	mov	fp, #0
	eor	r10, r3, r7
	eor	ip, r4, r8
	str	r10, [r0, #16]
	str	ip, [r0, #20]
	eor	r10, r5, r9
	eor	ip, r6, r2
	str	r10, [r0, #24]
	str	ip, [r0, #28]
	b	.L2
.L1:
	str	fp, [r0, #16]
	str	fp, [r0, #20]
	str	fp, [r0, #24]
	str	fp, [r0, #28]
.L2:
	and	r10, r5, #0xAAAAAAAA
	eor	r3, r10
	and	r10, r3, #0xAAAAAAAA
	lsl	r3, r3, #1
	and	r3, r3, #0xAAAAAAAA
	orr	r3, r3, r10, lsr #1
	and	r10, r8, #0xAAAAAAAA
	eor	r2, r2, r10, lsr #1
	and	r10, r2, #0xAAAAAAAA
	lsl	r2, r2, #1
	and	r2, r2, #0xAAAAAAAA
	orr	r2, r2, r10, lsr #1
	eor	r10, r4, r2
	eor	ip, r5, r7
	str	r10, [r0, #32]
	str	ip, [r0, #36]
	eor	r10, r6, r8
	eor	ip, r3, r9
	str	r10, [r0, #40]
	str	ip, [r0, #44]
	str	fp, [r0, #48]
	str	fp, [r0, #52]
	str	fp, [r0, #56]
	str	fp, [r0, #60]
	and	r10, r6, #0xAAAAAAAA
	eor	r4, r10
	and	r10, r4, #0xAAAAAAAA
	lsl	r4, r4, #1
	and	r4, r4, #0xAAAAAAAA
	orr	r4, r4, r10, lsr #1
	and	r10, r7, #0xAAAAAAAA
	eor	r9, r9, r10, lsr #1
	and	r10, r9, #0xAAAAAAAA
	lsl	r9, r9, #1
	and	r9, r9, #0xAAAAAAAA
	orr	r9, r9, r10, lsr #1
	eor	r10, r5, r9
	eor	ip, r6, r2
	str	r10, [r0, #64]
	str	ip, [r0, #68]
	eor	r10, r3, r7
	eor	ip, r4, r8
	str	r10, [r0, #72]
	str	ip, [r0, #76]
	str	fp, [r0, #80]
	str	fp, [r0, #84]
	str	fp, [r0, #88]
	str	fp, [r0, #92]
	and	r10, r3, #0xAAAAAAAA
	eor	r5, r10
	and	r10, r5, #0xAAAAAAAA
	lsl	r5, r5, #1
	and	r5, r5, #0xAAAAAAAA
	orr	r5, r5, r10, lsr #1
	and	r10, r2, #0xAAAAAAAA
	eor	r8, r8, r10, lsr #1
	and	r10, r8, #0xAAAAAAAA
	lsl	r8, r8, #1
	and	r8, r8, #0xAAAAAAAA
	orr	r8, r8, r10, lsr #1
	eor	r10, r6, r8
	eor	ip, r3, r9
	str	r10, [r0, #96]
	str	ip, [r0, #100]
	eor	r10, r4, r2
	eor	ip, r5, r7
	str	r10, [r0, #104]
	str	ip, [r0, #108]
	str	fp, [r0, #112]
	str	fp, [r0, #116]
	str	fp, [r0, #120]
	str	fp, [r0, #124]
	and	r10, r4, #0xAAAAAAAA
	eor	r6, r10
	and	r10, r6, #0xAAAAAAAA
	lsl	r6, r6, #1
	and	r6, r6, #0xAAAAAAAA
	orr	r6, r6, r10, lsr #1
	and	r10, r9, #0xAAAAAAAA
	eor	r7, r7, r10, lsr #1
	and	r10, r7, #0xAAAAAAAA
	lsl	r7, r7, #1
	and	r7, r7, #0xAAAAAAAA
	orr	r7, r7, r10, lsr #1
	eor	r10, r3, r7
	eor	ip, r4, r8
	str	r10, [r0, #128]
	str	ip, [r0, #132]
	eor	r10, r5, r9
	eor	ip, r6, r2
	str	r10, [r0, #136]
	str	ip, [r0, #140]
	add	r0, r0, #128
	subs	r1, r1, #1
	bne	.L1
	movw	fp, #640
	sub	r0, fp
	ldr	r3, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	movs	r1, #5
.L3:
	and	r10, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	lr, r3, #0xF0F0F0F0
	and	fp, r4, #0xF0F0F0F0
	str	r10, [r0, #16]
	str	ip, [r0, #20]
	str	lr, [r0, #24]
	str	fp, [r0, #28]
	ldr	r3, [r0, #32]
	ldr	r4, [r0, #36]
	ldr	r5, [r0, #40]
	ldr	r6, [r0, #44]
	movw	r7, #52224
	movt	r7, #51
	ror	r10, r3, #14
	and	ip, r3, #0xCC000000
	and	r10, r10, #0xCC00CC00
	and	lr, r3, r7
	bfi	r10, r3, #16, #8
	and	r3, r3, #0x00CC0000
	orr	r3, r10, r3, lsr #18
	orr	r3, r3, ip, lsr #2
	orr	r3, r3, lr, lsr #8
	ror	r10, r4, #14
	and	ip, r4, #0xCC000000
	and	r10, r10, #0xCC00CC00
	and	lr, r4, r7
	bfi	r10, r4, #16, #8
	and	r4, r4, #0x00CC0000
	orr	r4, r10, r4, lsr #18
	orr	r4, r4, ip, lsr #2
	orr	r4, r4, lr, lsr #8
	ror	r10, r5, #14
	and	ip, r5, #0xCC000000
	and	r10, r10, #0xCC00CC00
	and	lr, r5, r7
	bfi	r10, r5, #16, #8
	and	r5, r5, #0x00CC0000
	orr	r5, r10, r5, lsr #18
	orr	r5, r5, ip, lsr #2
	orr	r5, r5, lr, lsr #8
	ror	r10, r6, #14
	and	ip, r6, #0xCC000000
	and	r10, r10, #0xCC00CC00
	and	lr, r6, r7
	bfi	r10, r6, #16, #8
	and	r6, r6, #0x00CC0000
	orr	r6, r10, r6, lsr #18
	orr	r6, r6, ip, lsr #2
	orr	r6, r6, lr, lsr #8
	ror	r10, r3, #26
	ror	ip, r4, #26
	ror	lr, r5, #26
	ror	fp, r6, #26
	and	r10, r10, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	lr, lr, #0xC3C3C3C3
	and	fp, fp, #0xC3C3C3C3
	str	r10, [r0, #32]
	str	ip, [r0, #36]
	str	lr, [r0, #40]
	str	fp, [r0, #44]
	ror	r10, r5, #28
	ror	ip, r5, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #48]
	ror	r10, r6, #28
	ror	ip, r6, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #52]
	ror	r10, r3, #28
	ror	ip, r3, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #56]
	ror	r10, r4, #28
	ror	ip, r4, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #60]
	ldr	r3, [r0, #64]
	ldr	r4, [r0, #68]
	ldr	r5, [r0, #72]
	ldr	r6, [r0, #76]
	movw	r7, #204
	movt	r7, #52224
	movw	r8, #52224
	movt	r8, #13056
	movw	r9, #13056
	movt	r9, #204
	ror	r10, r3, #22
	ror	ip, r3, #16
	ror	lr, r3, #24
	and	r10, r10, r7
	and	ip, ip, r8
	and	r3, r3, #0x00CC00CC
	and	lr, lr, r9
	orr	r3, r10, r3, lsr #2
	orr	r3, r3, ip
	orr	r3, r3, lr
	ror	r10, r4, #22
	ror	ip, r4, #16
	ror	lr, r4, #24
	and	r10, r10, r7
	and	ip, ip, r8
	and	r4, r4, #0x00CC00CC
	and	lr, lr, r9
	orr	r4, r10, r4, lsr #2
	orr	r4, r4, ip
	orr	r4, r4, lr
	ror	r10, r5, #22
	ror	ip, r5, #16
	ror	lr, r5, #24
	and	r10, r10, r7
	and	ip, ip, r8
	and	r5, r5, #0x00CC00CC
	and	lr, lr, r9
	orr	r5, r10, r5, lsr #2
	orr	r5, r5, ip
	orr	r5, r5, lr
	ror	r10, r6, #22
	ror	ip, r6, #16
	ror	lr, r6, #24
	and	r10, r10, r7
	and	ip, ip, r8
	and	r6, r6, #0x00CC00CC
	and	lr, lr, r9
	orr	r6, r10, r6, lsr #2
	orr	r6, r6, ip
	orr	r6, r6, lr
	ror	r10, r3, #14
	ror	ip, r3, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #64]
	ror	r10, r4, #14
	ror	ip, r4, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #68]
	ror	r10, r5, #14
	ror	ip, r5, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #72]
	ror	r10, r6, #14
	ror	ip, r6, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #76]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r0, #80]
	str	r6, [r0, #84]
	str	r3, [r0, #88]
	str	r4, [r0, #92]
	ldr	r3, [r0, #96]
	ldr	r4, [r0, #100]
	ldr	r5, [r0, #104]
	ldr	r6, [r0, #108]
	movw	r7, #0
	movt	r7, #52428
	movw	r8, #204
	movt	r8, #13056
	movw	r9, #13107
	ror	r10, r3, #6
	ror	ip, r3, #24
	ror	lr, r3, #10
	and	fp, r3, #0x000000CC
	and	r10, r10, r7
	and	ip, ip, r8
	and	r3, r3, #0x00003300
	and	lr, lr, r9
	orr	r3, r10, r3, lsl #2
	orr	r3, r3, ip
	orr	r3, r3, lr
	orr	r3, r3, fp, lsl #14
	ror	r10, r4, #6
	ror	ip, r4, #24
	ror	lr, r4, #10
	and	fp, r4, #0x000000CC
	and	r10, r10, r7
	and	ip, ip, r8
	and	r4, r4, #0x00003300
	and	lr, lr, r9
	orr	r4, r10, r4, lsl #2
	orr	r4, r4, ip
	orr	r4, r4, lr
	orr	r4, r4, fp, lsl #14
	ror	r10, r5, #6
	ror	ip, r5, #24
	ror	lr, r5, #10
	and	fp, r5, #0x000000CC
	and	r10, r10, r7
	and	ip, ip, r8
	and	r5, r5, #0x00003300
	and	lr, lr, r9
	orr	r5, r10, r5, lsl #2
	orr	r5, r5, ip
	orr	r5, r5, lr
	orr	r5, r5, fp, lsl #14
	ror	r10, r6, #6
	ror	ip, r6, #24
	ror	lr, r6, #10
	and	fp, r6, #0x000000CC
	and	r10, r10, r7
	and	ip, ip, r8
	and	r6, r6, #0x00003300
	and	lr, lr, r9
	orr	r6, r10, r6, lsl #2
	orr	r6, r6, ip
	orr	r6, r6, lr
	orr	r6, r6, fp, lsl #14
	ror	r10, r3, #10
	ror	ip, r4, #10
	ror	lr, r5, #10
	ror	fp, r6, #10
	and	r10, r10, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	lr, lr, #0xC3C3C3C3
	and	fp, fp, #0xC3C3C3C3
	str	r10, [r0, #96]
	str	ip, [r0, #100]
	str	lr, [r0, #104]
	str	fp, [r0, #108]
	ror	r10, r5, #12
	ror	ip, r5, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #112]
	ror	r10, r6, #12
	ror	ip, r6, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #116]
	ror	r10, r3, #12
	ror	ip, r3, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #120]
	ror	r10, r4, #12
	ror	ip, r4, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #124]
	ldr	r3, [r0, #128]
	ldr	r4, [r0, #132]
	ldr	r5, [r0, #136]
	ldr	r6, [r0, #140]
	movw	r7, #51
	movt	r7, #52224
	movw	r8, #0
	movt	r8, #13260
	movw	r9, #13056
	movt	r9, #51
	ror	r10, r3, #24
	ror	ip, r3, #8
	ror	lr, r3, #26
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r3, r3, r9
	orr	r3, r10, r3, lsr #6
	orr	r3, r3, ip
	orr	r3, r3, lr
	ror	r10, r4, #24
	ror	ip, r4, #8
	ror	lr, r4, #26
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r4, r4, r9
	orr	r4, r10, r4, lsr #6
	orr	r4, r4, ip
	orr	r4, r4, lr
	ror	r10, r5, #24
	ror	ip, r5, #8
	ror	lr, r5, #26
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r5, r5, r9
	orr	r5, r10, r5, lsr #6
	orr	r5, r5, ip
	orr	r5, r5, lr
	ror	r10, r6, #24
	ror	ip, r6, #8
	ror	lr, r6, #26
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r6, r6, r9
	orr	r6, r10, r6, lsr #6
	orr	r6, r6, ip
	orr	r6, r6, lr
	ror	r10, r3, #30
	ror	ip, r3, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #128]
	ror	r10, r4, #30
	ror	ip, r4, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #132]
	ror	r10, r5, #30
	ror	ip, r5, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #136]
	ror	r10, r6, #30
	ror	ip, r6, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #140]
	subs	r1, r1, #1
	beq	.L4
	and	r10, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	lr, r3, #0xF0F0F0F0
	and	fp, r4, #0xF0F0F0F0
	str	r10, [r0, #144]
	str	ip, [r0, #148]
	str	lr, [r0, #152]
	str	fp, [r0, #156]
	ldr	r3, [r0, #160]
	ldr	r4, [r0, #164]
	ldr	r5, [r0, #168]
	ldr	r6, [r0, #172]
	movw	r7, #0
	movt	r7, #52275
	movw	r8, #51
	movt	r8, #13056
	movw	r9, #52224
	movt	r9, #204
	ror	r10, r3, #8
	ror	ip, r3, #26
	ror	lr, r3, #22
	and	fp, r3, #0x00330000
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r3, r3, #0x0000CC00
	orr	r10, r10, ip
	orr	r10, r10, lr
	orr	r10, r10, fp, lsr #14
	orr	r3, r10, r3, lsr #2
	ror	r10, r4, #8
	ror	ip, r4, #26
	ror	lr, r4, #22
	and	fp, r4, #0x00330000
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r4, r4, #0x0000CC00
	orr	r10, r10, ip
	orr	r10, r10, lr
	orr	r10, r10, fp, lsr #14
	orr	r4, r10, r4, lsr #2
	ror	r10, r5, #8
	ror	ip, r5, #26
	ror	lr, r5, #22
	and	fp, r5, #0x00330000
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r5, r5, #0x0000CC00
	orr	r10, r10, ip
	orr	r10, r10, lr
	orr	r10, r10, fp, lsr #14
	orr	r5, r10, r5, lsr #2
	ror	r10, r6, #8
	ror	ip, r6, #26
	ror	lr, r6, #22
	and	fp, r6, #0x00330000
	and	r10, r10, r7
	and	ip, ip, r8
	and	lr, lr, r9
	and	r6, r6, #0x0000CC00
	orr	r10, r10, ip
	orr	r10, r10, lr
	orr	r10, r10, fp, lsr #14
	orr	r6, r10, r6, lsr #2
	ror	r10, r3, #26
	ror	ip, r4, #26
	ror	lr, r5, #26
	ror	fp, r6, #26
	and	r10, r10, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	lr, lr, #0xC3C3C3C3
	and	fp, fp, #0xC3C3C3C3
	str	r10, [r0, #160]
	str	ip, [r0, #164]
	str	lr, [r0, #168]
	str	fp, [r0, #172]
	ror	r10, r5, #28
	ror	ip, r5, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #176]
	ror	r10, r6, #28
	ror	ip, r6, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #180]
	ror	r10, r3, #28
	ror	ip, r3, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #184]
	ror	r10, r4, #28
	ror	ip, r4, #12
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #188]
	ldr	r3, [r0, #192]
	ldr	r4, [r0, #196]
	ldr	r5, [r0, #200]
	ldr	r6, [r0, #204]
	movw	r7, #52275
	movw	r8, #0
	movt	r8, #13107
	movw	r9, #52224
	movt	r9, #13056
	ror	r10, r3, #8
	ror	ip, r3, #30
	ror	lr, r3, #10
	and	r3, r3, r9
	and	r10, r10, r7
	and	ip, ip, #0x00CC00CC
	and	lr, lr, r8
	orr	r3, r10, r3, ror #16
	orr	r3, r3, ip
	orr	r3, r3, lr
	ror	r10, r4, #8
	ror	ip, r4, #30
	ror	lr, r4, #10
	and	r4, r4, r9
	and	r10, r10, r7
	and	ip, ip, #0x00CC00CC
	and	lr, lr, r8
	orr	r4, r10, r4, ror #16
	orr	r4, r4, ip
	orr	r4, r4, lr
	ror	r10, r5, #8
	ror	ip, r5, #30
	ror	lr, r5, #10
	and	r5, r5, r9
	and	r10, r10, r7
	and	ip, ip, #0x00CC00CC
	and	lr, lr, r8
	orr	r5, r10, r5, ror #16
	orr	r5, r5, ip
	orr	r5, r5, lr
	ror	r10, r6, #8
	ror	ip, r6, #30
	ror	lr, r6, #10
	and	r6, r6, r9
	and	r10, r10, r7
	and	ip, ip, #0x00CC00CC
	and	lr, lr, r8
	orr	r6, r10, r6, ror #16
	orr	r6, r6, ip
	orr	r6, r6, lr
	ror	r10, r3, #14
	ror	ip, r3, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #192]
	ror	r10, r4, #14
	ror	ip, r4, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #196]
	ror	r10, r5, #14
	ror	ip, r5, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #200]
	ror	r10, r6, #14
	ror	ip, r6, #6
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #204]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r0, #208]
	str	r6, [r0, #212]
	str	r3, [r0, #216]
	str	r4, [r0, #220]
	ldr	r3, [r0, #224]
	ldr	r4, [r0, #228]
	ldr	r5, [r0, #232]
	ldr	r6, [r0, #236]
	movw	r7, #52224
	movt	r7, #51
	ror	r10, r3, #24
	ror	ip, r3, #14
	ror	lr, r3, #30
	ror	fp, r3, #16
	ror	r3, r3, #18
	and	r10, r10, r7
	and	ip, ip, #0x00CC0000
	and	lr, lr, #0xCC000000
	and	r3, r3, #0x33003300
	bfi	r3, fp, #0, #8
	orr	r3, r3, r10
	orr	r3, r3, ip
	orr	r3, r3, lr
	ror	r10, r4, #24
	ror	ip, r4, #14
	ror	lr, r4, #30
	ror	fp, r4, #16
	ror	r4, r4, #18
	and	r10, r10, r7
	and	ip, ip, #0x00CC0000
	and	lr, lr, #0xCC000000
	and	r4, r4, #0x33003300
	bfi	r4, fp, #0, #8
	orr	r4, r4, r10
	orr	r4, r4, ip
	orr	r4, r4, lr
	ror	r10, r5, #24
	ror	ip, r5, #14
	ror	lr, r5, #30
	ror	fp, r5, #16
	ror	r5, r5, #18
	and	r10, r10, r7
	and	ip, ip, #0x00CC0000
	and	lr, lr, #0xCC000000
	and	r5, r5, #0x33003300
	bfi	r5, fp, #0, #8
	orr	r5, r5, r10
	orr	r5, r5, ip
	orr	r5, r5, lr
	ror	r10, r6, #24
	ror	ip, r6, #14
	ror	lr, r6, #30
	ror	fp, r6, #16
	ror	r6, r6, #18
	and	r10, r10, r7
	and	ip, ip, #0x00CC0000
	and	lr, lr, #0xCC000000
	and	r6, r6, #0x33003300
	bfi	r6, fp, #0, #8
	orr	r6, r6, r10
	orr	r6, r6, ip
	orr	r6, r6, lr
	ror	r10, r3, #10
	ror	ip, r4, #10
	ror	lr, r5, #10
	ror	fp, r6, #10
	and	r10, r10, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	lr, lr, #0xC3C3C3C3
	and	fp, fp, #0xC3C3C3C3
	str	r10, [r0, #224]
	str	ip, [r0, #228]
	str	lr, [r0, #232]
	str	fp, [r0, #236]
	ror	r10, r5, #12
	ror	ip, r5, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #240]
	ror	r10, r6, #12
	ror	ip, r6, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #244]
	ror	r10, r3, #12
	ror	ip, r3, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #248]
	ror	r10, r4, #12
	ror	ip, r4, #28
	and	r10, r10, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #252]
	ldr	r3, [r0, #256]
	ldr	r4, [r0, #260]
	ldr	r5, [r0, #264]
	ldr	r6, [r0, #268]
	ror	r10, r3, #30
	ror	ip, r3, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #256]
	ror	r10, r4, #30
	ror	ip, r4, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #260]
	ror	r10, r5, #30
	ror	ip, r5, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #264]
	ror	r10, r6, #30
	ror	ip, r6, #22
	and	r10, r10, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	r10, ip
	str	r10, [r0, #268]
	add	r0, r0, #256
	subs	r1, r1, #1
	bne	.L3
.L4:
	add	r0, r0, #144
	movs	r1, #160
	adr	lr, rconst
	movw	fp, #640
	add	lr, fp
.L5:
	ldr	r10, [lr, #-4]!
	ldr	ip, [r0, #-4]!
	eor	r10, ip
	str	r10, [r0, #0]
	subs	r1, r1, #1
	bne	.L5
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_init_without_tk1, .-skinny_plus_init_without_tk1

	.align	4
	.type	rconst, %object
rconst:
	.word	0x00000004
	.word	0xffffffbf
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x10000100
	.word	0xfffffeff
	.word	0x44000000
	.word	0xfbffffff
	.word	0x00000000
	.word	0x04000000
	.word	0x00100000
	.word	0x00100000
	.word	0x00100001
	.word	0xffefffff
	.word	0x00440000
	.word	0xffafffff
	.word	0x00400000
	.word	0x00400000
	.word	0x01000000
	.word	0x01000000
	.word	0x01401000
	.word	0xffbfffff
	.word	0x01004000
	.word	0xfefffbff
	.word	0x00000400
	.word	0x00000400
	.word	0x00000010
	.word	0x00000000
	.word	0x00010410
	.word	0xfffffbef
	.word	0x00000054
	.word	0xffffffaf
	.word	0x00000000
	.word	0x00000040
	.word	0x00000100
	.word	0x00000100
	.word	0x10000140
	.word	0xfffffeff
	.word	0x44000000
	.word	0xfffffeff
	.word	0x04000000
	.word	0x04000000
	.word	0x00100000
	.word	0x00100000
	.word	0x04000001
	.word	0xfbffffff
	.word	0x00140000
	.word	0xffafffff
	.word	0x00400000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x01401000
	.word	0xfebfffff
	.word	0x01004400
	.word	0xfffffbff
	.word	0x00000000
	.word	0x00000400
	.word	0x00000010
	.word	0x00000010
	.word	0x00010010
	.word	0xffffffff
	.word	0x00000004
	.word	0xffffffaf
	.word	0x00000040
	.word	0x00000040
	.word	0x00000100
	.word	0x00000000
	.word	0x10000140
	.word	0xffffffbf
	.word	0x40000100
	.word	0xfbfffeff
	.word	0x00000000
	.word	0x04000000
	.word	0x00100000
	.word	0x00000000
	.word	0x04100001
	.word	0xffefffff
	.word	0x00440000
	.word	0xffefffff
	.word	0x00000000
	.word	0x00400000
	.word	0x01000000
	.word	0x01000000
	.word	0x00401000
	.word	0xffffffff
	.word	0x00004000
	.word	0xfeffffff
	.word	0x00000400
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00010400
	.word	0xfffffbff
	.word	0x00000014
	.word	0xffffffbf
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x10000100
	.word	0xffffffff
	.word	0x40000000
	.word	0xfbffffff
	.word	0x00000000
	.word	0x04000000
	.word	0x00100000
	.word	0x00000000
	.word	0x00100001
	.word	0xffefffff
	.word	0x00440000
	.word	0xffafffff
	.word	0x00000000
	.word	0x00400000
	.word	0x01000000
	.word	0x01000000
	.word	0x01401000
	.word	0xffffffff
	.word	0x00004000
	.word	0xfeffffff
	.word	0x00000400
	.word	0x00000400
	.word	0x00000010
	.word	0x00000000
	.word	0x00010400
	.word	0xfffffbff
	.word	0x00000014
	.word	0xffffffaf
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x10000140
	.word	0xfffffeff
	.word	0x44000000
	.word	0xffffffff
	.word	0x00000000
	.word	0x04000000
	.word	0x00100000
	.word	0x00100000
	.word	0x00000001
	.word	0xffefffff
	.word	0x00440000
	.word	0xffafffff
	.word	0x00400000
	.word	0x00000000
	.word	0x00000000
	.word	0x01000000
	.word	0x01401000
	.word	0xffbfffff
	.word	0x01004000
	.word	0xfffffbff
	.word	0x00000400
	.word	0x00000400
	.word	0x00000010
	.word	0x00000000
	.word	0x00010010
	.word	0xfffffbff
	.size	rconst, .-rconst

	.align	2
	.global	skinny_plus_encrypt
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt, %function
skinny_plus_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #272
	push	{r1}
	push	{r2}
	ldr	r3, [r0, #0]
	ldr	r5, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r6, [r0, #12]
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	str	r3, [fp, #-16]
	str	r4, [fp, #-12]
	str	r5, [fp, #-8]
	str	r6, [fp, #-4]
	sub	r1, fp, #272
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	and	lr, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	r2, r3, #0xF0F0F0F0
	and	r10, r4, #0xF0F0F0F0
	str	lr, [r1, #0]
	str	ip, [r1, #4]
	str	r2, [r1, #8]
	str	r10, [r1, #12]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52224
	movt	r7, #51
	ror	lr, r3, #14
	and	ip, r3, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r3, r7
	bfi	lr, r3, #16, #8
	and	r3, r3, #0x00CC0000
	orr	r3, lr, r3, lsr #18
	orr	r3, r3, ip, lsr #2
	orr	r3, r3, r2, lsr #8
	ror	lr, r4, #14
	and	ip, r4, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r4, r7
	bfi	lr, r4, #16, #8
	and	r4, r4, #0x00CC0000
	orr	r4, lr, r4, lsr #18
	orr	r4, r4, ip, lsr #2
	orr	r4, r4, r2, lsr #8
	ror	lr, r5, #14
	and	ip, r5, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r5, r7
	bfi	lr, r5, #16, #8
	and	r5, r5, #0x00CC0000
	orr	r5, lr, r5, lsr #18
	orr	r5, r5, ip, lsr #2
	orr	r5, r5, r2, lsr #8
	ror	lr, r6, #14
	and	ip, r6, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r6, r7
	bfi	lr, r6, #16, #8
	and	r6, r6, #0x00CC0000
	orr	r6, lr, r6, lsr #18
	orr	r6, r6, ip, lsr #2
	orr	r6, r6, r2, lsr #8
	ror	lr, r3, #26
	ror	ip, r4, #26
	ror	r2, r5, #26
	ror	r10, r6, #26
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #16]
	str	ip, [r1, #20]
	str	r2, [r1, #24]
	str	r10, [r1, #28]
	ror	lr, r5, #28
	ror	ip, r5, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #32]
	ror	lr, r6, #28
	ror	ip, r6, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #36]
	ror	lr, r3, #28
	ror	ip, r3, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #40]
	ror	lr, r4, #28
	ror	ip, r4, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #44]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #204
	movt	r7, #52224
	movw	r8, #52224
	movt	r8, #13056
	movw	r9, #13056
	movt	r9, #204
	ror	lr, r3, #22
	ror	ip, r3, #16
	ror	r2, r3, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r3, r3, #0x00CC00CC
	and	r2, r2, r9
	orr	r3, lr, r3, lsr #2
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #22
	ror	ip, r4, #16
	ror	r2, r4, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r4, r4, #0x00CC00CC
	and	r2, r2, r9
	orr	r4, lr, r4, lsr #2
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #22
	ror	ip, r5, #16
	ror	r2, r5, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r5, r5, #0x00CC00CC
	and	r2, r2, r9
	orr	r5, lr, r5, lsr #2
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #22
	ror	ip, r6, #16
	ror	r2, r6, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r6, r6, #0x00CC00CC
	and	r2, r2, r9
	orr	r6, lr, r6, lsr #2
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #14
	ror	ip, r3, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #48]
	ror	lr, r4, #14
	ror	ip, r4, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #52]
	ror	lr, r5, #14
	ror	ip, r5, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #56]
	ror	lr, r6, #14
	ror	ip, r6, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #60]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r1, #64]
	str	r6, [r1, #68]
	str	r3, [r1, #72]
	str	r4, [r1, #76]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #0
	movt	r7, #52428
	movw	r8, #204
	movt	r8, #13056
	movw	r9, #13107
	ror	lr, r3, #6
	ror	ip, r3, #24
	ror	r2, r3, #10
	and	r10, r3, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r3, r3, #0x00003300
	and	r2, r2, r9
	orr	r3, lr, r3, lsl #2
	orr	r3, r3, ip
	orr	r3, r3, r2
	orr	r3, r3, r10, lsl #14
	ror	lr, r4, #6
	ror	ip, r4, #24
	ror	r2, r4, #10
	and	r10, r4, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r4, r4, #0x00003300
	and	r2, r2, r9
	orr	r4, lr, r4, lsl #2
	orr	r4, r4, ip
	orr	r4, r4, r2
	orr	r4, r4, r10, lsl #14
	ror	lr, r5, #6
	ror	ip, r5, #24
	ror	r2, r5, #10
	and	r10, r5, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r5, r5, #0x00003300
	and	r2, r2, r9
	orr	r5, lr, r5, lsl #2
	orr	r5, r5, ip
	orr	r5, r5, r2
	orr	r5, r5, r10, lsl #14
	ror	lr, r6, #6
	ror	ip, r6, #24
	ror	r2, r6, #10
	and	r10, r6, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r6, r6, #0x00003300
	and	r2, r2, r9
	orr	r6, lr, r6, lsl #2
	orr	r6, r6, ip
	orr	r6, r6, r2
	orr	r6, r6, r10, lsl #14
	ror	lr, r3, #10
	ror	ip, r4, #10
	ror	r2, r5, #10
	ror	r10, r6, #10
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #80]
	str	ip, [r1, #84]
	str	r2, [r1, #88]
	str	r10, [r1, #92]
	ror	lr, r5, #12
	ror	ip, r5, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #96]
	ror	lr, r6, #12
	ror	ip, r6, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #100]
	ror	lr, r3, #12
	ror	ip, r3, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #104]
	ror	lr, r4, #12
	ror	ip, r4, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #108]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #51
	movt	r7, #52224
	movw	r8, #0
	movt	r8, #13260
	movw	r9, #13056
	movt	r9, #51
	ror	lr, r3, #24
	ror	ip, r3, #8
	ror	r2, r3, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r3, r3, r9
	orr	r3, lr, r3, lsr #6
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #24
	ror	ip, r4, #8
	ror	r2, r4, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r4, r4, r9
	orr	r4, lr, r4, lsr #6
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #24
	ror	ip, r5, #8
	ror	r2, r5, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r5, r5, r9
	orr	r5, lr, r5, lsr #6
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #24
	ror	ip, r6, #8
	ror	r2, r6, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r6, r6, r9
	orr	r6, lr, r6, lsr #6
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #30
	ror	ip, r3, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #112]
	ror	lr, r4, #30
	ror	ip, r4, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #116]
	ror	lr, r5, #30
	ror	ip, r5, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #120]
	ror	lr, r6, #30
	ror	ip, r6, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #124]
	and	lr, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	r2, r3, #0xF0F0F0F0
	and	r10, r4, #0xF0F0F0F0
	str	lr, [r1, #128]
	str	ip, [r1, #132]
	str	r2, [r1, #136]
	str	r10, [r1, #140]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #0
	movt	r7, #52275
	movw	r8, #51
	movt	r8, #13056
	movw	r9, #52224
	movt	r9, #204
	ror	lr, r3, #8
	ror	ip, r3, #26
	ror	r2, r3, #22
	and	r10, r3, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r3, r3, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r3, lr, r3, lsr #2
	ror	lr, r4, #8
	ror	ip, r4, #26
	ror	r2, r4, #22
	and	r10, r4, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r4, r4, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r4, lr, r4, lsr #2
	ror	lr, r5, #8
	ror	ip, r5, #26
	ror	r2, r5, #22
	and	r10, r5, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r5, r5, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r5, lr, r5, lsr #2
	ror	lr, r6, #8
	ror	ip, r6, #26
	ror	r2, r6, #22
	and	r10, r6, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r6, r6, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r6, lr, r6, lsr #2
	ror	lr, r3, #26
	ror	ip, r4, #26
	ror	r2, r5, #26
	ror	r10, r6, #26
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #144]
	str	ip, [r1, #148]
	str	r2, [r1, #152]
	str	r10, [r1, #156]
	ror	lr, r5, #28
	ror	ip, r5, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #160]
	ror	lr, r6, #28
	ror	ip, r6, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #164]
	ror	lr, r3, #28
	ror	ip, r3, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #168]
	ror	lr, r4, #28
	ror	ip, r4, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #172]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52275
	movw	r8, #0
	movt	r8, #13107
	movw	r9, #52224
	movt	r9, #13056
	ror	lr, r3, #8
	ror	ip, r3, #30
	ror	r2, r3, #10
	and	r3, r3, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r3, lr, r3, ror #16
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #8
	ror	ip, r4, #30
	ror	r2, r4, #10
	and	r4, r4, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r4, lr, r4, ror #16
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #8
	ror	ip, r5, #30
	ror	r2, r5, #10
	and	r5, r5, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r5, lr, r5, ror #16
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #8
	ror	ip, r6, #30
	ror	r2, r6, #10
	and	r6, r6, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r6, lr, r6, ror #16
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #14
	ror	ip, r3, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #176]
	ror	lr, r4, #14
	ror	ip, r4, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #180]
	ror	lr, r5, #14
	ror	ip, r5, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #184]
	ror	lr, r6, #14
	ror	ip, r6, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #188]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r1, #192]
	str	r6, [r1, #196]
	str	r3, [r1, #200]
	str	r4, [r1, #204]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52224
	movt	r7, #51
	ror	lr, r3, #24
	ror	ip, r3, #14
	ror	r2, r3, #30
	ror	r10, r3, #16
	ror	r3, r3, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r3, r3, #0x33003300
	bfi	r3, r10, #0, #8
	orr	r3, r3, lr
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #24
	ror	ip, r4, #14
	ror	r2, r4, #30
	ror	r10, r4, #16
	ror	r4, r4, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r4, r4, #0x33003300
	bfi	r4, r10, #0, #8
	orr	r4, r4, lr
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #24
	ror	ip, r5, #14
	ror	r2, r5, #30
	ror	r10, r5, #16
	ror	r5, r5, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r5, r5, #0x33003300
	bfi	r5, r10, #0, #8
	orr	r5, r5, lr
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #24
	ror	ip, r6, #14
	ror	r2, r6, #30
	ror	r10, r6, #16
	ror	r6, r6, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r6, r6, #0x33003300
	bfi	r6, r10, #0, #8
	orr	r6, r6, lr
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #10
	ror	ip, r4, #10
	ror	r2, r5, #10
	ror	r10, r6, #10
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #208]
	str	ip, [r1, #212]
	str	r2, [r1, #216]
	str	r10, [r1, #220]
	ror	lr, r5, #12
	ror	ip, r5, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #224]
	ror	lr, r6, #12
	ror	ip, r6, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #228]
	ror	lr, r3, #12
	ror	ip, r3, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #232]
	ror	lr, r4, #12
	ror	ip, r4, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #236]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	ror	lr, r3, #30
	ror	ip, r3, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #240]
	ror	lr, r4, #30
	ror	ip, r4, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #244]
	ror	lr, r5, #30
	ror	ip, r5, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #248]
	ror	lr, r6, #30
	ror	ip, r6, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #252]
	pop	{r2}
	ldr	r3, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r4, [r2, #8]
	ldr	r6, [r2, #12]
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	movs	r1, #0
	sub	r7, fp, #272
	add	r0, r0, #16
.L6:
	and	r8, r1, #0xFF
	add	r8, r7, r8
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	eor	r4, lr
	eor	lr, r3, r6, lsr #0
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r6, r6, lr, lsl #0
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r3, lr
	eor	r3, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r6, lr
	eor	r6, ip
	ror	lr, r3, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #30
	ror	lr, r3, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #4
	ror	lr, r3, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #2
	ror	lr, r4, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #30
	ror	lr, r4, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #4
	ror	lr, r4, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #2
	ror	lr, r5, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #30
	ror	lr, r5, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #4
	ror	lr, r5, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #2
	ror	lr, r6, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #30
	ror	lr, r6, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #4
	ror	lr, r6, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #2
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	eor	r6, lr
	eor	lr, r5, r4, lsr #0
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r4, r4, lr, lsl #0
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r3, lr
	eor	r3, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r6, lr
	eor	r6, ip
	ror	lr, r3, #16
	and	lr, lr, #0x30303030
	eor	r3, r3, lr, ror #30
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #28
	ror	lr, r3, #16
	and	lr, lr, #0x30303030
	eor	r3, r3, lr, ror #2
	ror	lr, r4, #16
	and	lr, lr, #0x30303030
	eor	r4, r4, lr, ror #30
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #28
	ror	lr, r4, #16
	and	lr, lr, #0x30303030
	eor	r4, r4, lr, ror #2
	ror	lr, r5, #16
	and	lr, lr, #0x30303030
	eor	r5, r5, lr, ror #30
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #28
	ror	lr, r5, #16
	and	lr, lr, #0x30303030
	eor	r5, r5, lr, ror #2
	ror	lr, r6, #16
	and	lr, lr, #0x30303030
	eor	r6, r6, lr, ror #30
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #28
	ror	lr, r6, #16
	and	lr, lr, #0x30303030
	eor	r6, r6, lr, ror #2
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	eor	r4, lr
	eor	lr, r3, r6, lsr #0
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r6, r6, lr, lsl #0
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r3, lr
	eor	r3, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r6, lr
	eor	r6, ip
	ror	lr, r3, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #6
	ror	lr, r3, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #28
	ror	lr, r3, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #2
	ror	lr, r4, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #6
	ror	lr, r4, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #28
	ror	lr, r4, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #2
	ror	lr, r5, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #6
	ror	lr, r5, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #28
	ror	lr, r5, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #2
	ror	lr, r6, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #6
	ror	lr, r6, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #28
	ror	lr, r6, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #2
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	orr	lr, r3, r4
	eor	r6, lr
	eor	lr, r5, r4, lsr #0
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r4, r4, lr, lsl #0
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r3, lr
	eor	r3, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0], #4
	ldr	ip, [r8], #4
	eor	r6, lr
	eor	r6, ip
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #30
	and	lr, r3, #0x30303030
	eor	r3, r3, lr, ror #4
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #26
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #30
	and	lr, r4, #0x30303030
	eor	r4, r4, lr, ror #4
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #26
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #30
	and	lr, r5, #0x30303030
	eor	r5, r5, lr, ror #4
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #26
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #30
	and	lr, r6, #0x30303030
	eor	r6, r6, lr, ror #4
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #26
	add	r1, r1, #64
	cmp	r1, #640
	bne	.L6
	pop	{r1}
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	str	r3, [r1, #0]
	str	r5, [r1, #4]
	str	r4, [r1, #8]
	str	r6, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_encrypt, .-skinny_plus_encrypt

	.align	2
	.global	skinny_plus_decrypt
	.thumb
	.thumb_func
	.type	skinny_plus_decrypt, %function
skinny_plus_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #272
	push	{r1}
	push	{r2}
	ldr	r3, [r0, #0]
	ldr	r5, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r6, [r0, #12]
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	str	r3, [fp, #-16]
	str	r4, [fp, #-12]
	str	r5, [fp, #-8]
	str	r6, [fp, #-4]
	sub	r1, fp, #272
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	and	lr, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	r2, r3, #0xF0F0F0F0
	and	r10, r4, #0xF0F0F0F0
	str	lr, [r1, #0]
	str	ip, [r1, #4]
	str	r2, [r1, #8]
	str	r10, [r1, #12]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52224
	movt	r7, #51
	ror	lr, r3, #14
	and	ip, r3, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r3, r7
	bfi	lr, r3, #16, #8
	and	r3, r3, #0x00CC0000
	orr	r3, lr, r3, lsr #18
	orr	r3, r3, ip, lsr #2
	orr	r3, r3, r2, lsr #8
	ror	lr, r4, #14
	and	ip, r4, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r4, r7
	bfi	lr, r4, #16, #8
	and	r4, r4, #0x00CC0000
	orr	r4, lr, r4, lsr #18
	orr	r4, r4, ip, lsr #2
	orr	r4, r4, r2, lsr #8
	ror	lr, r5, #14
	and	ip, r5, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r5, r7
	bfi	lr, r5, #16, #8
	and	r5, r5, #0x00CC0000
	orr	r5, lr, r5, lsr #18
	orr	r5, r5, ip, lsr #2
	orr	r5, r5, r2, lsr #8
	ror	lr, r6, #14
	and	ip, r6, #0xCC000000
	and	lr, lr, #0xCC00CC00
	and	r2, r6, r7
	bfi	lr, r6, #16, #8
	and	r6, r6, #0x00CC0000
	orr	r6, lr, r6, lsr #18
	orr	r6, r6, ip, lsr #2
	orr	r6, r6, r2, lsr #8
	ror	lr, r3, #26
	ror	ip, r4, #26
	ror	r2, r5, #26
	ror	r10, r6, #26
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #16]
	str	ip, [r1, #20]
	str	r2, [r1, #24]
	str	r10, [r1, #28]
	ror	lr, r5, #28
	ror	ip, r5, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #32]
	ror	lr, r6, #28
	ror	ip, r6, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #36]
	ror	lr, r3, #28
	ror	ip, r3, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #40]
	ror	lr, r4, #28
	ror	ip, r4, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #44]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #204
	movt	r7, #52224
	movw	r8, #52224
	movt	r8, #13056
	movw	r9, #13056
	movt	r9, #204
	ror	lr, r3, #22
	ror	ip, r3, #16
	ror	r2, r3, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r3, r3, #0x00CC00CC
	and	r2, r2, r9
	orr	r3, lr, r3, lsr #2
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #22
	ror	ip, r4, #16
	ror	r2, r4, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r4, r4, #0x00CC00CC
	and	r2, r2, r9
	orr	r4, lr, r4, lsr #2
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #22
	ror	ip, r5, #16
	ror	r2, r5, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r5, r5, #0x00CC00CC
	and	r2, r2, r9
	orr	r5, lr, r5, lsr #2
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #22
	ror	ip, r6, #16
	ror	r2, r6, #24
	and	lr, lr, r7
	and	ip, ip, r8
	and	r6, r6, #0x00CC00CC
	and	r2, r2, r9
	orr	r6, lr, r6, lsr #2
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #14
	ror	ip, r3, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #48]
	ror	lr, r4, #14
	ror	ip, r4, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #52]
	ror	lr, r5, #14
	ror	ip, r5, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #56]
	ror	lr, r6, #14
	ror	ip, r6, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #60]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r1, #64]
	str	r6, [r1, #68]
	str	r3, [r1, #72]
	str	r4, [r1, #76]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #0
	movt	r7, #52428
	movw	r8, #204
	movt	r8, #13056
	movw	r9, #13107
	ror	lr, r3, #6
	ror	ip, r3, #24
	ror	r2, r3, #10
	and	r10, r3, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r3, r3, #0x00003300
	and	r2, r2, r9
	orr	r3, lr, r3, lsl #2
	orr	r3, r3, ip
	orr	r3, r3, r2
	orr	r3, r3, r10, lsl #14
	ror	lr, r4, #6
	ror	ip, r4, #24
	ror	r2, r4, #10
	and	r10, r4, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r4, r4, #0x00003300
	and	r2, r2, r9
	orr	r4, lr, r4, lsl #2
	orr	r4, r4, ip
	orr	r4, r4, r2
	orr	r4, r4, r10, lsl #14
	ror	lr, r5, #6
	ror	ip, r5, #24
	ror	r2, r5, #10
	and	r10, r5, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r5, r5, #0x00003300
	and	r2, r2, r9
	orr	r5, lr, r5, lsl #2
	orr	r5, r5, ip
	orr	r5, r5, r2
	orr	r5, r5, r10, lsl #14
	ror	lr, r6, #6
	ror	ip, r6, #24
	ror	r2, r6, #10
	and	r10, r6, #0x000000CC
	and	lr, lr, r7
	and	ip, ip, r8
	and	r6, r6, #0x00003300
	and	r2, r2, r9
	orr	r6, lr, r6, lsl #2
	orr	r6, r6, ip
	orr	r6, r6, r2
	orr	r6, r6, r10, lsl #14
	ror	lr, r3, #10
	ror	ip, r4, #10
	ror	r2, r5, #10
	ror	r10, r6, #10
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #80]
	str	ip, [r1, #84]
	str	r2, [r1, #88]
	str	r10, [r1, #92]
	ror	lr, r5, #12
	ror	ip, r5, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #96]
	ror	lr, r6, #12
	ror	ip, r6, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #100]
	ror	lr, r3, #12
	ror	ip, r3, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #104]
	ror	lr, r4, #12
	ror	ip, r4, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #108]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #51
	movt	r7, #52224
	movw	r8, #0
	movt	r8, #13260
	movw	r9, #13056
	movt	r9, #51
	ror	lr, r3, #24
	ror	ip, r3, #8
	ror	r2, r3, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r3, r3, r9
	orr	r3, lr, r3, lsr #6
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #24
	ror	ip, r4, #8
	ror	r2, r4, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r4, r4, r9
	orr	r4, lr, r4, lsr #6
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #24
	ror	ip, r5, #8
	ror	r2, r5, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r5, r5, r9
	orr	r5, lr, r5, lsr #6
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #24
	ror	ip, r6, #8
	ror	r2, r6, #26
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r6, r6, r9
	orr	r6, lr, r6, lsr #6
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #30
	ror	ip, r3, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #112]
	ror	lr, r4, #30
	ror	ip, r4, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #116]
	ror	lr, r5, #30
	ror	ip, r5, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #120]
	ror	lr, r6, #30
	ror	ip, r6, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #124]
	and	lr, r5, #0xF0F0F0F0
	and	ip, r6, #0xF0F0F0F0
	and	r2, r3, #0xF0F0F0F0
	and	r10, r4, #0xF0F0F0F0
	str	lr, [r1, #128]
	str	ip, [r1, #132]
	str	r2, [r1, #136]
	str	r10, [r1, #140]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #0
	movt	r7, #52275
	movw	r8, #51
	movt	r8, #13056
	movw	r9, #52224
	movt	r9, #204
	ror	lr, r3, #8
	ror	ip, r3, #26
	ror	r2, r3, #22
	and	r10, r3, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r3, r3, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r3, lr, r3, lsr #2
	ror	lr, r4, #8
	ror	ip, r4, #26
	ror	r2, r4, #22
	and	r10, r4, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r4, r4, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r4, lr, r4, lsr #2
	ror	lr, r5, #8
	ror	ip, r5, #26
	ror	r2, r5, #22
	and	r10, r5, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r5, r5, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r5, lr, r5, lsr #2
	ror	lr, r6, #8
	ror	ip, r6, #26
	ror	r2, r6, #22
	and	r10, r6, #0x00330000
	and	lr, lr, r7
	and	ip, ip, r8
	and	r2, r2, r9
	and	r6, r6, #0x0000CC00
	orr	lr, lr, ip
	orr	lr, lr, r2
	orr	lr, lr, r10, lsr #14
	orr	r6, lr, r6, lsr #2
	ror	lr, r3, #26
	ror	ip, r4, #26
	ror	r2, r5, #26
	ror	r10, r6, #26
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #144]
	str	ip, [r1, #148]
	str	r2, [r1, #152]
	str	r10, [r1, #156]
	ror	lr, r5, #28
	ror	ip, r5, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #160]
	ror	lr, r6, #28
	ror	ip, r6, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #164]
	ror	lr, r3, #28
	ror	ip, r3, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #168]
	ror	lr, r4, #28
	ror	ip, r4, #12
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #172]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52275
	movw	r8, #0
	movt	r8, #13107
	movw	r9, #52224
	movt	r9, #13056
	ror	lr, r3, #8
	ror	ip, r3, #30
	ror	r2, r3, #10
	and	r3, r3, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r3, lr, r3, ror #16
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #8
	ror	ip, r4, #30
	ror	r2, r4, #10
	and	r4, r4, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r4, lr, r4, ror #16
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #8
	ror	ip, r5, #30
	ror	r2, r5, #10
	and	r5, r5, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r5, lr, r5, ror #16
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #8
	ror	ip, r6, #30
	ror	r2, r6, #10
	and	r6, r6, r9
	and	lr, lr, r7
	and	ip, ip, #0x00CC00CC
	and	r2, r2, r8
	orr	r6, lr, r6, ror #16
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #14
	ror	ip, r3, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #176]
	ror	lr, r4, #14
	ror	ip, r4, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #180]
	ror	lr, r5, #14
	ror	ip, r5, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #184]
	ror	lr, r6, #14
	ror	ip, r6, #6
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #188]
	ror	r5, r5, #16
	ror	r6, r6, #16
	ror	r3, r3, #16
	ror	r4, r4, #16
	and	r5, r5, #0xF0F0F0F0
	and	r6, r6, #0xF0F0F0F0
	and	r3, r3, #0xF0F0F0F0
	and	r4, r4, #0xF0F0F0F0
	str	r5, [r1, #192]
	str	r6, [r1, #196]
	str	r3, [r1, #200]
	str	r4, [r1, #204]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	movw	r7, #52224
	movt	r7, #51
	ror	lr, r3, #24
	ror	ip, r3, #14
	ror	r2, r3, #30
	ror	r10, r3, #16
	ror	r3, r3, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r3, r3, #0x33003300
	bfi	r3, r10, #0, #8
	orr	r3, r3, lr
	orr	r3, r3, ip
	orr	r3, r3, r2
	ror	lr, r4, #24
	ror	ip, r4, #14
	ror	r2, r4, #30
	ror	r10, r4, #16
	ror	r4, r4, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r4, r4, #0x33003300
	bfi	r4, r10, #0, #8
	orr	r4, r4, lr
	orr	r4, r4, ip
	orr	r4, r4, r2
	ror	lr, r5, #24
	ror	ip, r5, #14
	ror	r2, r5, #30
	ror	r10, r5, #16
	ror	r5, r5, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r5, r5, #0x33003300
	bfi	r5, r10, #0, #8
	orr	r5, r5, lr
	orr	r5, r5, ip
	orr	r5, r5, r2
	ror	lr, r6, #24
	ror	ip, r6, #14
	ror	r2, r6, #30
	ror	r10, r6, #16
	ror	r6, r6, #18
	and	lr, lr, r7
	and	ip, ip, #0x00CC0000
	and	r2, r2, #0xCC000000
	and	r6, r6, #0x33003300
	bfi	r6, r10, #0, #8
	orr	r6, r6, lr
	orr	r6, r6, ip
	orr	r6, r6, r2
	ror	lr, r3, #10
	ror	ip, r4, #10
	ror	r2, r5, #10
	ror	r10, r6, #10
	and	lr, lr, #0xC3C3C3C3
	and	ip, ip, #0xC3C3C3C3
	and	r2, r2, #0xC3C3C3C3
	and	r10, r10, #0xC3C3C3C3
	str	lr, [r1, #208]
	str	ip, [r1, #212]
	str	r2, [r1, #216]
	str	r10, [r1, #220]
	ror	lr, r5, #12
	ror	ip, r5, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #224]
	ror	lr, r6, #12
	ror	ip, r6, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #228]
	ror	lr, r3, #12
	ror	ip, r3, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #232]
	ror	lr, r4, #12
	ror	ip, r4, #28
	and	lr, lr, #0x03030303
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #236]
	ldr	r3, [fp, #-16]
	ldr	r4, [fp, #-12]
	ldr	r5, [fp, #-8]
	ldr	r6, [fp, #-4]
	ror	lr, r3, #30
	ror	ip, r3, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #240]
	ror	lr, r4, #30
	ror	ip, r4, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #244]
	ror	lr, r5, #30
	ror	ip, r5, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #248]
	ror	lr, r6, #30
	ror	ip, r6, #22
	and	lr, lr, #0x30303030
	and	ip, ip, #0x0C0C0C0C
	orr	lr, ip
	str	lr, [r1, #252]
	pop	{r2}
	ldr	r3, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r4, [r2, #8]
	ldr	r6, [r2, #12]
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	movw	r1, #640
	sub	r7, fp, #272
	add	r0, r0, #656
.L7:
	sub	r1, r1, #64
	and	r8, r1, #0xFF
	add	r8, r7, r8
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #26
	and	lr, r3, #0x30303030
	eor	r3, r3, lr, ror #4
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #30
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #26
	and	lr, r4, #0x30303030
	eor	r4, r4, lr, ror #4
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #30
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #26
	and	lr, r5, #0x30303030
	eor	r5, r5, lr, ror #4
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #30
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #26
	and	lr, r6, #0x30303030
	eor	r6, r6, lr, ror #4
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #30
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #60]
	eor	r6, lr
	eor	r6, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #56]
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #52]
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #48]
	eor	r3, lr
	eor	r3, ip
	eor	lr, r5, r4, lsr #0
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r4, r4, lr, lsl #0
	orr	lr, r3, r4
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	ror	lr, r3, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #2
	ror	lr, r3, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #28
	ror	lr, r3, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #6
	ror	lr, r4, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #2
	ror	lr, r4, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #28
	ror	lr, r4, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #6
	ror	lr, r5, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #2
	ror	lr, r5, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #28
	ror	lr, r5, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #6
	ror	lr, r6, #24
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #2
	ror	lr, r6, #16
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #28
	ror	lr, r6, #8
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #6
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #44]
	eor	r6, lr
	eor	r6, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #40]
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #36]
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #32]
	eor	r3, lr
	eor	r3, ip
	eor	lr, r3, r6, lsr #0
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r6, r6, lr, lsl #0
	orr	lr, r5, r6
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	ror	lr, r3, #16
	and	lr, lr, #0x30303030
	eor	r3, r3, lr, ror #2
	and	lr, r3, #0x03030303
	eor	r3, r3, lr, ror #28
	ror	lr, r3, #16
	and	lr, lr, #0x30303030
	eor	r3, r3, lr, ror #30
	ror	lr, r4, #16
	and	lr, lr, #0x30303030
	eor	r4, r4, lr, ror #2
	and	lr, r4, #0x03030303
	eor	r4, r4, lr, ror #28
	ror	lr, r4, #16
	and	lr, lr, #0x30303030
	eor	r4, r4, lr, ror #30
	ror	lr, r5, #16
	and	lr, lr, #0x30303030
	eor	r5, r5, lr, ror #2
	and	lr, r5, #0x03030303
	eor	r5, r5, lr, ror #28
	ror	lr, r5, #16
	and	lr, lr, #0x30303030
	eor	r5, r5, lr, ror #30
	ror	lr, r6, #16
	and	lr, lr, #0x30303030
	eor	r6, r6, lr, ror #2
	and	lr, r6, #0x03030303
	eor	r6, r6, lr, ror #28
	ror	lr, r6, #16
	and	lr, lr, #0x30303030
	eor	r6, r6, lr, ror #30
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #28]
	eor	r6, lr
	eor	r6, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #24]
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #20]
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #16]
	eor	r3, lr
	eor	r3, ip
	eor	lr, r5, r4, lsr #0
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r4, r4, lr, lsl #0
	orr	lr, r3, r4
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	ror	lr, r3, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #2
	ror	lr, r3, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r3, r3, lr, ror #4
	ror	lr, r3, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r3, r3, lr, ror #30
	ror	lr, r4, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #2
	ror	lr, r4, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r4, r4, lr, ror #4
	ror	lr, r4, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r4, r4, lr, ror #30
	ror	lr, r5, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #2
	ror	lr, r5, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r5, r5, lr, ror #4
	ror	lr, r5, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r5, r5, lr, ror #30
	ror	lr, r6, #8
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #2
	ror	lr, r6, #16
	and	lr, lr, #0xC0C0C0C0
	eor	r6, r6, lr, ror #4
	ror	lr, r6, #24
	and	lr, lr, #0x0C0C0C0C
	eor	r6, r6, lr, ror #30
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #12]
	eor	r6, lr
	eor	r6, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #8]
	eor	r5, lr
	eor	r5, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #4]
	eor	r4, lr
	eor	r4, ip
	ldr	lr, [r0, #-4]!
	ldr	ip, [r8, #0]
	eor	r3, lr
	eor	r3, ip
	eor	lr, r3, r6, lsr #0
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r6, r6, lr, lsl #0
	orr	lr, r5, r6
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	eor	lr, r6, r3, lsr #1
	and	lr, lr, #1431655765
	eor	r6, lr
	eor	r3, r3, lr, lsl #1
	eor	lr, r3, r4, lsr #1
	and	lr, lr, #1431655765
	eor	r3, lr
	eor	r4, r4, lr, lsl #1
	orr	lr, r5, r6
	mvn	lr, lr
	eor	r4, lr
	eor	lr, r5, r6, lsr #1
	and	lr, lr, #1431655765
	eor	r5, lr
	eor	r6, r6, lr, lsl #1
	eor	lr, r4, r5, lsr #1
	and	lr, lr, #1431655765
	eor	r4, lr
	eor	r5, r5, lr, lsl #1
	orr	lr, r3, r4
	mvn	lr, lr
	eor	r6, lr
	cmp	r1, #0
	bne	.L7
	pop	{r1}
	eor	lr, r4, r6, lsr #2
	and	lr, lr, #50529027
	eor	r4, lr
	eor	r6, r6, lr, lsl #2
	eor	lr, r5, r6, lsr #4
	and	lr, lr, #50529027
	eor	r5, lr
	eor	r6, r6, lr, lsl #4
	eor	lr, r5, r4, lsr #2
	and	lr, lr, #202116108
	eor	r5, lr
	eor	r4, r4, lr, lsl #2
	eor	lr, r3, r6, lsr #6
	and	lr, lr, #50529027
	eor	r3, lr
	eor	r6, r6, lr, lsl #6
	eor	lr, r3, r4, lsr #4
	and	lr, lr, #202116108
	eor	r3, lr
	eor	r4, r4, lr, lsl #4
	eor	lr, r3, r5, lsr #2
	and	lr, lr, #808464432
	eor	r3, lr
	eor	r5, r5, lr, lsl #2
	eor	lr, r3, r3, lsr #3
	eor	ip, r4, r4, lsr #3
	eor	r2, r5, r5, lsr #3
	eor	r10, r6, r6, lsr #3
	and	lr, lr, #168430090
	and	ip, ip, #168430090
	and	r2, r2, #168430090
	and	r10, r10, #168430090
	eor	r3, lr
	eor	r4, ip
	eors	r5, r2
	eor	r6, r10
	eor	r3, r3, lr, lsl #3
	eor	r4, r4, ip, lsl #3
	eor	r5, r5, r2, lsl #3
	eor	r6, r6, r10, lsl #3
	str	r3, [r1, #0]
	str	r5, [r1, #4]
	str	r4, [r1, #8]
	str	r6, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_decrypt, .-skinny_plus_decrypt

#endif
#endif
