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
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
	.syntax unified
	.thumb
	.text

	.align	2
	.global	skinny_plus_init_without_tk1
	.thumb
	.thumb_func
	.type	skinny_plus_init_without_tk1, %function
skinny_plus_init_without_tk1:
	ldr	r3, [r1, #0]
	ldr	ip, [r2, #0]
	str	r3, [r0, #16]
	str	ip, [r0, #32]
	ldr	r3, [r1, #4]
	ldr	ip, [r2, #4]
	str	r3, [r0, #20]
	str	ip, [r0, #36]
	ldr	r3, [r1, #8]
	ldr	ip, [r2, #8]
	str	r3, [r0, #24]
	str	ip, [r0, #40]
	ldr	r3, [r1, #12]
	ldr	ip, [r2, #12]
	str	r3, [r0, #28]
	str	ip, [r0, #44]
	bx	lr
	.size	skinny_plus_init_without_tk1, .-skinny_plus_init_without_tk1

	.align	2
	.global	skinny_plus_encrypt
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt, %function
skinny_plus_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #48
	ldr	r3, [r2, #0]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #12]
	str	r9, [fp, #-8]
	str	r10, [fp, #-4]
	ldr	lr, [r0, #16]
	ldr	ip, [r0, #20]
	str	lr, [fp, #-48]
	str	ip, [fp, #-44]
	ldr	lr, [r0, #24]
	ldr	ip, [r0, #28]
	str	lr, [fp, #-40]
	str	ip, [fp, #-36]
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #36]
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	ldr	lr, [r0, #40]
	ldr	ip, [r0, #44]
	str	lr, [fp, #-24]
	str	ip, [fp, #-20]
	movs	r2, #0
	movs	r0, #10
.L1:
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r3, r7
	eor	r4, r8
	eor	r5, r5, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r3, r9
	eor	r4, r10
	eor	r3, lr
	eor	r4, ip
	and	lr, r2, #0x0F
	eor	r4, r4, r2, lsr #4
	eor	r3, lr
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	eors	r4, r5
	eors	r5, r3
	eors	r6, r5
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r6, r7
	eor	r3, r8
	eor	r4, r4, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r6, r9
	eor	r3, r10
	eor	r6, lr
	eor	r3, ip
	and	lr, r2, #0x0F
	eor	r3, r3, r2, lsr #4
	eor	r6, lr
	ror	r3, r3, #24
	ror	r4, r4, #16
	ror	r5, r5, #8
	eors	r3, r4
	eors	r4, r6
	eors	r5, r4
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r5, r7
	eor	r6, r8
	eor	r3, r3, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r5, r9
	eor	r6, r10
	eor	r5, lr
	eor	r6, ip
	and	lr, r2, #0x0F
	eor	r6, r6, r2, lsr #4
	eor	r5, lr
	ror	r6, r6, #24
	ror	r3, r3, #16
	ror	r4, r4, #8
	eors	r6, r3
	eors	r3, r5
	eors	r4, r3
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r4, r7
	eor	r5, r8
	eor	r6, r6, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r4, r9
	eor	r5, r10
	eor	r4, lr
	eor	r5, ip
	and	lr, r2, #0x0F
	eor	r5, r5, r2, lsr #4
	eor	r4, lr
	ror	r5, r5, #24
	ror	r6, r6, #16
	ror	r3, r3, #8
	eors	r5, r6
	eors	r6, r4
	eors	r3, r6
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	subs	r0, r0, #1
	bne	.L1
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
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
	sub	sp, sp, #48
	ldr	r3, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	ubfx	r7, r4, #8, #16
	ubfx	lr, r3, #24, #8
	bfi	r7, lr, #16, #8
	ubfx	lr, r3, #16, #8
	bfi	r7, lr, #24, #8
	lsr	r8, r4, #24
	bfi	r8, r3, #8, #16
	bfi	r8, r4, #24, #8
	ubfx	r9, r6, #8, #16
	ubfx	lr, r5, #24, #8
	bfi	r9, lr, #16, #8
	ubfx	lr, r5, #16, #8
	bfi	r9, lr, #24, #8
	lsr	r10, r6, #24
	bfi	r10, r5, #8, #16
	bfi	r10, r6, #24, #8
	movs	r3, #20
.L2:
	lsl	lr, r7, #1
	lsl	ip, r8, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r7, r7, #5
	lsr	r8, r8, #5
	eor	r7, r7, r7, lsr #2
	eor	r8, r8, r8, lsr #2
	and	r7, r7, #0x01010101
	and	r8, r8, #0x01010101
	eor	r7, r7, lr
	eor	r8, r8, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	subs	r3, r3, #1
	bne	.L2
	str	r7, [fp, #-48]
	str	r8, [fp, #-44]
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r3, [r0, #32]
	ldr	r4, [r0, #36]
	ldr	r5, [r0, #40]
	ldr	r6, [r0, #44]
	ubfx	r7, r4, #8, #16
	ubfx	lr, r3, #24, #8
	bfi	r7, lr, #16, #8
	ubfx	lr, r3, #16, #8
	bfi	r7, lr, #24, #8
	lsr	r8, r4, #24
	bfi	r8, r3, #8, #16
	bfi	r8, r4, #24, #8
	ubfx	r9, r6, #8, #16
	ubfx	lr, r5, #24, #8
	bfi	r9, lr, #16, #8
	ubfx	lr, r5, #16, #8
	bfi	r9, lr, #24, #8
	lsr	r10, r6, #24
	bfi	r10, r5, #8, #16
	bfi	r10, r6, #24, #8
	movs	r3, #20
.L3:
	lsr	lr, r7, #1
	lsr	ip, r8, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r7, r7, #1
	lsl	r8, r8, #1
	eor	r7, r7, r7, lsl #6
	eor	r8, r8, r8, lsl #6
	and	r7, r7, #0x80808080
	and	r8, r8, #0x80808080
	eor	r7, r7, lr
	eor	r8, r8, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	subs	r3, r3, #1
	bne	.L3
	str	r7, [fp, #-32]
	str	r8, [fp, #-28]
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ubfx	r7, r4, #8, #16
	ubfx	lr, r3, #24, #8
	bfi	r7, lr, #16, #8
	ubfx	lr, r3, #16, #8
	bfi	r7, lr, #24, #8
	lsr	r8, r4, #24
	bfi	r8, r3, #8, #16
	bfi	r8, r4, #24, #8
	ubfx	r9, r6, #8, #16
	ubfx	lr, r5, #24, #8
	bfi	r9, lr, #16, #8
	ubfx	lr, r5, #16, #8
	bfi	r9, lr, #24, #8
	lsr	r10, r6, #24
	bfi	r10, r5, #8, #16
	bfi	r10, r6, #24, #8
	str	r9, [fp, #-8]
	str	r10, [fp, #-4]
	ldr	r3, [r2, #0]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	movs	r2, #52
	movs	r0, #10
.L4:
	mov	lr, r7
	mov	ip, r8
	ubfx	r7, lr, #16, #8
	bfi	r7, lr, #8, #8
	bfi	r7, ip, #16, #8
	ubfx	r8, ip, #24, #8
	bfi	r7, r8, #24, #8
	ror	r8, lr, #16
	and	r8, r8, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r8, r8, lr
	ubfx	lr, ip, #8, #8
	bfi	r8, lr, #16, #8
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	eors	r3, r6
	eors	r6, r4
	eors	r5, r6
	ror	r5, r5, #8
	ror	r6, r6, #16
	ror	r3, r3, #24
	eor	lr, r2, r2, lsl #5
	eor	lr, lr, #0x20
	and	lr, lr, #0x20
	eor	r2, lr, r2, lsr #1
	eors	r4, r7
	eor	r5, r8
	eor	r6, r6, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r4, lr
	eor	r5, ip
	ldr	lr, [fp, #-24]
	ldr	ip, [fp, #-20]
	eor	r4, lr
	eor	r5, ip
	and	lr, r2, #0x0F
	eor	r5, r5, r2, lsr #4
	eor	r4, lr
	mvns	r3, r3
	lsr	lr, r3, #1
	and	lr, lr, r3, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x10101010
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #6
	and	lr, lr, r3, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #1
	and	ip, ip, r3, lsl #2
	and	ip, ip, #0x04040404
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #4
	and	ip, ip, r3, lsl #5
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r3, r3, #2
	orr	r3, r3, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r3, r3, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r3, r3, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r3, r3, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r3, r3, ip, lsr #1
	mvns	r4, r4
	lsr	lr, r4, #1
	and	lr, lr, r4, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x10101010
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #6
	and	lr, lr, r4, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #1
	and	ip, ip, r4, lsl #2
	and	ip, ip, #0x04040404
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #4
	and	ip, ip, r4, lsl #5
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r4, r4, #2
	orr	r4, r4, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r4, r4, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r4, r4, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r4, r4, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r4, r4, ip, lsr #1
	mvns	r5, r5
	lsr	lr, r5, #1
	and	lr, lr, r5, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x10101010
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #6
	and	lr, lr, r5, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #1
	and	ip, ip, r5, lsl #2
	and	ip, ip, #0x04040404
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #4
	and	ip, ip, r5, lsl #5
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r5, r5, #2
	orr	r5, r5, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r5, r5, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r5, r5, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r5, r5, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r5, r5, ip, lsr #1
	mvns	r6, r6
	lsr	lr, r6, #1
	and	lr, lr, r6, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x10101010
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #6
	and	lr, lr, r6, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #1
	and	ip, ip, r6, lsl #2
	and	ip, ip, #0x04040404
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #4
	and	ip, ip, r6, lsl #5
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r6, r6, #2
	orr	r6, r6, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r6, r6, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r6, r6, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r6, r6, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r6, r6, ip, lsr #1
	mov	lr, r7
	mov	ip, r8
	ubfx	r7, lr, #16, #8
	bfi	r7, lr, #8, #8
	bfi	r7, ip, #16, #8
	ubfx	r8, ip, #24, #8
	bfi	r7, r8, #24, #8
	ror	r8, lr, #16
	and	r8, r8, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r8, r8, lr
	ubfx	lr, ip, #8, #8
	bfi	r8, lr, #16, #8
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	eors	r4, r3
	eors	r3, r5
	eors	r6, r3
	ror	r6, r6, #8
	ror	r3, r3, #16
	ror	r4, r4, #24
	eor	lr, r2, r2, lsl #5
	eor	lr, lr, #0x20
	and	lr, lr, #0x20
	eor	r2, lr, r2, lsr #1
	eors	r5, r7
	eor	r6, r8
	eor	r3, r3, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r5, lr
	eor	r6, ip
	ldr	lr, [fp, #-32]
	ldr	ip, [fp, #-28]
	eor	r5, lr
	eor	r6, ip
	and	lr, r2, #0x0F
	eor	r6, r6, r2, lsr #4
	eor	r5, lr
	mvns	r4, r4
	lsr	lr, r4, #1
	and	lr, lr, r4, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x10101010
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #6
	and	lr, lr, r4, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #1
	and	ip, ip, r4, lsl #2
	and	ip, ip, #0x04040404
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #4
	and	ip, ip, r4, lsl #5
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r4, r4, #2
	orr	r4, r4, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r4, r4, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r4, r4, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r4, r4, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r4, r4, ip, lsr #1
	mvns	r5, r5
	lsr	lr, r5, #1
	and	lr, lr, r5, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x10101010
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #6
	and	lr, lr, r5, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #1
	and	ip, ip, r5, lsl #2
	and	ip, ip, #0x04040404
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #4
	and	ip, ip, r5, lsl #5
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r5, r5, #2
	orr	r5, r5, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r5, r5, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r5, r5, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r5, r5, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r5, r5, ip, lsr #1
	mvns	r6, r6
	lsr	lr, r6, #1
	and	lr, lr, r6, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x10101010
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #6
	and	lr, lr, r6, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #1
	and	ip, ip, r6, lsl #2
	and	ip, ip, #0x04040404
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #4
	and	ip, ip, r6, lsl #5
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r6, r6, #2
	orr	r6, r6, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r6, r6, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r6, r6, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r6, r6, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r6, r6, ip, lsr #1
	mvns	r3, r3
	lsr	lr, r3, #1
	and	lr, lr, r3, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x10101010
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #6
	and	lr, lr, r3, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #1
	and	ip, ip, r3, lsl #2
	and	ip, ip, #0x04040404
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #4
	and	ip, ip, r3, lsl #5
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r3, r3, #2
	orr	r3, r3, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r3, r3, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r3, r3, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r3, r3, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r3, r3, ip, lsr #1
	mov	lr, r7
	mov	ip, r8
	ubfx	r7, lr, #16, #8
	bfi	r7, lr, #8, #8
	bfi	r7, ip, #16, #8
	ubfx	r8, ip, #24, #8
	bfi	r7, r8, #24, #8
	ror	r8, lr, #16
	and	r8, r8, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r8, r8, lr
	ubfx	lr, ip, #8, #8
	bfi	r8, lr, #16, #8
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	eors	r5, r4
	eors	r4, r6
	eors	r3, r4
	ror	r3, r3, #8
	ror	r4, r4, #16
	ror	r5, r5, #24
	eor	lr, r2, r2, lsl #5
	eor	lr, lr, #0x20
	and	lr, lr, #0x20
	eor	r2, lr, r2, lsr #1
	eors	r6, r7
	eor	r3, r8
	eor	r4, r4, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r6, lr
	eor	r3, ip
	ldr	lr, [fp, #-24]
	ldr	ip, [fp, #-20]
	eor	r6, lr
	eor	r3, ip
	and	lr, r2, #0x0F
	eor	r3, r3, r2, lsr #4
	eor	r6, lr
	mvns	r5, r5
	lsr	lr, r5, #1
	and	lr, lr, r5, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x10101010
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #6
	and	lr, lr, r5, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #1
	and	ip, ip, r5, lsl #2
	and	ip, ip, #0x04040404
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #4
	and	ip, ip, r5, lsl #5
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r5, r5, #2
	orr	r5, r5, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r5, r5, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r5, r5, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r5, r5, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r5, r5, ip, lsr #1
	mvns	r6, r6
	lsr	lr, r6, #1
	and	lr, lr, r6, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x10101010
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #6
	and	lr, lr, r6, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #1
	and	ip, ip, r6, lsl #2
	and	ip, ip, #0x04040404
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #4
	and	ip, ip, r6, lsl #5
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r6, r6, #2
	orr	r6, r6, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r6, r6, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r6, r6, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r6, r6, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r6, r6, ip, lsr #1
	mvns	r3, r3
	lsr	lr, r3, #1
	and	lr, lr, r3, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x10101010
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #6
	and	lr, lr, r3, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #1
	and	ip, ip, r3, lsl #2
	and	ip, ip, #0x04040404
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #4
	and	ip, ip, r3, lsl #5
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r3, r3, #2
	orr	r3, r3, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r3, r3, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r3, r3, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r3, r3, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r3, r3, ip, lsr #1
	mvns	r4, r4
	lsr	lr, r4, #1
	and	lr, lr, r4, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x10101010
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #6
	and	lr, lr, r4, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #1
	and	ip, ip, r4, lsl #2
	and	ip, ip, #0x04040404
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #4
	and	ip, ip, r4, lsl #5
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r4, r4, #2
	orr	r4, r4, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r4, r4, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r4, r4, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r4, r4, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r4, r4, ip, lsr #1
	mov	lr, r7
	mov	ip, r8
	ubfx	r7, lr, #16, #8
	bfi	r7, lr, #8, #8
	bfi	r7, ip, #16, #8
	ubfx	r8, ip, #24, #8
	bfi	r7, r8, #24, #8
	ror	r8, lr, #16
	and	r8, r8, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r8, r8, lr
	ubfx	lr, ip, #8, #8
	bfi	r8, lr, #16, #8
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	mov	ip, r10
	ubfx	r9, lr, #16, #8
	bfi	r9, lr, #8, #8
	bfi	r9, ip, #16, #8
	ubfx	r10, ip, #24, #8
	bfi	r9, r10, #24, #8
	ror	r10, lr, #16
	and	r10, r10, #0xFF00FF00
	ubfx	lr, ip, #16, #8
	orr	r10, r10, lr
	ubfx	lr, ip, #8, #8
	bfi	r10, lr, #16, #8
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	eors	r6, r5
	eors	r5, r3
	eors	r4, r5
	ror	r4, r4, #8
	ror	r5, r5, #16
	ror	r6, r6, #24
	eor	lr, r2, r2, lsl #5
	eor	lr, lr, #0x20
	and	lr, lr, #0x20
	eor	r2, lr, r2, lsr #1
	eors	r3, r7
	eor	r4, r8
	eor	r5, r5, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r3, lr
	eor	r4, ip
	ldr	lr, [fp, #-32]
	ldr	ip, [fp, #-28]
	eor	r3, lr
	eor	r4, ip
	and	lr, r2, #0x0F
	eor	r4, r4, r2, lsr #4
	eor	r3, lr
	mvns	r6, r6
	lsr	lr, r6, #1
	and	lr, lr, r6, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x10101010
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #6
	and	lr, lr, r6, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #1
	and	ip, ip, r6, lsl #2
	and	ip, ip, #0x04040404
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #4
	and	ip, ip, r6, lsl #5
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r6, r6, #2
	orr	r6, r6, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r6, r6, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r6, r6, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r6, r6, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r6, r6, ip, lsr #1
	mvns	r3, r3
	lsr	lr, r3, #1
	and	lr, lr, r3, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x10101010
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #6
	and	lr, lr, r3, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #1
	and	ip, ip, r3, lsl #2
	and	ip, ip, #0x04040404
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #4
	and	ip, ip, r3, lsl #5
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r3, r3, #2
	orr	r3, r3, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r3, r3, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r3, r3, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r3, r3, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r3, r3, ip, lsr #1
	mvns	r4, r4
	lsr	lr, r4, #1
	and	lr, lr, r4, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x10101010
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #6
	and	lr, lr, r4, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #1
	and	ip, ip, r4, lsl #2
	and	ip, ip, #0x04040404
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #4
	and	ip, ip, r4, lsl #5
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r4, r4, #2
	orr	r4, r4, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r4, r4, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r4, r4, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r4, r4, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r4, r4, ip, lsr #1
	mvns	r5, r5
	lsr	lr, r5, #1
	and	lr, lr, r5, lsr #3
	and	lr, lr, #0x01010101
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x10101010
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #6
	and	lr, lr, r5, lsr #1
	and	lr, lr, #0x02020202
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #1
	and	ip, ip, r5, lsl #2
	and	ip, ip, #0x04040404
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #4
	and	ip, ip, r5, lsl #5
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x01010101
	and	ip, lr, #0x04040404
	lsl	r5, r5, #2
	orr	r5, r5, ip, lsl #4
	and	ip, lr, #0x02020202
	orr	r5, r5, ip, lsl #6
	and	ip, lr, #0x20202020
	orr	r5, r5, ip, lsr #5
	and	ip, lr, #0xC8C8C8C8
	orr	r5, r5, ip, lsr #2
	and	ip, lr, #0x10101010
	orr	r5, r5, ip, lsr #1
	subs	r0, r0, #1
	bne	.L4
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_decrypt, .-skinny_plus_decrypt
	.global	skinny_plus_encrypt_tk_full
	.set	skinny_plus_encrypt_tk_full,skinny_plus_encrypt
	.global	skinny_plus_decrypt_tk_full
	.set	skinny_plus_decrypt_tk_full,skinny_plus_decrypt

#endif
#endif
