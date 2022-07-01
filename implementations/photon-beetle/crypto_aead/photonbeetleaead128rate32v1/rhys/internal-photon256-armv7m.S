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

	.syntax unified
	.thumb
	.text

	.align	4
	.type	rconst, %object
rconst:
	.word	0x00000001
	.word	0x01010000
	.word	0x01000000
	.word	0x00000000
	.word	0x01010100
	.word	0x00000101
	.word	0x00010101
	.word	0x01010101
	.word	0x00000001
	.word	0x00000101
	.word	0x01000000
	.word	0x00000000
	.word	0x01010100
	.word	0x01010000
	.word	0x00010101
	.word	0x01010101
	.word	0x00000001
	.word	0x00000101
	.word	0x00010101
	.word	0x00000000
	.word	0x01010100
	.word	0x01010000
	.word	0x01000000
	.word	0x01010101
	.word	0x01010100
	.word	0x00000101
	.word	0x00010101
	.word	0x01010101
	.word	0x00000001
	.word	0x01010000
	.word	0x01000000
	.word	0x00000000
	.word	0x00000001
	.word	0x01010000
	.word	0x00010101
	.word	0x01010101
	.word	0x01010100
	.word	0x00000101
	.word	0x01000000
	.word	0x00000000
	.word	0x00000001
	.word	0x00000101
	.word	0x01000000
	.word	0x01010101
	.word	0x01010100
	.word	0x01010000
	.word	0x00010101
	.word	0x00000000
	.word	0x01010100
	.word	0x00000101
	.word	0x00010101
	.word	0x00000000
	.word	0x00000001
	.word	0x01010000
	.word	0x01000000
	.word	0x01010101
	.word	0x01010100
	.word	0x01010000
	.word	0x00010101
	.word	0x01010101
	.word	0x00000001
	.word	0x00000101
	.word	0x01000000
	.word	0x00000000
	.word	0x00000001
	.word	0x01010000
	.word	0x01000000
	.word	0x01010101
	.word	0x01010100
	.word	0x00000101
	.word	0x00010101
	.word	0x00000000
	.word	0x01010100
	.word	0x00000101
	.word	0x01000000
	.word	0x00000000
	.word	0x00000001
	.word	0x01010000
	.word	0x00010101
	.word	0x01010101
	.word	0x00000001
	.word	0x01010000
	.word	0x00010101
	.word	0x00000000
	.word	0x01010100
	.word	0x00000101
	.word	0x01000000
	.word	0x01010101
	.word	0x01010100
	.word	0x00000101
	.word	0x01000000
	.word	0x01010101
	.word	0x00000001
	.word	0x01010000
	.word	0x00010101
	.word	0x00000000
	.size	rconst, .-rconst

	.align	2
	.global	photon256_permute
	.thumb
	.thumb_func
	.type	photon256_permute, %function
photon256_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #48
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
	eor	ip, r6, r6, lsr #3
	and	ip, ip, #168430090
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #3
	eor	ip, r6, r6, lsr #6
	and	ip, ip, #13369548
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #6
	eor	ip, r6, r6, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #12
	eor	ip, r6, r6, lsr #8
	and	ip, ip, #65280
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #8
	eor	ip, r7, r7, lsr #3
	and	ip, ip, #168430090
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #3
	eor	ip, r7, r7, lsr #6
	and	ip, ip, #13369548
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #6
	eor	ip, r7, r7, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #12
	eor	ip, r7, r7, lsr #8
	and	ip, ip, #65280
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #8
	eor	ip, r8, r8, lsr #3
	and	ip, ip, #168430090
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #3
	eor	ip, r8, r8, lsr #6
	and	ip, ip, #13369548
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #6
	eor	ip, r8, r8, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #12
	eor	ip, r8, r8, lsr #8
	and	ip, ip, #65280
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #8
	eor	ip, r9, r9, lsr #3
	and	ip, ip, #168430090
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #3
	eor	ip, r9, r9, lsr #6
	and	ip, ip, #13369548
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #6
	eor	ip, r9, r9, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #12
	eor	ip, r9, r9, lsr #8
	and	ip, ip, #65280
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #8
	uxtb	r2, r6
	uxtb	r3, r6, ror #8
	uxtb	r4, r6, ror #16
	uxtb	r5, r6, ror #24
	bfi	r2, r7, #8, #8
	bfi	r2, r8, #16, #8
	bfi	r2, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r3, r7, #8, #8
	bfi	r3, r8, #16, #8
	bfi	r3, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r4, r7, #8, #8
	bfi	r4, r8, #16, #8
	bfi	r4, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r5, r7, #8, #8
	bfi	r5, r8, #16, #8
	bfi	r5, r9, #24, #8
	str	r2, [r0, #16]
	str	r3, [r0, #20]
	str	r4, [r0, #24]
	str	r5, [r0, #28]
	ldr	r6, [r0, #0]
	ldr	r7, [r0, #4]
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
	eor	ip, r6, r6, lsr #3
	and	ip, ip, #168430090
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #3
	eor	ip, r6, r6, lsr #6
	and	ip, ip, #13369548
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #6
	eor	ip, r6, r6, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #12
	eor	ip, r6, r6, lsr #8
	and	ip, ip, #65280
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #8
	eor	ip, r7, r7, lsr #3
	and	ip, ip, #168430090
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #3
	eor	ip, r7, r7, lsr #6
	and	ip, ip, #13369548
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #6
	eor	ip, r7, r7, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #12
	eor	ip, r7, r7, lsr #8
	and	ip, ip, #65280
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #8
	eor	ip, r8, r8, lsr #3
	and	ip, ip, #168430090
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #3
	eor	ip, r8, r8, lsr #6
	and	ip, ip, #13369548
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #6
	eor	ip, r8, r8, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #12
	eor	ip, r8, r8, lsr #8
	and	ip, ip, #65280
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #8
	eor	ip, r9, r9, lsr #3
	and	ip, ip, #168430090
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #3
	eor	ip, r9, r9, lsr #6
	and	ip, ip, #13369548
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #6
	eor	ip, r9, r9, lsr #12
	movw	lr, #61680
	and	ip, ip, lr
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #12
	eor	ip, r9, r9, lsr #8
	and	ip, ip, #65280
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #8
	uxtb	r2, r6
	uxtb	r3, r6, ror #8
	uxtb	r4, r6, ror #16
	uxtb	r5, r6, ror #24
	bfi	r2, r7, #8, #8
	bfi	r2, r8, #16, #8
	bfi	r2, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r3, r7, #8, #8
	bfi	r3, r8, #16, #8
	bfi	r3, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r4, r7, #8, #8
	bfi	r4, r8, #16, #8
	bfi	r4, r9, #24, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	r9, r9, #8
	bfi	r5, r7, #8, #8
	bfi	r5, r8, #16, #8
	bfi	r5, r9, #24, #8
	adr	r10, rconst
	movs	r1, #12
.L1:
	ldr	r6, [r10], #4
	ldr	r7, [r10], #4
	ldr	r8, [r10], #4
	ldr	r9, [r10], #4
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, r9
	eors	r3, r4
	and	r6, r4, r3
	eors	r5, r6
	movs	r7, r5
	ands	r5, r3
	eors	r5, r4
	mov	r8, r5
	eors	r5, r2
	mvns	r5, r5
	movs	r4, r5
	orr	r8, r2
	eors	r2, r7
	eors	r3, r2
	orrs	r4, r3
	eors	r4, r7
	eor	r3, r8
	eors	r5, r3
	eor	ip, r2, r2, lsr #4
	movw	lr, #256
	movt	lr, #1795
	and	ip, ip, lr
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #4
	eor	ip, r2, r2, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #2
	eor	ip, r2, r2, lsr #1
	and	ip, ip, #1426085120
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #1
	eor	ip, r3, r3, lsr #4
	movw	lr, #256
	movt	lr, #1795
	and	ip, ip, lr
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #4
	eor	ip, r3, r3, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #2
	eor	ip, r3, r3, lsr #1
	and	ip, ip, #1426085120
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #1
	eor	ip, r4, r4, lsr #4
	movw	lr, #256
	movt	lr, #1795
	and	ip, ip, lr
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #4
	eor	ip, r4, r4, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #2
	eor	ip, r4, r4, lsr #1
	and	ip, ip, #1426085120
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #1
	eor	ip, r5, r5, lsr #4
	movw	lr, #256
	movt	lr, #1795
	and	ip, ip, lr
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #4
	eor	ip, r5, r5, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #2
	eor	ip, r5, r5, lsr #1
	and	ip, ip, #1426085120
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #1
	str	r2, [fp, #-48]
	str	r3, [fp, #-44]
	str	r4, [fp, #-40]
	str	r5, [fp, #-36]
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r6, [r10], #4
	ldr	r7, [r10], #4
	ldr	r8, [r10], #4
	ldr	r9, [r10], #4
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, r9
	eors	r3, r4
	and	r6, r4, r3
	eors	r5, r6
	movs	r7, r5
	ands	r5, r3
	eors	r5, r4
	mov	r8, r5
	eors	r5, r2
	mvns	r5, r5
	movs	r4, r5
	orr	r8, r2
	eors	r2, r7
	eors	r3, r2
	orrs	r4, r3
	eors	r4, r7
	eor	r3, r8
	eors	r5, r3
	eor	ip, r2, r2, lsr #4
	movw	lr, #3599
	movt	lr, #2060
	and	ip, ip, lr
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #4
	eor	ip, r2, r2, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #2
	eor	ip, r2, r2, lsr #1
	and	ip, ip, #1426085120
	eor	r2, r2, ip
	eor	r2, r2, ip, lsl #1
	eor	ip, r3, r3, lsr #4
	movw	lr, #3599
	movt	lr, #2060
	and	ip, ip, lr
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #4
	eor	ip, r3, r3, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #2
	eor	ip, r3, r3, lsr #1
	and	ip, ip, #1426085120
	eor	r3, r3, ip
	eor	r3, r3, ip, lsl #1
	eor	ip, r4, r4, lsr #4
	movw	lr, #3599
	movt	lr, #2060
	and	ip, ip, lr
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #4
	eor	ip, r4, r4, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #2
	eor	ip, r4, r4, lsr #1
	and	ip, ip, #1426085120
	eor	r4, r4, ip
	eor	r4, r4, ip, lsl #1
	eor	ip, r5, r5, lsr #4
	movw	lr, #3599
	movt	lr, #2060
	and	ip, ip, lr
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #4
	eor	ip, r5, r5, lsr #2
	movw	lr, #4352
	movt	lr, #8755
	and	ip, ip, lr
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #2
	eor	ip, r5, r5, lsr #1
	and	ip, ip, #1426085120
	eor	r5, r5, ip
	eor	r5, r5, ip, lsl #1
	str	r2, [fp, #-32]
	str	r3, [fp, #-28]
	str	r4, [fp, #-24]
	str	r5, [fp, #-20]
	ldrb	r2, [fp, #-48]
	ldrb	ip, [fp, #-44]
	ldrb	lr, [fp, #-40]
	orr	r2, r2, ip, lsl #8
	ldrb	ip, [fp, #-36]
	orr	r2, r2, lr, lsl #16
	orr	r2, r2, ip, lsl #24
	ldrb	r3, [fp, #-47]
	ldrb	ip, [fp, #-43]
	ldrb	lr, [fp, #-39]
	orr	r3, r3, ip, lsl #8
	ldrb	ip, [fp, #-35]
	orr	r3, r3, lr, lsl #16
	orr	r3, r3, ip, lsl #24
	ldrb	r4, [fp, #-46]
	ldrb	ip, [fp, #-42]
	ldrb	lr, [fp, #-38]
	orr	r4, r4, ip, lsl #8
	ldrb	ip, [fp, #-34]
	orr	r4, r4, lr, lsl #16
	orr	r4, r4, ip, lsl #24
	ldrb	r5, [fp, #-45]
	ldrb	ip, [fp, #-41]
	ldrb	lr, [fp, #-37]
	orr	r5, r5, ip, lsl #8
	ldrb	ip, [fp, #-33]
	orr	r5, r5, lr, lsl #16
	orr	r5, r5, ip, lsl #24
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	mov	r6, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	mov	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r3
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	mov	r8, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r8, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r8, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	mov	r9, r2
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r5
	str	r6, [fp, #-16]
	str	r7, [fp, #-12]
	str	r8, [fp, #-8]
	str	r9, [fp, #-4]
	movs	r6, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	movs	r7, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	mov	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	mov	r9, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r3
	eor	r9, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	ldrb	r2, [fp, #-32]
	ldrb	ip, [fp, #-28]
	ldrb	lr, [fp, #-24]
	orr	r2, r2, ip, lsl #8
	ldrb	ip, [fp, #-20]
	orr	r2, r2, lr, lsl #16
	orr	r2, r2, ip, lsl #24
	ldrb	r3, [fp, #-31]
	ldrb	ip, [fp, #-27]
	ldrb	lr, [fp, #-23]
	orr	r3, r3, ip, lsl #8
	ldrb	ip, [fp, #-19]
	orr	r3, r3, lr, lsl #16
	orr	r3, r3, ip, lsl #24
	ldrb	r4, [fp, #-30]
	ldrb	ip, [fp, #-26]
	ldrb	lr, [fp, #-22]
	orr	r4, r4, ip, lsl #8
	ldrb	ip, [fp, #-18]
	orr	r4, r4, lr, lsl #16
	orr	r4, r4, ip, lsl #24
	ldrb	r5, [fp, #-29]
	ldrb	ip, [fp, #-25]
	ldrb	lr, [fp, #-21]
	orr	r5, r5, ip, lsl #8
	ldrb	ip, [fp, #-17]
	orr	r5, r5, lr, lsl #16
	orr	r5, r5, ip, lsl #24
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r3
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	r8, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r8, r3
	eor	r8, r4
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r9, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	strb	r6, [r0, #16]
	lsr	ip, r6, #8
	lsr	lr, r6, #16
	strb	ip, [r0, #20]
	strb	lr, [r0, #24]
	lsr	ip, r6, #24
	strb	ip, [r0, #28]
	strb	r7, [r0, #17]
	lsr	ip, r7, #8
	lsr	lr, r7, #16
	strb	ip, [r0, #21]
	strb	lr, [r0, #25]
	lsr	ip, r7, #24
	strb	ip, [r0, #29]
	strb	r8, [r0, #18]
	lsr	ip, r8, #8
	lsr	lr, r8, #16
	strb	ip, [r0, #22]
	strb	lr, [r0, #26]
	lsr	ip, r8, #24
	strb	ip, [r0, #30]
	strb	r9, [r0, #19]
	lsr	ip, r9, #8
	lsr	lr, r9, #16
	strb	ip, [r0, #23]
	strb	lr, [r0, #27]
	lsr	ip, r9, #24
	strb	ip, [r0, #31]
	ldr	r6, [fp, #-16]
	ldr	r7, [fp, #-12]
	ldr	r8, [fp, #-8]
	ldr	r9, [fp, #-4]
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r6, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r6, ip
	eors	r7, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r3
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eors	r7, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r7, ip
	eor	r8, r2
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r8, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	r8, r5
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r8, ip
	eor	ip, r2, r2, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r3
	eor	ip, r3, r3, lsr #24
	ror	ip, ip, #24
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	r9, r4
	eor	ip, r4, r4, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, r5, r5, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	eor	ip, ip, ip, lsr #24
	ror	ip, ip, #24
	eor	r9, ip
	strb	r6, [r0, #0]
	lsr	ip, r6, #8
	lsr	lr, r6, #16
	strb	ip, [r0, #4]
	strb	lr, [r0, #8]
	lsr	ip, r6, #24
	strb	ip, [r0, #12]
	strb	r7, [r0, #1]
	lsr	ip, r7, #8
	lsr	lr, r7, #16
	strb	ip, [r0, #5]
	strb	lr, [r0, #9]
	lsr	ip, r7, #24
	strb	ip, [r0, #13]
	strb	r8, [r0, #2]
	lsr	ip, r8, #8
	lsr	lr, r8, #16
	strb	ip, [r0, #6]
	strb	lr, [r0, #10]
	lsr	ip, r8, #24
	strb	ip, [r0, #14]
	strb	r9, [r0, #3]
	lsr	ip, r9, #8
	lsr	lr, r9, #16
	strb	ip, [r0, #7]
	strb	lr, [r0, #11]
	lsr	ip, r9, #24
	strb	ip, [r0, #15]
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	subs	r1, r1, #1
	bne	.L1
	uxtb	r6, r2
	uxtb	r7, r2, ror #8
	uxtb	r8, r2, ror #16
	uxtb	r9, r2, ror #24
	bfi	r6, r3, #8, #8
	bfi	r6, r4, #16, #8
	bfi	r6, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r7, r3, #8, #8
	bfi	r7, r4, #16, #8
	bfi	r7, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r8, r3, #8, #8
	bfi	r8, r4, #16, #8
	bfi	r8, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r9, r3, #8, #8
	bfi	r9, r4, #16, #8
	bfi	r9, r5, #24, #8
	eor	ip, r6, r6, lsr #7
	and	ip, ip, #11141290
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #7
	eor	ip, r6, r6, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #14
	eor	ip, r6, r6, lsr #4
	and	ip, ip, #15728880
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #4
	eor	ip, r6, r6, lsr #8
	and	ip, ip, #65280
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #8
	eor	ip, r7, r7, lsr #7
	and	ip, ip, #11141290
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #7
	eor	ip, r7, r7, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #14
	eor	ip, r7, r7, lsr #4
	and	ip, ip, #15728880
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #4
	eor	ip, r7, r7, lsr #8
	and	ip, ip, #65280
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #8
	eor	ip, r8, r8, lsr #7
	and	ip, ip, #11141290
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #7
	eor	ip, r8, r8, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #14
	eor	ip, r8, r8, lsr #4
	and	ip, ip, #15728880
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #4
	eor	ip, r8, r8, lsr #8
	and	ip, ip, #65280
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #8
	eor	ip, r9, r9, lsr #7
	and	ip, ip, #11141290
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #7
	eor	ip, r9, r9, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #14
	eor	ip, r9, r9, lsr #4
	and	ip, ip, #15728880
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #4
	eor	ip, r9, r9, lsr #8
	and	ip, ip, #65280
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #8
	str	r6, [r0, #0]
	str	r7, [r0, #4]
	str	r8, [r0, #8]
	str	r9, [r0, #12]
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	uxtb	r6, r2
	uxtb	r7, r2, ror #8
	uxtb	r8, r2, ror #16
	uxtb	r9, r2, ror #24
	bfi	r6, r3, #8, #8
	bfi	r6, r4, #16, #8
	bfi	r6, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r7, r3, #8, #8
	bfi	r7, r4, #16, #8
	bfi	r7, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r8, r3, #8, #8
	bfi	r8, r4, #16, #8
	bfi	r8, r5, #24, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	lsr	r5, r5, #8
	bfi	r9, r3, #8, #8
	bfi	r9, r4, #16, #8
	bfi	r9, r5, #24, #8
	eor	ip, r6, r6, lsr #7
	and	ip, ip, #11141290
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #7
	eor	ip, r6, r6, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #14
	eor	ip, r6, r6, lsr #4
	and	ip, ip, #15728880
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #4
	eor	ip, r6, r6, lsr #8
	and	ip, ip, #65280
	eor	r6, r6, ip
	eor	r6, r6, ip, lsl #8
	eor	ip, r7, r7, lsr #7
	and	ip, ip, #11141290
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #7
	eor	ip, r7, r7, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #14
	eor	ip, r7, r7, lsr #4
	and	ip, ip, #15728880
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #4
	eor	ip, r7, r7, lsr #8
	and	ip, ip, #65280
	eor	r7, r7, ip
	eor	r7, r7, ip, lsl #8
	eor	ip, r8, r8, lsr #7
	and	ip, ip, #11141290
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #7
	eor	ip, r8, r8, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #14
	eor	ip, r8, r8, lsr #4
	and	ip, ip, #15728880
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #4
	eor	ip, r8, r8, lsr #8
	and	ip, ip, #65280
	eor	r8, r8, ip
	eor	r8, r8, ip, lsl #8
	eor	ip, r9, r9, lsr #7
	and	ip, ip, #11141290
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #7
	eor	ip, r9, r9, lsr #14
	movw	lr, #52428
	and	ip, ip, lr
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #14
	eor	ip, r9, r9, lsr #4
	and	ip, ip, #15728880
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #4
	eor	ip, r9, r9, lsr #8
	and	ip, ip, #65280
	eor	r9, r9, ip
	eor	r9, r9, ip, lsl #8
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	photon256_permute, .-photon256_permute

#endif
