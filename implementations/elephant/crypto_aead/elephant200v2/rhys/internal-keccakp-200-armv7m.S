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

	.align	2
	.type	rconst, %object
rconst:
	.byte	0x01
	.byte	0x82
	.byte	0x8a
	.byte	0x00
	.byte	0x8b
	.byte	0x01
	.byte	0x81
	.byte	0x09
	.byte	0x8a
	.byte	0x88
	.byte	0x09
	.byte	0x0a
	.byte	0x8b
	.byte	0x8b
	.byte	0x89
	.byte	0x03
	.byte	0x02
	.byte	0x80
	.size	rconst, .-rconst

	.align	2
	.global	keccakp_200_permute
	.thumb
	.thumb_func
	.type	keccakp_200_permute, %function
keccakp_200_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #5]
	ldr	r3, [r0, #10]
	ldr	r4, [r0, #15]
	ldr	r5, [r0, #20]
	ldrb	r6, [r0, #4]
	ldrb	r7, [r0, #9]
	ldrb	r8, [r0, #14]
	ldrb	r9, [r0, #19]
	ldrb	r10, [r0, #24]
	push	{r0}
	movs	r0, #0
.L1:
	eor	fp, r1, r2
	eor	lr, r6, r7
	eor	fp, r3
	eor	lr, r8
	eor	fp, r4
	eor	lr, r9
	eor	fp, r5
	eor	lr, r10
	ubfx	ip, lr, #0, #7
	eor	lr, lr, ip, lsl #25
	and	ip, lr, #0x80
	eor	lr, lr, ip, lsl #17
	eor	lr, lr, fp, lsl #8
	and	ip, fp, #0x7F7F7F7F
	eor	lr, lr, ip, lsr #7
	and	ip, fp, #0x80808080
	eor	lr, lr, ip, lsr #15
	ubfx	ip, fp, #0, #7
	eor	fp, fp, ip, lsl #25
	ubfx	ip, fp, #7, #1
	eor	fp, fp, ip, lsl #24
	lsr	fp, fp, #24
	eor	r1, lr
	eor	r6, fp
	eor	r2, lr
	eor	r7, fp
	eor	r3, lr
	eor	r8, fp
	eor	r4, lr
	eor	r9, fp
	eor	r5, lr
	eor	r10, fp
	lsr	lr, r1, #8
	lsr	ip, r2, #12
	lsr	fp, r2, #8
	bfi	r1, ip, #8, #4
	bfi	r1, fp, #12, #4
	lsr	ip, r7, #4
	bfi	r2, r7, #12, #4
	bfi	r2, ip, #8, #4
	lsr	ip, r5, #19
	lsr	fp, r5, #16
	bfi	r7, ip, #0, #5
	bfi	r7, fp, #5, #3
	lsr	ip, r8, #1
	bfi	r5, r8, #23, #1
	bfi	r5, ip, #16, #7
	lsr	ip, r5, #6
	bfi	r8, r5, #2, #6
	bfi	r8, ip, #0, #2
	lsr	ip, r1, #18
	lsr	fp, r1, #16
	bfi	r5, ip, #0, #6
	bfi	r5, fp, #6, #2
	lsr	ip, r3, #21
	lsr	fp, r3, #16
	bfi	r1, ip, #16, #3
	bfi	r1, fp, #19, #5
	lsr	ip, r3, #31
	lsr	fp, r3, #24
	bfi	r3, ip, #16, #1
	bfi	r3, fp, #17, #7
	bfi	r3, r9, #24, #8
	lsr	ip, r5, #24
	bfi	r9, ip, #0, #8
	lsr	ip, r4, #7
	bfi	r5, r4, #25, #7
	bfi	r5, ip, #24, #1
	lsr	ip, r6, #5
	bfi	r4, r6, #3, #5
	bfi	r4, ip, #0, #3
	lsr	ip, r10, #2
	bfi	r6, r10, #6, #2
	bfi	r6, ip, #0, #6
	lsr	ip, r5, #14
	lsr	fp, r5, #8
	bfi	r10, ip, #0, #2
	bfi	r10, fp, #2, #6
	lsr	ip, r2, #25
	lsr	fp, r2, #24
	bfi	r5, ip, #8, #7
	bfi	r5, fp, #15, #1
	lsr	ip, r4, #11
	lsr	fp, r4, #8
	bfi	r2, ip, #24, #5
	bfi	r2, fp, #29, #3
	lsr	ip, r2, #4
	bfi	r4, r2, #12, #4
	bfi	r4, ip, #8, #4
	lsr	ip, r1, #28
	lsr	fp, r1, #24
	bfi	r2, ip, #0, #4
	bfi	r2, fp, #4, #4
	lsr	ip, r4, #27
	lsr	fp, r4, #24
	bfi	r1, ip, #24, #5
	bfi	r1, fp, #29, #3
	lsr	ip, r4, #17
	lsr	fp, r4, #16
	bfi	r4, ip, #24, #7
	bfi	r4, fp, #31, #1
	lsr	ip, r3, #14
	lsr	fp, r3, #8
	bfi	r4, ip, #16, #2
	bfi	r4, fp, #18, #6
	lsr	ip, r2, #18
	lsr	fp, r2, #16
	bfi	r3, ip, #8, #6
	bfi	r3, fp, #14, #2
	lsr	ip, r3, #5
	bfi	r2, r3, #19, #5
	bfi	r2, ip, #16, #3
	lsr	ip, lr, #7
	bfi	r3, lr, #1, #7
	bfi	r3, ip, #0, #1
	lsr	ip, r1, #8
	lsr	fp, r1, #16
	orr	ip, ip, r6, lsl #24
	orr	fp, fp, r1, lsl #24
	lsr	lr, r1, #8
	orr	fp, fp, r6, lsl #16
	bic	lr, lr, r1
	bic	fp, fp, ip
	ubfx	lr, lr, #0, #8
	eor	r1, fp
	eor	r6, lr
	lsr	ip, r2, #8
	lsr	fp, r2, #16
	orr	ip, ip, r7, lsl #24
	orr	fp, fp, r2, lsl #24
	lsr	lr, r2, #8
	orr	fp, fp, r7, lsl #16
	bic	lr, lr, r2
	bic	fp, fp, ip
	ubfx	lr, lr, #0, #8
	eor	r2, fp
	eor	r7, lr
	lsr	ip, r3, #8
	lsr	fp, r3, #16
	orr	ip, ip, r8, lsl #24
	orr	fp, fp, r3, lsl #24
	lsr	lr, r3, #8
	orr	fp, fp, r8, lsl #16
	bic	lr, lr, r3
	bic	fp, fp, ip
	ubfx	lr, lr, #0, #8
	eor	r3, fp
	eor	r8, lr
	lsr	ip, r4, #8
	lsr	fp, r4, #16
	orr	ip, ip, r9, lsl #24
	orr	fp, fp, r4, lsl #24
	lsr	lr, r4, #8
	orr	fp, fp, r9, lsl #16
	bic	lr, lr, r4
	bic	fp, fp, ip
	ubfx	lr, lr, #0, #8
	eor	r4, fp
	eor	r9, lr
	lsr	ip, r5, #8
	lsr	fp, r5, #16
	orr	ip, ip, r10, lsl #24
	orr	fp, fp, r5, lsl #24
	lsr	lr, r5, #8
	orr	fp, fp, r10, lsl #16
	bic	lr, lr, r5
	bic	fp, fp, ip
	ubfx	lr, lr, #0, #8
	eor	r5, fp
	eor	r10, lr
	adr	fp, rconst
	ldrb	ip, [fp, r0]
	eor	r1, ip
	add	r0, #1
	cmp	r0, #18
	bne	.L1
	pop	{r0}
	str	r1, [r0, #0]
	str	r2, [r0, #5]
	str	r3, [r0, #10]
	str	r4, [r0, #15]
	str	r5, [r0, #20]
	strb	r6, [r0, #4]
	strb	r7, [r0, #9]
	strb	r8, [r0, #14]
	strb	r9, [r0, #19]
	strb	r10, [r0, #24]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	keccakp_200_permute, .-keccakp_200_permute

#endif
