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
	.byte	0
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	1
	.byte	2
	.byte	2
	.byte	0
	.byte	2
	.byte	0
	.byte	1
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	2
	.byte	0
	.byte	1
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	0
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	3
	.byte	0
	.byte	1
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	2
	.byte	3
	.byte	2
	.byte	1
	.byte	1
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	2
	.byte	2
	.byte	1
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	0
	.byte	2
	.byte	0
	.byte	3
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	0
	.byte	2
	.byte	1
	.byte	0
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	0
	.byte	2
	.byte	0
	.byte	2
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	1
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	1
	.byte	1
	.byte	2
	.byte	2
	.byte	3
	.byte	2
	.byte	1
	.byte	1
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	2
	.byte	2
	.byte	1
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	2
	.byte	2
	.byte	1
	.byte	3
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	2
	.byte	2
	.byte	1
	.byte	1
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	1
	.byte	2
	.byte	0
	.byte	2
	.byte	0
	.byte	2
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.byte	1
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	1
	.byte	1
	.byte	1
	.byte	2
	.byte	2
	.byte	2
	.byte	0
	.byte	1
	.byte	1
	.byte	1
	.byte	0
	.byte	0
	.byte	2
	.byte	2
	.byte	2
	.byte	1
	.byte	1
	.byte	0
	.byte	2
	.byte	1
	.byte	0
	.byte	2
	.byte	2
	.byte	1
	.byte	0
	.byte	2
	.byte	2
	.byte	1
	.byte	1
	.byte	0
	.byte	2
	.byte	0
	.byte	2
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	1
	.byte	0
	.byte	0
	.byte	2
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	3
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	0
	.byte	0
	.byte	0
	.byte	1
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	0
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	2
	.byte	0
	.byte	1
	.byte	3
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	1
	.byte	1
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	1
	.byte	2
	.byte	0
	.byte	3
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	3
	.byte	0
	.byte	1
	.byte	3
	.byte	2
	.byte	0
	.byte	0
	.byte	1
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	2
	.byte	1
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	0
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	1
	.byte	0
	.byte	1
	.byte	2
	.byte	0
	.byte	2
	.byte	2
	.byte	1
	.byte	0
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	1
	.byte	2
	.byte	0
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	2
	.byte	1
	.byte	1
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	2
	.byte	0
	.byte	1
	.byte	1
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	2
	.byte	2
	.byte	1
	.byte	3
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	0
	.byte	2
	.byte	0
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	0
	.byte	1
	.byte	3
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	0
	.byte	2
	.byte	1
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	2
	.byte	3
	.byte	3
	.byte	1
	.byte	0
	.byte	2
	.byte	0
	.byte	2
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	1
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	1
	.byte	3
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	0
	.byte	2
	.byte	0
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	3
	.byte	0
	.byte	0
	.byte	0
	.byte	3
	.byte	2
	.byte	1
	.byte	2
	.byte	1
	.byte	3
	.byte	0
	.byte	1
	.byte	2
	.byte	1
	.byte	0
	.byte	0
	.byte	2
	.byte	1
	.byte	2
	.byte	0
	.byte	1
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	2
	.byte	0
	.byte	1
	.byte	0
	.byte	3
	.byte	0
	.byte	0
	.byte	3
	.byte	0
	.byte	2
	.byte	0
	.byte	3
	.byte	0
	.byte	3
	.byte	3
	.byte	0
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	2
	.byte	0
	.byte	3
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	1
	.byte	3
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	2
	.byte	1
	.byte	3
	.byte	1
	.byte	3
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	1
	.byte	1
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	2
	.byte	2
	.byte	255
	.size	rconst, .-rconst

	.align	2
	.global	spongent160_permute
	.thumb
	.thumb_func
	.type	spongent160_permute, %function
spongent160_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r9, [r0]
	ldr	r10, [r0, #4]
	ldr	fp, [r0, #8]
	ldr	lr, [r0, #12]
	ldr	ip, [r0, #16]
	push	{r0}
	eor	r1, r9, r9, lsr #3
	and	r1, r1, #168430090
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #3
	eor	r1, r9, r9, lsr #6
	and	r1, r1, #13369548
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #6
	eor	r1, r9, r9, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #12
	eor	r1, r9, r9, lsr #24
	and	r1, r1, #255
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #24
	eor	r1, r10, r10, lsr #3
	and	r1, r1, #168430090
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #3
	eor	r1, r10, r10, lsr #6
	and	r1, r1, #13369548
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #6
	eor	r1, r10, r10, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #12
	eor	r1, r10, r10, lsr #24
	and	r1, r1, #255
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #24
	eor	r1, fp, fp, lsr #3
	and	r1, r1, #168430090
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #3
	eor	r1, fp, fp, lsr #6
	and	r1, r1, #13369548
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #6
	eor	r1, fp, fp, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #12
	eor	r1, fp, fp, lsr #24
	and	r1, r1, #255
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #24
	eor	r1, lr, lr, lsr #3
	and	r1, r1, #168430090
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #3
	eor	r1, lr, lr, lsr #6
	and	r1, r1, #13369548
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #6
	eor	r1, lr, lr, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #12
	eor	r1, lr, lr, lsr #24
	and	r1, r1, #255
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #24
	eor	r1, ip, ip, lsr #3
	and	r1, r1, #168430090
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #3
	eor	r1, ip, ip, lsr #6
	and	r1, r1, #13369548
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #6
	eor	r1, ip, ip, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #12
	eor	r1, ip, ip, lsr #24
	and	r1, r1, #255
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #24
	ubfx	r1, r9, #0, #8
	bfi	r1, r10, #8, #8
	bfi	r1, fp, #16, #8
	bfi	r1, lr, #24, #8
	ubfx	r5, ip, #0, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	ubfx	r2, r9, #8, #8
	bfi	r2, r10, #8, #8
	bfi	r2, fp, #16, #8
	bfi	r2, lr, #24, #8
	ubfx	r6, ip, #8, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	ubfx	r3, r9, #16, #8
	bfi	r3, r10, #8, #8
	bfi	r3, fp, #16, #8
	bfi	r3, lr, #24, #8
	ubfx	r7, ip, #16, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	ubfx	r4, r9, #24, #8
	bfi	r4, r10, #8, #8
	bfi	r4, fp, #16, #8
	bfi	r4, lr, #24, #8
	ubfx	r8, ip, #24, #8
	adr	r0, rconst
	add	r0, #80
.L11:
	ldrb	r9, [r0], #1
	cmp	r9, #255
	beq	.L12
	eor	r1, r9
	ldrb	r9, [r0], #1
	eor	r2, r9
	ldrb	r9, [r0], #1
	eor	r3, r9
	ldrb	r9, [r0], #1
	eor	r4, r9
	ldrb	r9, [r0], #1
	eor	r5, r5, r9, lsl #6
	ldrb	r9, [r0], #1
	eor	r6, r6, r9, lsl #6
	ldrb	r9, [r0], #1
	eor	r7, r7, r9, lsl #6
	ldrb	r9, [r0], #1
	eor	r8, r8, r9, lsl #6
	eor	r9, r1, r3
	eor	r10, r2, r3
	and	r9, r10
	eor	r10, r1, r2
	eor	r10, r4
	eor	r10, r9
	mvn	r10, r10
	mvn	fp, r1
	and	r10, fp
	eor	fp, r2, r10
	eor	lr, fp, r3
	eor	lr, r4
	eor	lr, r9
	and	fp, lr
	eor	lr, r3, r9
	eor	ip, r2, r9
	mvn	ip, ip
	and	lr, ip
	eor	fp, r2
	eor	fp, r3
	eor	fp, r4
	eor	ip, r1, r3
	eor	ip, r4
	eor	ip, r9
	eor	ip, r10
	eors	r3, r1
	eors	r3, r2
	eor	r3, r10
	eors	r4, r1
	eor	r4, r9
	eor	r4, lr
	mov	r1, fp
	mov	r2, ip
	eor	r9, r5, r7
	eor	r10, r6, r7
	and	r9, r10
	eor	r10, r5, r6
	eor	r10, r8
	eor	r10, r9
	mvn	r10, r10
	mvn	fp, r5
	and	r10, fp
	eor	fp, r6, r10
	eor	lr, fp, r7
	eor	lr, r8
	eor	lr, r9
	and	fp, lr
	eor	lr, r7, r9
	eor	ip, r6, r9
	mvn	ip, ip
	and	lr, ip
	eor	fp, r6
	eor	fp, r7
	eor	fp, r8
	eor	ip, r5, r7
	eor	ip, r8
	eor	ip, r9
	eor	ip, r10
	eors	r7, r5
	eors	r7, r6
	eor	r7, r10
	eor	r8, r5
	eor	r8, r9
	eor	r8, lr
	mov	r5, fp
	mov	r6, ip
	mov	r9, r3
	lsr	r10, r4, #1
	bfi	r3, r10, #0, #1
	lsr	r10, r4, #4
	bfi	r4, r10, #1, #1
	lsr	r10, r4, #16
	bfi	r4, r10, #4, #1
	lsr	r10, r3, #24
	bfi	r4, r10, #16, #1
	lsr	r10, r2, #17
	bfi	r3, r10, #24, #1
	lsr	r10, r3, #30
	bfi	r2, r10, #17, #1
	lsr	r10, r1, #1
	bfi	r3, r10, #30, #1
	lsr	r10, r4, #7
	bfi	r1, r10, #1, #1
	lsr	r10, r4, #28
	bfi	r4, r10, #7, #1
	bfi	r4, r6, #28, #1
	lsr	r10, r1, #10
	bfi	r6, r10, #0, #1
	lsr	r10, r3, #3
	bfi	r1, r10, #10, #1
	lsr	r10, r4, #13
	bfi	r3, r10, #3, #1
	lsr	r10, r3, #12
	bfi	r4, r10, #13, #1
	lsr	r10, r3, #9
	bfi	r3, r10, #12, #1
	lsr	r10, r8, #5
	bfi	r3, r10, #9, #1
	lsr	r10, r1, #28
	bfi	r8, r10, #5, #1
	lsr	r10, r6, #3
	bfi	r1, r10, #28, #1
	lsr	r10, r1, #22
	bfi	r6, r10, #3, #1
	lsr	r10, r2, #11
	bfi	r1, r10, #22, #1
	lsr	r10, r3, #6
	bfi	r2, r10, #11, #1
	lsr	r10, r4, #25
	bfi	r3, r10, #6, #1
	lsr	r10, r2, #20
	bfi	r4, r10, #25, #1
	lsr	r10, r2, #2
	bfi	r2, r10, #20, #1
	lsr	r10, r4, #10
	bfi	r2, r10, #2, #1
	bfi	r4, r9, #10, #1
	mov	r9, r2
	lsr	r10, r4, #2
	bfi	r2, r10, #0, #1
	lsr	r10, r4, #8
	bfi	r4, r10, #2, #1
	bfi	r4, r8, #8, #1
	lsr	r10, r1, #8
	bfi	r8, r10, #0, #1
	lsr	r10, r8, #3
	bfi	r1, r10, #8, #1
	lsr	r10, r1, #20
	bfi	r8, r10, #3, #1
	lsr	r10, r2, #3
	bfi	r1, r10, #20, #1
	lsr	r10, r4, #14
	bfi	r2, r10, #3, #1
	lsr	r10, r3, #16
	bfi	r4, r10, #14, #1
	lsr	r10, r3, #25
	bfi	r3, r10, #16, #1
	lsr	r10, r2, #21
	bfi	r3, r10, #25, #1
	lsr	r10, r2, #6
	bfi	r2, r10, #21, #1
	lsr	r10, r4, #26
	bfi	r2, r10, #6, #1
	lsr	r10, r2, #24
	bfi	r4, r10, #26, #1
	lsr	r10, r2, #18
	bfi	r2, r10, #24, #1
	lsr	r10, r7, #2
	bfi	r2, r10, #18, #1
	lsr	r10, r1, #17
	bfi	r7, r10, #2, #1
	lsr	r10, r3, #31
	bfi	r1, r10, #17, #1
	lsr	r10, r1, #5
	bfi	r3, r10, #31, #1
	lsr	r10, r4, #23
	bfi	r1, r10, #5, #1
	lsr	r10, r2, #12
	bfi	r4, r10, #23, #1
	lsr	r10, r3, #10
	bfi	r2, r10, #12, #1
	lsr	r10, r3, #1
	bfi	r3, r10, #10, #1
	lsr	r10, r4, #5
	bfi	r3, r10, #1, #1
	lsr	r10, r4, #20
	bfi	r4, r10, #5, #1
	bfi	r4, r9, #20, #1
	mov	r9, r1
	lsr	r10, r4, #3
	bfi	r1, r10, #0, #1
	lsr	r10, r4, #12
	bfi	r4, r10, #3, #1
	lsr	r10, r3, #8
	bfi	r4, r10, #12, #1
	lsr	r10, r8, #1
	bfi	r3, r10, #8, #1
	lsr	r10, r1, #12
	bfi	r8, r10, #1, #1
	lsr	r10, r3, #11
	bfi	r1, r10, #12, #1
	lsr	r10, r3, #5
	bfi	r3, r10, #11, #1
	lsr	r10, r4, #21
	bfi	r3, r10, #5, #1
	lsr	r10, r2, #4
	bfi	r4, r10, #21, #1
	lsr	r10, r4, #18
	bfi	r2, r10, #4, #1
	bfi	r4, r7, #18, #1
	lsr	r10, r1, #9
	bfi	r7, r10, #0, #1
	lsr	r10, r8, #7
	bfi	r1, r10, #9, #1
	lsr	r10, r5, #4
	bfi	r8, r10, #7, #1
	lsr	r10, r1, #27
	bfi	r5, r10, #4, #1
	lsr	r10, r2, #31
	bfi	r1, r10, #27, #1
	lsr	r10, r1, #6
	bfi	r2, r10, #31, #1
	lsr	r10, r4, #27
	bfi	r1, r10, #6, #1
	lsr	r10, r2, #28
	bfi	r4, r10, #27, #1
	lsr	r10, r6, #2
	bfi	r2, r10, #28, #1
	lsr	r10, r1, #18
	bfi	r6, r10, #2, #1
	lsr	r10, r7, #3
	bfi	r1, r10, #18, #1
	lsr	r10, r1, #21
	bfi	r7, r10, #3, #1
	lsr	r10, r2, #7
	bfi	r1, r10, #21, #1
	lsr	r10, r4, #30
	bfi	r2, r10, #7, #1
	bfi	r4, r9, #30, #1
	lsr	r9, r2, #1
	lsr	r10, r4, #6
	bfi	r2, r10, #1, #1
	lsr	r10, r4, #24
	bfi	r4, r10, #6, #1
	lsr	r10, r2, #16
	bfi	r4, r10, #24, #1
	lsr	r10, r3, #26
	bfi	r2, r10, #16, #1
	lsr	r10, r2, #25
	bfi	r3, r10, #26, #1
	lsr	r10, r2, #22
	bfi	r2, r10, #25, #1
	lsr	r10, r2, #10
	bfi	r2, r10, #22, #1
	lsr	r10, r3, #2
	bfi	r2, r10, #10, #1
	lsr	r10, r4, #9
	bfi	r3, r10, #2, #1
	lsr	r10, r8, #4
	bfi	r4, r10, #9, #1
	lsr	r10, r1, #24
	bfi	r8, r10, #4, #1
	lsr	r10, r2, #19
	bfi	r1, r10, #24, #1
	lsr	r10, r7, #6
	bfi	r2, r10, #19, #1
	lsr	r10, r5, #1
	bfi	r7, r10, #6, #1
	lsr	r10, r1, #15
	bfi	r5, r10, #1, #1
	lsr	r10, r3, #23
	bfi	r1, r10, #15, #1
	lsr	r10, r2, #13
	bfi	r3, r10, #23, #1
	lsr	r10, r3, #14
	bfi	r2, r10, #13, #1
	lsr	r10, r3, #17
	bfi	r3, r10, #14, #1
	lsr	r10, r3, #29
	bfi	r3, r10, #17, #1
	lsr	r10, r6, #5
	bfi	r3, r10, #29, #1
	lsr	r10, r1, #30
	bfi	r6, r10, #5, #1
	lsr	r10, r1, #3
	bfi	r1, r10, #30, #1
	lsr	r10, r4, #15
	bfi	r1, r10, #3, #1
	lsr	r10, r3, #20
	bfi	r4, r10, #15, #1
	bfi	r3, r9, #20, #1
	lsr	r9, r1, #2
	lsr	r10, r4, #11
	bfi	r1, r10, #2, #1
	lsr	r10, r3, #4
	bfi	r4, r10, #11, #1
	lsr	r10, r4, #17
	bfi	r3, r10, #4, #1
	lsr	r10, r3, #28
	bfi	r4, r10, #17, #1
	lsr	r10, r6, #1
	bfi	r3, r10, #28, #1
	lsr	r10, r1, #14
	bfi	r6, r10, #1, #1
	lsr	r10, r3, #19
	bfi	r1, r10, #14, #1
	lsr	r10, r7, #5
	bfi	r3, r10, #19, #1
	lsr	r10, r1, #29
	bfi	r7, r10, #5, #1
	lsr	r10, r6, #7
	bfi	r1, r10, #29, #1
	lsr	r10, r5, #6
	bfi	r6, r10, #7, #1
	lsr	r10, r5, #3
	bfi	r5, r10, #6, #1
	lsr	r10, r1, #23
	bfi	r5, r10, #3, #1
	lsr	r10, r2, #15
	bfi	r1, r10, #23, #1
	lsr	r10, r3, #22
	bfi	r2, r10, #15, #1
	lsr	r10, r2, #9
	bfi	r3, r10, #22, #1
	lsr	r10, r8, #6
	bfi	r2, r10, #9, #1
	bfi	r8, r5, #6, #1
	lsr	r10, r1, #11
	bfi	r5, r10, #0, #1
	lsr	r10, r3, #7
	bfi	r1, r10, #11, #1
	lsr	r10, r4, #29
	bfi	r3, r10, #7, #1
	lsr	r10, r6, #4
	bfi	r4, r10, #29, #1
	lsr	r10, r1, #26
	bfi	r6, r10, #4, #1
	lsr	r10, r2, #27
	bfi	r1, r10, #26, #1
	lsr	r10, r2, #30
	bfi	r2, r10, #27, #1
	bfi	r2, r9, #30, #1
	lsr	r9, r1, #4
	lsr	r10, r4, #19
	bfi	r1, r10, #4, #1
	lsr	r10, r7, #4
	bfi	r4, r10, #19, #1
	lsr	r10, r1, #25
	bfi	r7, r10, #4, #1
	lsr	r10, r2, #23
	bfi	r1, r10, #25, #1
	lsr	r10, r2, #14
	bfi	r2, r10, #23, #1
	lsr	r10, r3, #18
	bfi	r2, r10, #14, #1
	lsr	r10, r7, #1
	bfi	r3, r10, #18, #1
	lsr	r10, r1, #13
	bfi	r7, r10, #1, #1
	lsr	r10, r3, #15
	bfi	r1, r10, #13, #1
	lsr	r10, r3, #21
	bfi	r3, r10, #15, #1
	lsr	r10, r2, #5
	bfi	r3, r10, #21, #1
	lsr	r10, r4, #22
	bfi	r2, r10, #5, #1
	lsr	r10, r2, #8
	bfi	r4, r10, #22, #1
	lsr	r10, r8, #2
	bfi	r2, r10, #8, #1
	lsr	r10, r1, #16
	bfi	r8, r10, #2, #1
	lsr	r10, r3, #27
	bfi	r1, r10, #16, #1
	lsr	r10, r2, #29
	bfi	r3, r10, #27, #1
	lsr	r10, r6, #6
	bfi	r2, r10, #29, #1
	lsr	r10, r5, #2
	bfi	r6, r10, #6, #1
	lsr	r10, r1, #19
	bfi	r5, r10, #2, #1
	lsr	r10, r7, #7
	bfi	r1, r10, #19, #1
	lsr	r10, r5, #5
	bfi	r7, r10, #7, #1
	lsr	r10, r1, #31
	bfi	r5, r10, #5, #1
	lsr	r10, r1, #7
	bfi	r1, r10, #31, #1
	lsr	r10, r4, #31
	bfi	r1, r10, #7, #1
	bfi	r4, r9, #31, #1
	b	.L11
.L12:
	ubfx	r9, r1, #0, #8
	bfi	r9, r2, #8, #8
	bfi	r9, r3, #16, #8
	bfi	r9, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	r10, r1, #8, #8
	bfi	r10, r2, #8, #8
	bfi	r10, r3, #16, #8
	bfi	r10, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	fp, r1, #16, #8
	bfi	fp, r2, #8, #8
	bfi	fp, r3, #16, #8
	bfi	fp, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	lr, r1, #24, #8
	bfi	lr, r2, #8, #8
	bfi	lr, r3, #16, #8
	bfi	lr, r4, #24, #8
	ubfx	ip, r5, #0, #8
	bfi	ip, r6, #8, #8
	bfi	ip, r7, #16, #8
	bfi	ip, r8, #24, #8
	eor	r1, r9, r9, lsr #9
	and	r1, r1, #5570645
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #9
	eor	r1, r9, r9, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #18
	eor	r1, r9, r9, lsr #12
	and	r1, r1, #983055
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #12
	eor	r1, r9, r9, lsr #24
	and	r1, r1, #255
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #24
	eor	r1, r10, r10, lsr #9
	and	r1, r1, #5570645
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #9
	eor	r1, r10, r10, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #18
	eor	r1, r10, r10, lsr #12
	and	r1, r1, #983055
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #12
	eor	r1, r10, r10, lsr #24
	and	r1, r1, #255
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #24
	eor	r1, fp, fp, lsr #9
	and	r1, r1, #5570645
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #9
	eor	r1, fp, fp, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #18
	eor	r1, fp, fp, lsr #12
	and	r1, r1, #983055
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #12
	eor	r1, fp, fp, lsr #24
	and	r1, r1, #255
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #24
	eor	r1, lr, lr, lsr #9
	and	r1, r1, #5570645
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #9
	eor	r1, lr, lr, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #18
	eor	r1, lr, lr, lsr #12
	and	r1, r1, #983055
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #12
	eor	r1, lr, lr, lsr #24
	and	r1, r1, #255
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #24
	eor	r1, ip, ip, lsr #9
	and	r1, r1, #5570645
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #9
	eor	r1, ip, ip, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #18
	eor	r1, ip, ip, lsr #12
	and	r1, r1, #983055
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #12
	eor	r1, ip, ip, lsr #24
	and	r1, r1, #255
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #24
	pop	{r0}
	str	r9, [r0]
	str	r10, [r0, #4]
	str	fp, [r0, #8]
	str	lr, [r0, #12]
	str	ip, [r0, #16]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	spongent160_permute, .-spongent160_permute

	.align	2
	.global	spongent176_permute
	.thumb
	.thumb_func
	.type	spongent176_permute, %function
spongent176_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r0}
	ldr	r9, [r0]
	ldr	r10, [r0, #4]
	ldr	fp, [r0, #8]
	ldr	lr, [r0, #12]
	ldr	ip, [r0, #16]
	ldrh	r0, [r0, #20]
	eor	r1, r9, r9, lsr #3
	and	r1, r1, #168430090
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #3
	eor	r1, r9, r9, lsr #6
	and	r1, r1, #13369548
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #6
	eor	r1, r9, r9, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #12
	eor	r1, r9, r9, lsr #24
	and	r1, r1, #255
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #24
	eor	r1, r10, r10, lsr #3
	and	r1, r1, #168430090
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #3
	eor	r1, r10, r10, lsr #6
	and	r1, r1, #13369548
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #6
	eor	r1, r10, r10, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #12
	eor	r1, r10, r10, lsr #24
	and	r1, r1, #255
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #24
	eor	r1, fp, fp, lsr #3
	and	r1, r1, #168430090
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #3
	eor	r1, fp, fp, lsr #6
	and	r1, r1, #13369548
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #6
	eor	r1, fp, fp, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #12
	eor	r1, fp, fp, lsr #24
	and	r1, r1, #255
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #24
	eor	r1, lr, lr, lsr #3
	and	r1, r1, #168430090
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #3
	eor	r1, lr, lr, lsr #6
	and	r1, r1, #13369548
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #6
	eor	r1, lr, lr, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #12
	eor	r1, lr, lr, lsr #24
	and	r1, r1, #255
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #24
	eor	r1, ip, ip, lsr #3
	and	r1, r1, #168430090
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #3
	eor	r1, ip, ip, lsr #6
	and	r1, r1, #13369548
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #6
	eor	r1, ip, ip, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #12
	eor	r1, ip, ip, lsr #24
	and	r1, r1, #255
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #24
	eor	r1, r0, r0, lsr #3
	and	r1, r1, #168430090
	eor	r0, r0, r1
	eor	r0, r0, r1, lsl #3
	eor	r1, r0, r0, lsr #6
	and	r1, r1, #13369548
	eor	r0, r0, r1
	eor	r0, r0, r1, lsl #6
	eor	r1, r0, r0, lsr #12
	movw	r2, #61680
	and	r1, r1, r2
	eor	r0, r0, r1
	eor	r0, r0, r1, lsl #12
	eor	r1, r0, r0, lsr #24
	and	r1, r1, #255
	eor	r0, r0, r1
	eor	r0, r0, r1, lsl #24
	ubfx	r1, r9, #0, #8
	bfi	r1, r10, #8, #8
	bfi	r1, fp, #16, #8
	bfi	r1, lr, #24, #8
	ubfx	r5, ip, #0, #8
	bfi	r5, r0, #8, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	lsr	r0, r0, #8
	ubfx	r2, r9, #8, #8
	bfi	r2, r10, #8, #8
	bfi	r2, fp, #16, #8
	bfi	r2, lr, #24, #8
	ubfx	r6, ip, #8, #8
	bfi	r6, r0, #8, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	lsr	r0, r0, #8
	ubfx	r3, r9, #16, #8
	bfi	r3, r10, #8, #8
	bfi	r3, fp, #16, #8
	bfi	r3, lr, #24, #8
	ubfx	r7, ip, #16, #8
	bfi	r7, r0, #8, #8
	lsr	r10, r10, #8
	lsr	fp, fp, #8
	lsr	lr, lr, #8
	lsr	r0, r0, #8
	ubfx	r4, r9, #24, #8
	bfi	r4, r10, #8, #8
	bfi	r4, fp, #16, #8
	bfi	r4, lr, #24, #8
	ubfx	r8, ip, #24, #8
	bfi	r8, r0, #8, #8
	adr	r0, rconst
.L21:
	ldrb	r9, [r0], #1
	cmp	r9, #255
	beq	.L22
	eor	r1, r9
	ldrb	r9, [r0], #1
	eor	r2, r9
	ldrb	r9, [r0], #1
	eor	r3, r9
	ldrb	r9, [r0], #1
	eor	r4, r9
	ldrb	r9, [r0], #1
	eor	r5, r5, r9, lsl #10
	ldrb	r9, [r0], #1
	eor	r6, r6, r9, lsl #10
	ldrb	r9, [r0], #1
	eor	r7, r7, r9, lsl #10
	ldrb	r9, [r0], #1
	eor	r8, r8, r9, lsl #10
	eor	r9, r1, r3
	eor	r10, r2, r3
	and	r9, r10
	eor	r10, r1, r2
	eor	r10, r4
	eor	r10, r9
	mvn	r10, r10
	mvn	fp, r1
	and	r10, fp
	eor	fp, r2, r10
	eor	lr, fp, r3
	eor	lr, r4
	eor	lr, r9
	and	fp, lr
	eor	lr, r3, r9
	eor	ip, r2, r9
	mvn	ip, ip
	and	lr, ip
	eor	fp, r2
	eor	fp, r3
	eor	fp, r4
	eor	ip, r1, r3
	eor	ip, r4
	eor	ip, r9
	eor	ip, r10
	eors	r3, r1
	eors	r3, r2
	eor	r3, r10
	eors	r4, r1
	eor	r4, r9
	eor	r4, lr
	mov	r1, fp
	mov	r2, ip
	eor	r9, r5, r7
	eor	r10, r6, r7
	and	r9, r10
	eor	r10, r5, r6
	eor	r10, r8
	eor	r10, r9
	mvn	r10, r10
	mvn	fp, r5
	and	r10, fp
	eor	fp, r6, r10
	eor	lr, fp, r7
	eor	lr, r8
	eor	lr, r9
	and	fp, lr
	eor	lr, r7, r9
	eor	ip, r6, r9
	mvn	ip, ip
	and	lr, ip
	eor	fp, r6
	eor	fp, r7
	eor	fp, r8
	eor	ip, r5, r7
	eor	ip, r8
	eor	ip, r9
	eor	ip, r10
	eors	r7, r5
	eors	r7, r6
	eor	r7, r10
	eor	r8, r5
	eor	r8, r9
	eor	r8, lr
	mov	r5, fp
	mov	r6, ip
	mov	r9, r3
	lsr	r10, r4, #1
	bfi	r3, r10, #0, #1
	lsr	r10, r4, #4
	bfi	r4, r10, #1, #1
	lsr	r10, r4, #16
	bfi	r4, r10, #4, #1
	lsr	r10, r3, #20
	bfi	r4, r10, #16, #1
	lsr	r10, r7, #5
	bfi	r3, r10, #20, #1
	lsr	r10, r1, #17
	bfi	r7, r10, #5, #1
	lsr	r10, r3, #27
	bfi	r1, r10, #17, #1
	lsr	r10, r2, #21
	bfi	r3, r10, #27, #1
	lsr	r10, r7, #10
	bfi	r2, r10, #21, #1
	lsr	r10, r5, #5
	bfi	r7, r10, #10, #1
	lsr	r10, r1, #19
	bfi	r5, r10, #5, #1
	lsr	r10, r7, #3
	bfi	r1, r10, #19, #1
	lsr	r10, r1, #9
	bfi	r7, r10, #3, #1
	lsr	r10, r8, #7
	bfi	r1, r10, #9, #1
	lsr	r10, r1, #24
	bfi	r8, r10, #7, #1
	lsr	r10, r2, #11
	bfi	r1, r10, #24, #1
	lsr	r10, r3, #2
	bfi	r2, r10, #11, #1
	lsr	r10, r4, #9
	bfi	r3, r10, #2, #1
	lsr	r10, r8, #4
	bfi	r4, r10, #9, #1
	lsr	r10, r1, #12
	bfi	r8, r10, #4, #1
	lsr	r10, r3, #7
	bfi	r1, r10, #12, #1
	lsr	r10, r4, #29
	bfi	r3, r10, #7, #1
	lsr	r10, r2, #28
	bfi	r4, r10, #29, #1
	lsr	r10, r2, #26
	bfi	r2, r10, #28, #1
	lsr	r10, r2, #18
	bfi	r2, r10, #26, #1
	lsr	r10, r3, #30
	bfi	r2, r10, #18, #1
	lsr	r10, r6, #1
	bfi	r3, r10, #30, #1
	lsr	r10, r1, #2
	bfi	r6, r10, #1, #1
	lsr	r10, r4, #11
	bfi	r1, r10, #2, #1
	bfi	r4, r9, #11, #1
	mov	r9, r2
	lsr	r10, r4, #2
	bfi	r2, r10, #0, #1
	lsr	r10, r4, #8
	bfi	r4, r10, #2, #1
	bfi	r4, r8, #8, #1
	lsr	r10, r6, #8
	bfi	r8, r10, #0, #1
	lsr	r10, r1, #30
	bfi	r6, r10, #8, #1
	lsr	r10, r6, #3
	bfi	r1, r10, #30, #1
	lsr	r10, r1, #10
	bfi	r6, r10, #3, #1
	lsr	r10, r8, #11
	bfi	r1, r10, #10, #1
	lsr	r10, r5, #8
	bfi	r8, r10, #11, #1
	lsr	r10, r1, #31
	bfi	r5, r10, #8, #1
	lsr	r10, r6, #7
	bfi	r1, r10, #31, #1
	lsr	r10, r1, #26
	bfi	r6, r10, #7, #1
	lsr	r10, r2, #19
	bfi	r1, r10, #26, #1
	lsr	r10, r7, #2
	bfi	r2, r10, #19, #1
	lsr	r10, r1, #5
	bfi	r7, r10, #2, #1
	lsr	r10, r4, #23
	bfi	r1, r10, #5, #1
	lsr	r10, r2, #4
	bfi	r4, r10, #23, #1
	lsr	r10, r4, #18
	bfi	r2, r10, #4, #1
	lsr	r10, r3, #28
	bfi	r4, r10, #18, #1
	lsr	r10, r2, #25
	bfi	r3, r10, #28, #1
	lsr	r10, r2, #14
	bfi	r2, r10, #25, #1
	lsr	r10, r3, #14
	bfi	r2, r10, #14, #1
	lsr	r10, r3, #13
	bfi	r3, r10, #14, #1
	lsr	r10, r3, #9
	bfi	r3, r10, #13, #1
	lsr	r10, r8, #5
	bfi	r3, r10, #9, #1
	lsr	r10, r1, #16
	bfi	r8, r10, #5, #1
	lsr	r10, r3, #23
	bfi	r1, r10, #16, #1
	lsr	r10, r2, #5
	bfi	r3, r10, #23, #1
	lsr	r10, r4, #22
	bfi	r2, r10, #5, #1
	bfi	r4, r9, #22, #1
	mov	r9, r1
	lsr	r10, r4, #3
	bfi	r1, r10, #0, #1
	lsr	r10, r4, #12
	bfi	r4, r10, #3, #1
	lsr	r10, r3, #4
	bfi	r4, r10, #12, #1
	lsr	r10, r4, #17
	bfi	r3, r10, #4, #1
	lsr	r10, r3, #24
	bfi	r4, r10, #17, #1
	lsr	r10, r2, #9
	bfi	r3, r10, #24, #1
	lsr	r10, r8, #6
	bfi	r2, r10, #9, #1
	lsr	r10, r1, #20
	bfi	r8, r10, #6, #1
	lsr	r10, r7, #7
	bfi	r1, r10, #20, #1
	lsr	r10, r1, #25
	bfi	r7, r10, #7, #1
	lsr	r10, r2, #15
	bfi	r1, r10, #25, #1
	lsr	r10, r3, #18
	bfi	r2, r10, #15, #1
	lsr	r10, r3, #29
	bfi	r3, r10, #18, #1
	lsr	r10, r2, #29
	bfi	r3, r10, #29, #1
	lsr	r10, r2, #30
	bfi	r2, r10, #29, #1
	lsr	r10, r6, #2
	bfi	r2, r10, #30, #1
	lsr	r10, r1, #6
	bfi	r6, r10, #2, #1
	lsr	r10, r4, #27
	bfi	r1, r10, #6, #1
	lsr	r10, r2, #20
	bfi	r4, r10, #27, #1
	lsr	r10, r7, #6
	bfi	r2, r10, #20, #1
	lsr	r10, r1, #21
	bfi	r7, r10, #6, #1
	lsr	r10, r7, #11
	bfi	r1, r10, #21, #1
	lsr	r10, r5, #9
	bfi	r7, r10, #11, #1
	lsr	r10, r5, #3
	bfi	r5, r10, #9, #1
	lsr	r10, r1, #11
	bfi	r5, r10, #3, #1
	lsr	r10, r3, #3
	bfi	r1, r10, #11, #1
	lsr	r10, r4, #13
	bfi	r3, r10, #3, #1
	lsr	r10, r3, #8
	bfi	r4, r10, #13, #1
	lsr	r10, r8, #1
	bfi	r3, r10, #8, #1
	bfi	r8, r9, #1, #1
	lsr	r9, r3, #1
	lsr	r10, r4, #5
	bfi	r3, r10, #1, #1
	lsr	r10, r4, #20
	bfi	r4, r10, #5, #1
	lsr	r10, r7, #4
	bfi	r4, r10, #20, #1
	lsr	r10, r1, #13
	bfi	r7, r10, #4, #1
	lsr	r10, r3, #11
	bfi	r1, r10, #13, #1
	bfi	r3, r9, #11, #1
	lsr	r9, r2, #1
	lsr	r10, r4, #6
	bfi	r2, r10, #1, #1
	lsr	r10, r4, #24
	bfi	r4, r10, #6, #1
	lsr	r10, r2, #8
	bfi	r4, r10, #24, #1
	lsr	r10, r8, #2
	bfi	r2, r10, #8, #1
	lsr	r10, r1, #4
	bfi	r8, r10, #2, #1
	lsr	r10, r4, #19
	bfi	r1, r10, #4, #1
	bfi	r4, r7, #19, #1
	lsr	r10, r6, #9
	bfi	r7, r10, #0, #1
	lsr	r10, r5, #2
	bfi	r6, r10, #9, #1
	lsr	r10, r1, #7
	bfi	r5, r10, #2, #1
	lsr	r10, r4, #31
	bfi	r1, r10, #7, #1
	lsr	r10, r6, #4
	bfi	r4, r10, #31, #1
	lsr	r10, r1, #14
	bfi	r6, r10, #4, #1
	lsr	r10, r3, #15
	bfi	r1, r10, #14, #1
	lsr	r10, r3, #17
	bfi	r3, r10, #15, #1
	lsr	r10, r3, #25
	bfi	r3, r10, #17, #1
	lsr	r10, r2, #13
	bfi	r3, r10, #25, #1
	lsr	r10, r3, #10
	bfi	r2, r10, #13, #1
	lsr	r10, r8, #9
	bfi	r3, r10, #10, #1
	bfi	r8, r5, #9, #1
	lsr	r10, r6, #11
	bfi	r5, r10, #0, #1
	lsr	r10, r5, #10
	bfi	r6, r10, #11, #1
	lsr	r10, r5, #7
	bfi	r5, r10, #10, #1
	lsr	r10, r1, #27
	bfi	r5, r10, #7, #1
	lsr	r10, r2, #23
	bfi	r1, r10, #27, #1
	lsr	r10, r2, #6
	bfi	r2, r10, #23, #1
	lsr	r10, r4, #26
	bfi	r2, r10, #6, #1
	lsr	r10, r2, #16
	bfi	r4, r10, #26, #1
	lsr	r10, r3, #22
	bfi	r2, r10, #16, #1
	bfi	r3, r9, #22, #1
	lsr	r9, r1, #1
	lsr	r10, r4, #7
	bfi	r1, r10, #1, #1
	lsr	r10, r4, #28
	bfi	r4, r10, #7, #1
	lsr	r10, r2, #24
	bfi	r4, r10, #28, #1
	lsr	r10, r2, #10
	bfi	r2, r10, #24, #1
	lsr	r10, r8, #10
	bfi	r2, r10, #10, #1
	lsr	r10, r5, #4
	bfi	r8, r10, #10, #1
	lsr	r10, r1, #15
	bfi	r5, r10, #4, #1
	lsr	r10, r3, #19
	bfi	r1, r10, #15, #1
	lsr	r10, r7, #1
	bfi	r3, r10, #19, #1
	bfi	r7, r9, #1, #1
	lsr	r9, r2, #2
	lsr	r10, r4, #10
	bfi	r2, r10, #2, #1
	lsr	r10, r8, #8
	bfi	r4, r10, #10, #1
	lsr	r10, r1, #28
	bfi	r8, r10, #8, #1
	lsr	r10, r2, #27
	bfi	r1, r10, #28, #1
	lsr	r10, r2, #22
	bfi	r2, r10, #27, #1
	bfi	r2, r9, #22, #1
	lsr	r9, r2, #3
	lsr	r10, r4, #14
	bfi	r2, r10, #3, #1
	lsr	r10, r3, #12
	bfi	r4, r10, #14, #1
	lsr	r10, r3, #5
	bfi	r3, r10, #12, #1
	lsr	r10, r4, #21
	bfi	r3, r10, #5, #1
	lsr	r10, r7, #8
	bfi	r4, r10, #21, #1
	lsr	r10, r1, #29
	bfi	r7, r10, #8, #1
	lsr	r10, r2, #31
	bfi	r1, r10, #29, #1
	lsr	r10, r6, #6
	bfi	r2, r10, #31, #1
	lsr	r10, r1, #22
	bfi	r6, r10, #6, #1
	bfi	r1, r9, #22, #1
	lsr	r9, r1, #3
	lsr	r10, r4, #15
	bfi	r1, r10, #3, #1
	lsr	r10, r3, #16
	bfi	r4, r10, #15, #1
	lsr	r10, r3, #21
	bfi	r3, r10, #16, #1
	lsr	r10, r7, #9
	bfi	r3, r10, #21, #1
	lsr	r10, r5, #1
	bfi	r7, r10, #9, #1
	bfi	r5, r9, #1, #1
	lsr	r9, r3, #6
	lsr	r10, r4, #25
	bfi	r3, r10, #6, #1
	lsr	r10, r2, #12
	bfi	r4, r10, #25, #1
	bfi	r2, r9, #12, #1
	lsr	r9, r2, #7
	lsr	r10, r4, #30
	bfi	r2, r10, #7, #1
	bfi	r4, r6, #30, #1
	lsr	r10, r6, #10
	bfi	r6, r10, #0, #1
	lsr	r10, r5, #6
	bfi	r6, r10, #10, #1
	lsr	r10, r1, #23
	bfi	r5, r10, #6, #1
	bfi	r1, r9, #23, #1
	lsr	r9, r1, #8
	lsr	r10, r8, #3
	bfi	r1, r10, #8, #1
	bfi	r8, r9, #3, #1
	lsr	r9, r2, #17
	lsr	r10, r3, #26
	bfi	r2, r10, #17, #1
	bfi	r3, r9, #26, #1
	lsr	r9, r1, #18
	lsr	r10, r3, #31
	bfi	r1, r10, #18, #1
	lsr	r10, r6, #5
	bfi	r3, r10, #31, #1
	bfi	r6, r9, #5, #1
	b	.L21
.L22:
	ubfx	r9, r1, #0, #8
	bfi	r9, r2, #8, #8
	bfi	r9, r3, #16, #8
	bfi	r9, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	r10, r1, #8, #8
	bfi	r10, r2, #8, #8
	bfi	r10, r3, #16, #8
	bfi	r10, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	fp, r1, #16, #8
	bfi	fp, r2, #8, #8
	bfi	fp, r3, #16, #8
	bfi	fp, r4, #24, #8
	lsr	r2, r2, #8
	lsr	r3, r3, #8
	lsr	r4, r4, #8
	ubfx	lr, r1, #24, #8
	bfi	lr, r2, #8, #8
	bfi	lr, r3, #16, #8
	bfi	lr, r4, #24, #8
	ubfx	ip, r5, #0, #8
	bfi	ip, r6, #8, #8
	bfi	ip, r7, #16, #8
	bfi	ip, r8, #24, #8
	lsr	r6, r6, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	ubfx	r4, r5, #8, #8
	bfi	r4, r6, #8, #8
	bfi	r4, r7, #16, #8
	bfi	r4, r8, #24, #8
	eor	r1, r9, r9, lsr #9
	and	r1, r1, #5570645
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #9
	eor	r1, r9, r9, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #18
	eor	r1, r9, r9, lsr #12
	and	r1, r1, #983055
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #12
	eor	r1, r9, r9, lsr #24
	and	r1, r1, #255
	eor	r9, r9, r1
	eor	r9, r9, r1, lsl #24
	eor	r1, r10, r10, lsr #9
	and	r1, r1, #5570645
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #9
	eor	r1, r10, r10, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #18
	eor	r1, r10, r10, lsr #12
	and	r1, r1, #983055
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #12
	eor	r1, r10, r10, lsr #24
	and	r1, r1, #255
	eor	r10, r10, r1
	eor	r10, r10, r1, lsl #24
	eor	r1, fp, fp, lsr #9
	and	r1, r1, #5570645
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #9
	eor	r1, fp, fp, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #18
	eor	r1, fp, fp, lsr #12
	and	r1, r1, #983055
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #12
	eor	r1, fp, fp, lsr #24
	and	r1, r1, #255
	eor	fp, fp, r1
	eor	fp, fp, r1, lsl #24
	eor	r1, lr, lr, lsr #9
	and	r1, r1, #5570645
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #9
	eor	r1, lr, lr, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #18
	eor	r1, lr, lr, lsr #12
	and	r1, r1, #983055
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #12
	eor	r1, lr, lr, lsr #24
	and	r1, r1, #255
	eor	lr, lr, r1
	eor	lr, lr, r1, lsl #24
	eor	r1, ip, ip, lsr #9
	and	r1, r1, #5570645
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #9
	eor	r1, ip, ip, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #18
	eor	r1, ip, ip, lsr #12
	and	r1, r1, #983055
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #12
	eor	r1, ip, ip, lsr #24
	and	r1, r1, #255
	eor	ip, ip, r1
	eor	ip, ip, r1, lsl #24
	eor	r1, r4, r4, lsr #9
	and	r1, r1, #5570645
	eor	r4, r4, r1
	eor	r4, r4, r1, lsl #9
	eor	r1, r4, r4, lsr #18
	movw	r2, #13107
	and	r1, r1, r2
	eor	r4, r4, r1
	eor	r4, r4, r1, lsl #18
	eor	r1, r4, r4, lsr #12
	and	r1, r1, #983055
	eor	r4, r4, r1
	eor	r4, r4, r1, lsl #12
	eor	r1, r4, r4, lsr #24
	and	r1, r1, #255
	eor	r4, r4, r1
	eor	r4, r4, r1, lsl #24
	pop	{r0}
	str	r9, [r0]
	str	r10, [r0, #4]
	str	fp, [r0, #8]
	str	lr, [r0, #12]
	str	ip, [r0, #16]
	strh	r4, [r0, #20]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	spongent176_permute, .-spongent176_permute

#endif
