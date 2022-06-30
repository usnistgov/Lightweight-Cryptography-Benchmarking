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
	.global	grain128_core
	.thumb
	.thumb_func
	.type	grain128_core, %function
grain128_core:
	push	{r4, r5, r6, r7, lr}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	eors	r1, r3
	eor	r1, r1, r3, lsl #7
	eor	r1, r1, r4, lsr #25
	eor	r1, r1, r4, lsl #6
	eor	r1, r1, r5, lsr #26
	eor	r1, r1, r5, lsl #6
	eor	r1, r1, r6, lsr #26
	eor	r1, r1, r5, lsl #17
	eor	r1, r1, r6, lsr #15
	eors	r1, r6
	str	r4, [r0, #0]
	str	r5, [r0, #4]
	str	r6, [r0, #8]
	str	r1, [r0, #12]
	eors	r2, r3
	ldr	r3, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	eors	r2, r3
	eor	r2, r2, r3, lsl #26
	eor	r2, r2, r4, lsr #6
	eor	r2, r2, r4, lsl #24
	eor	r2, r2, r5, lsr #8
	eor	r2, r2, r5, lsl #27
	eor	r2, r2, r6, lsr #5
	eors	r2, r6
	lsl	r7, r3, #3
	lsl	r1, r5, #3
	eor	r7, r7, r4, lsr #29
	eor	r1, r1, r6, lsr #29
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r3, #11
	lsl	r1, r3, #13
	eor	r7, r7, r4, lsr #21
	eor	r1, r1, r4, lsr #19
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r3, #17
	lsl	r1, r3, #18
	eor	r7, r7, r4, lsr #15
	eor	r1, r1, r4, lsr #14
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r3, #27
	lsl	r1, r4, #27
	eor	r7, r7, r4, lsr #5
	eor	r1, r1, r5, lsr #5
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r4, #8
	lsl	r1, r4, #16
	eor	r7, r7, r5, lsr #24
	eor	r1, r1, r5, lsr #16
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r4, #29
	lsl	r1, r5, #1
	eor	r7, r7, r5, lsr #3
	eor	r1, r1, r6, lsr #31
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r5, #4
	lsl	r1, r5, #20
	eor	r7, r7, r6, lsr #28
	eor	r1, r1, r6, lsr #12
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r3, #22
	lsl	r1, r3, #24
	eor	r7, r7, r4, lsr #10
	eor	r1, r1, r4, lsr #8
	ands	r7, r1
	lsl	r1, r3, #25
	eor	r1, r1, r4, lsr #7
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r5, #6
	lsl	r1, r5, #14
	eor	r7, r7, r6, lsr #26
	eor	r1, r1, r6, lsr #18
	ands	r7, r1
	lsl	r1, r5, #18
	eor	r1, r1, r6, lsr #14
	ands	r7, r1
	eors	r2, r7
	lsl	r7, r5, #24
	lsl	r1, r5, #28
	eor	r7, r7, r6, lsr #8
	eor	r1, r1, r6, lsr #4
	ands	r7, r1
	lsl	r1, r5, #29
	eor	r1, r1, r6, lsr #3
	ands	r7, r1
	lsl	r1, r5, #31
	eor	r1, r1, r6, lsr #1
	ands	r7, r1
	eors	r2, r7
	str	r4, [r0, #16]
	str	r5, [r0, #20]
	str	r6, [r0, #24]
	str	r2, [r0, #28]
	pop	{r4, r5, r6, r7, pc}
	.size	grain128_core, .-grain128_core

	.align	2
	.global	grain128_preoutput
	.thumb
	.thumb_func
	.type	grain128_preoutput, %function
grain128_preoutput:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	lsl	r9, r5, #12
	eor	r9, r9, r6, lsr #20
	lsl	r10, r7, #31
	eor	r10, r10, r8, lsr #1
	lsl	r0, r1, #8
	eor	r0, r0, r2, lsr #24
	and	r0, r9
	lsl	ip, r1, #13
	lsl	fp, r1, #20
	eor	ip, ip, r2, lsr #19
	eor	fp, fp, r2, lsr #12
	and	ip, fp
	eor	r0, ip
	lsl	ip, r2, #10
	eor	ip, ip, r3, lsr #22
	and	ip, r10
	eor	r0, ip
	lsl	ip, r2, #28
	lsl	fp, r3, #15
	eor	ip, ip, r3, lsr #4
	eor	fp, fp, r4, lsr #17
	and	ip, fp
	eor	r0, ip
	and	r9, r10
	lsl	ip, r3, #30
	eor	ip, ip, r4, lsr #2
	and	r9, ip
	eor	r0, r9
	eor	r0, r0, r3, lsl #29
	eor	r0, r0, r4, lsr #3
	eor	r0, r0, r5, lsl #2
	eor	r0, r0, r6, lsr #30
	eor	r0, r0, r5, lsl #15
	eor	r0, r0, r6, lsr #17
	eor	r0, r0, r6, lsl #4
	eor	r0, r0, r7, lsr #28
	eor	r0, r0, r6, lsl #13
	eor	r0, r0, r7, lsr #19
	eors	r0, r7
	eor	r0, r0, r7, lsl #9
	eor	r0, r0, r8, lsr #23
	eor	r0, r0, r7, lsl #25
	eor	r0, r0, r8, lsr #7
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	grain128_preoutput, .-grain128_preoutput

	.align	2
	.global	grain128_next_keystream
	.thumb
	.thumb_func
	.type	grain128_next_keystream, %function
grain128_next_keystream:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	lsl	r9, r5, #12
	eor	r9, r9, r6, lsr #20
	lsl	lr, r7, #31
	eor	lr, lr, r8, lsr #1
	lsl	r10, r1, #8
	eor	r10, r10, r2, lsr #24
	and	r10, r9
	lsl	ip, r1, #13
	lsl	fp, r1, #20
	eor	ip, ip, r2, lsr #19
	eor	fp, fp, r2, lsr #12
	and	ip, fp
	eor	r10, ip
	lsl	ip, r2, #10
	eor	ip, ip, r3, lsr #22
	and	ip, lr
	eor	r10, ip
	lsl	ip, r2, #28
	lsl	fp, r3, #15
	eor	ip, ip, r3, lsr #4
	eor	fp, fp, r4, lsr #17
	and	ip, fp
	eor	r10, ip
	and	r9, lr
	lsl	ip, r3, #30
	eor	ip, ip, r4, lsr #2
	and	r9, ip
	eor	r10, r9
	eor	r10, r10, r3, lsl #29
	eor	r10, r10, r4, lsr #3
	eor	r10, r10, r5, lsl #2
	eor	r10, r10, r6, lsr #30
	eor	r10, r10, r5, lsl #15
	eor	r10, r10, r6, lsr #17
	eor	r10, r10, r6, lsl #4
	eor	r10, r10, r7, lsr #28
	eor	r10, r10, r6, lsl #13
	eor	r10, r10, r7, lsr #19
	eor	r10, r7
	eor	r10, r10, r7, lsl #9
	eor	r10, r10, r8, lsr #23
	eor	r10, r10, r7, lsl #25
	eor	r10, r10, r8, lsr #7
	eor	ip, r10, r10, lsr #3
	and	ip, ip, #286331153
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #3
	eor	ip, r10, r10, lsr #6
	and	ip, ip, #50529027
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #6
	eor	ip, r10, r10, lsr #12
	and	ip, ip, #983055
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #12
	rev16	r10, r10
	rev	r10, r10
	str	r10, [r0, #48]
	mov	r10, r1
	eor	r10, r10, r1, lsl #7
	eor	r10, r10, r2, lsr #25
	eor	r10, r10, r2, lsl #6
	eor	r10, r10, r3, lsr #26
	eor	r10, r10, r3, lsl #6
	eor	r10, r10, r4, lsr #26
	eor	r10, r10, r3, lsl #17
	eor	r10, r10, r4, lsr #15
	eor	r10, r4
	mov	lr, r1
	mov	r1, r10
	eor	lr, r5
	eor	lr, lr, r5, lsl #26
	eor	lr, lr, r6, lsr #6
	eor	lr, lr, r6, lsl #24
	eor	lr, lr, r7, lsr #8
	eor	lr, lr, r7, lsl #27
	eor	lr, lr, r8, lsr #5
	eor	lr, r8
	lsl	ip, r5, #3
	lsl	fp, r7, #3
	eor	ip, ip, r6, lsr #29
	eor	fp, fp, r8, lsr #29
	and	ip, fp
	eor	lr, ip
	lsl	ip, r5, #11
	lsl	fp, r5, #13
	eor	ip, ip, r6, lsr #21
	eor	fp, fp, r6, lsr #19
	and	ip, fp
	eor	lr, ip
	lsl	ip, r5, #17
	lsl	fp, r5, #18
	eor	ip, ip, r6, lsr #15
	eor	fp, fp, r6, lsr #14
	and	ip, fp
	eor	lr, ip
	lsl	ip, r5, #27
	lsl	fp, r6, #27
	eor	ip, ip, r6, lsr #5
	eor	fp, fp, r7, lsr #5
	and	ip, fp
	eor	lr, ip
	lsl	ip, r6, #8
	lsl	fp, r6, #16
	eor	ip, ip, r7, lsr #24
	eor	fp, fp, r7, lsr #16
	and	ip, fp
	eor	lr, ip
	lsl	ip, r6, #29
	lsl	fp, r7, #1
	eor	ip, ip, r7, lsr #3
	eor	fp, fp, r8, lsr #31
	and	ip, fp
	eor	lr, ip
	lsl	ip, r7, #4
	lsl	fp, r7, #20
	eor	ip, ip, r8, lsr #28
	eor	fp, fp, r8, lsr #12
	and	ip, fp
	eor	lr, ip
	lsl	ip, r5, #22
	lsl	fp, r5, #24
	eor	ip, ip, r6, lsr #10
	eor	fp, fp, r6, lsr #8
	and	ip, fp
	lsl	fp, r5, #25
	eor	fp, fp, r6, lsr #7
	and	ip, fp
	eor	lr, ip
	lsl	ip, r7, #6
	lsl	fp, r7, #14
	eor	ip, ip, r8, lsr #26
	eor	fp, fp, r8, lsr #18
	and	ip, fp
	lsl	fp, r7, #18
	eor	fp, fp, r8, lsr #14
	and	ip, fp
	eor	lr, ip
	lsl	ip, r7, #24
	lsl	fp, r7, #28
	eor	ip, ip, r8, lsr #8
	eor	fp, fp, r8, lsr #4
	and	ip, fp
	lsl	fp, r7, #29
	eor	fp, fp, r8, lsr #3
	and	ip, fp
	lsl	fp, r7, #31
	eor	fp, fp, r8, lsr #1
	and	ip, fp
	eor	lr, ip
	lsl	r9, r6, #12
	eor	r9, r9, r7, lsr #20
	lsl	r5, r8, #31
	eor	r5, r5, lr, lsr #1
	lsl	r10, r2, #8
	eor	r10, r10, r3, lsr #24
	and	r10, r9
	lsl	ip, r2, #13
	lsl	fp, r2, #20
	eor	ip, ip, r3, lsr #19
	eor	fp, fp, r3, lsr #12
	and	ip, fp
	eor	r10, ip
	lsl	ip, r3, #10
	eor	ip, ip, r4, lsr #22
	and	ip, r5
	eor	r10, ip
	lsl	ip, r3, #28
	lsl	fp, r4, #15
	eor	ip, ip, r4, lsr #4
	eor	fp, fp, r1, lsr #17
	and	ip, fp
	eor	r10, ip
	and	r9, r5
	lsl	ip, r4, #30
	eor	ip, ip, r1, lsr #2
	and	r9, ip
	eor	r10, r9
	eor	r10, r10, r4, lsl #29
	eor	r10, r10, r1, lsr #3
	eor	r10, r10, r6, lsl #2
	eor	r10, r10, r7, lsr #30
	eor	r10, r10, r6, lsl #15
	eor	r10, r10, r7, lsr #17
	eor	r10, r10, r7, lsl #4
	eor	r10, r10, r8, lsr #28
	eor	r10, r10, r7, lsl #13
	eor	r10, r10, r8, lsr #19
	eor	r10, r8
	eor	r10, r10, r8, lsl #9
	eor	r10, r10, lr, lsr #23
	eor	r10, r10, r8, lsl #25
	eor	r10, r10, lr, lsr #7
	eor	ip, r10, r10, lsr #3
	and	ip, ip, #286331153
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #3
	eor	ip, r10, r10, lsr #6
	and	ip, ip, #50529027
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #6
	eor	ip, r10, r10, lsr #12
	and	ip, ip, #983055
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #12
	rev16	r10, r10
	rev	r10, r10
	str	r10, [r0, #52]
	mov	r10, r2
	eor	r10, r10, r2, lsl #7
	eor	r10, r10, r3, lsr #25
	eor	r10, r10, r3, lsl #6
	eor	r10, r10, r4, lsr #26
	eor	r10, r10, r4, lsl #6
	eor	r10, r10, r1, lsr #26
	eor	r10, r10, r4, lsl #17
	eor	r10, r10, r1, lsr #15
	eor	r10, r1
	movs	r5, r2
	mov	r2, r10
	eors	r5, r6
	eor	r5, r5, r6, lsl #26
	eor	r5, r5, r7, lsr #6
	eor	r5, r5, r7, lsl #24
	eor	r5, r5, r8, lsr #8
	eor	r5, r5, r8, lsl #27
	eor	r5, r5, lr, lsr #5
	eor	r5, lr
	lsl	ip, r6, #3
	lsl	fp, r8, #3
	eor	ip, ip, r7, lsr #29
	eor	fp, fp, lr, lsr #29
	and	ip, fp
	eor	r5, ip
	lsl	ip, r6, #11
	lsl	fp, r6, #13
	eor	ip, ip, r7, lsr #21
	eor	fp, fp, r7, lsr #19
	and	ip, fp
	eor	r5, ip
	lsl	ip, r6, #17
	lsl	fp, r6, #18
	eor	ip, ip, r7, lsr #15
	eor	fp, fp, r7, lsr #14
	and	ip, fp
	eor	r5, ip
	lsl	ip, r6, #27
	lsl	fp, r7, #27
	eor	ip, ip, r7, lsr #5
	eor	fp, fp, r8, lsr #5
	and	ip, fp
	eor	r5, ip
	lsl	ip, r7, #8
	lsl	fp, r7, #16
	eor	ip, ip, r8, lsr #24
	eor	fp, fp, r8, lsr #16
	and	ip, fp
	eor	r5, ip
	lsl	ip, r7, #29
	lsl	fp, r8, #1
	eor	ip, ip, r8, lsr #3
	eor	fp, fp, lr, lsr #31
	and	ip, fp
	eor	r5, ip
	lsl	ip, r8, #4
	lsl	fp, r8, #20
	eor	ip, ip, lr, lsr #28
	eor	fp, fp, lr, lsr #12
	and	ip, fp
	eor	r5, ip
	lsl	ip, r6, #22
	lsl	fp, r6, #24
	eor	ip, ip, r7, lsr #10
	eor	fp, fp, r7, lsr #8
	and	ip, fp
	lsl	fp, r6, #25
	eor	fp, fp, r7, lsr #7
	and	ip, fp
	eor	r5, ip
	lsl	ip, r8, #6
	lsl	fp, r8, #14
	eor	ip, ip, lr, lsr #26
	eor	fp, fp, lr, lsr #18
	and	ip, fp
	lsl	fp, r8, #18
	eor	fp, fp, lr, lsr #14
	and	ip, fp
	eor	r5, ip
	lsl	ip, r8, #24
	lsl	fp, r8, #28
	eor	ip, ip, lr, lsr #8
	eor	fp, fp, lr, lsr #4
	and	ip, fp
	lsl	fp, r8, #29
	eor	fp, fp, lr, lsr #3
	and	ip, fp
	lsl	fp, r8, #31
	eor	fp, fp, lr, lsr #1
	and	ip, fp
	eor	r5, ip
	lsl	r9, r7, #12
	eor	r9, r9, r8, lsr #20
	lsl	r6, lr, #31
	eor	r6, r6, r5, lsr #1
	lsl	r10, r3, #8
	eor	r10, r10, r4, lsr #24
	and	r10, r9
	lsl	ip, r3, #13
	lsl	fp, r3, #20
	eor	ip, ip, r4, lsr #19
	eor	fp, fp, r4, lsr #12
	and	ip, fp
	eor	r10, ip
	lsl	ip, r4, #10
	eor	ip, ip, r1, lsr #22
	and	ip, r6
	eor	r10, ip
	lsl	ip, r4, #28
	lsl	fp, r1, #15
	eor	ip, ip, r1, lsr #4
	eor	fp, fp, r2, lsr #17
	and	ip, fp
	eor	r10, ip
	and	r9, r6
	lsl	ip, r1, #30
	eor	ip, ip, r2, lsr #2
	and	r9, ip
	eor	r10, r9
	eor	r10, r10, r1, lsl #29
	eor	r10, r10, r2, lsr #3
	eor	r10, r10, r7, lsl #2
	eor	r10, r10, r8, lsr #30
	eor	r10, r10, r7, lsl #15
	eor	r10, r10, r8, lsr #17
	eor	r10, r10, r8, lsl #4
	eor	r10, r10, lr, lsr #28
	eor	r10, r10, r8, lsl #13
	eor	r10, r10, lr, lsr #19
	eor	r10, lr
	eor	r10, r10, lr, lsl #9
	eor	r10, r10, r5, lsr #23
	eor	r10, r10, lr, lsl #25
	eor	r10, r10, r5, lsr #7
	eor	ip, r10, r10, lsr #3
	and	ip, ip, #286331153
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #3
	eor	ip, r10, r10, lsr #6
	and	ip, ip, #50529027
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #6
	eor	ip, r10, r10, lsr #12
	and	ip, ip, #983055
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #12
	rev16	r10, r10
	rev	r10, r10
	str	r10, [r0, #56]
	mov	r10, r3
	eor	r10, r10, r3, lsl #7
	eor	r10, r10, r4, lsr #25
	eor	r10, r10, r4, lsl #6
	eor	r10, r10, r1, lsr #26
	eor	r10, r10, r1, lsl #6
	eor	r10, r10, r2, lsr #26
	eor	r10, r10, r1, lsl #17
	eor	r10, r10, r2, lsr #15
	eor	r10, r2
	movs	r6, r3
	mov	r3, r10
	eors	r6, r7
	eor	r6, r6, r7, lsl #26
	eor	r6, r6, r8, lsr #6
	eor	r6, r6, r8, lsl #24
	eor	r6, r6, lr, lsr #8
	eor	r6, r6, lr, lsl #27
	eor	r6, r6, r5, lsr #5
	eors	r6, r5
	lsl	ip, r7, #3
	lsl	fp, lr, #3
	eor	ip, ip, r8, lsr #29
	eor	fp, fp, r5, lsr #29
	and	ip, fp
	eor	r6, ip
	lsl	ip, r7, #11
	lsl	fp, r7, #13
	eor	ip, ip, r8, lsr #21
	eor	fp, fp, r8, lsr #19
	and	ip, fp
	eor	r6, ip
	lsl	ip, r7, #17
	lsl	fp, r7, #18
	eor	ip, ip, r8, lsr #15
	eor	fp, fp, r8, lsr #14
	and	ip, fp
	eor	r6, ip
	lsl	ip, r7, #27
	lsl	fp, r8, #27
	eor	ip, ip, r8, lsr #5
	eor	fp, fp, lr, lsr #5
	and	ip, fp
	eor	r6, ip
	lsl	ip, r8, #8
	lsl	fp, r8, #16
	eor	ip, ip, lr, lsr #24
	eor	fp, fp, lr, lsr #16
	and	ip, fp
	eor	r6, ip
	lsl	ip, r8, #29
	lsl	fp, lr, #1
	eor	ip, ip, lr, lsr #3
	eor	fp, fp, r5, lsr #31
	and	ip, fp
	eor	r6, ip
	lsl	ip, lr, #4
	lsl	fp, lr, #20
	eor	ip, ip, r5, lsr #28
	eor	fp, fp, r5, lsr #12
	and	ip, fp
	eor	r6, ip
	lsl	ip, r7, #22
	lsl	fp, r7, #24
	eor	ip, ip, r8, lsr #10
	eor	fp, fp, r8, lsr #8
	and	ip, fp
	lsl	fp, r7, #25
	eor	fp, fp, r8, lsr #7
	and	ip, fp
	eor	r6, ip
	lsl	ip, lr, #6
	lsl	fp, lr, #14
	eor	ip, ip, r5, lsr #26
	eor	fp, fp, r5, lsr #18
	and	ip, fp
	lsl	fp, lr, #18
	eor	fp, fp, r5, lsr #14
	and	ip, fp
	eor	r6, ip
	lsl	ip, lr, #24
	lsl	fp, lr, #28
	eor	ip, ip, r5, lsr #8
	eor	fp, fp, r5, lsr #4
	and	ip, fp
	lsl	fp, lr, #29
	eor	fp, fp, r5, lsr #3
	and	ip, fp
	lsl	fp, lr, #31
	eor	fp, fp, r5, lsr #1
	and	ip, fp
	eor	r6, ip
	lsl	r9, r8, #12
	eor	r9, r9, lr, lsr #20
	lsl	r7, r5, #31
	eor	r7, r7, r6, lsr #1
	lsl	r10, r4, #8
	eor	r10, r10, r1, lsr #24
	and	r10, r9
	lsl	ip, r4, #13
	lsl	fp, r4, #20
	eor	ip, ip, r1, lsr #19
	eor	fp, fp, r1, lsr #12
	and	ip, fp
	eor	r10, ip
	lsl	ip, r1, #10
	eor	ip, ip, r2, lsr #22
	and	ip, r7
	eor	r10, ip
	lsl	ip, r1, #28
	lsl	fp, r2, #15
	eor	ip, ip, r2, lsr #4
	eor	fp, fp, r3, lsr #17
	and	ip, fp
	eor	r10, ip
	and	r9, r7
	lsl	ip, r2, #30
	eor	ip, ip, r3, lsr #2
	and	r9, ip
	eor	r10, r9
	eor	r10, r10, r2, lsl #29
	eor	r10, r10, r3, lsr #3
	eor	r10, r10, r8, lsl #2
	eor	r10, r10, lr, lsr #30
	eor	r10, r10, r8, lsl #15
	eor	r10, r10, lr, lsr #17
	eor	r10, r10, lr, lsl #4
	eor	r10, r10, r5, lsr #28
	eor	r10, r10, lr, lsl #13
	eor	r10, r10, r5, lsr #19
	eor	r10, r5
	eor	r10, r10, r5, lsl #9
	eor	r10, r10, r6, lsr #23
	eor	r10, r10, r5, lsl #25
	eor	r10, r10, r6, lsr #7
	eor	ip, r10, r10, lsr #3
	and	ip, ip, #286331153
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #3
	eor	ip, r10, r10, lsr #6
	and	ip, ip, #50529027
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #6
	eor	ip, r10, r10, lsr #12
	and	ip, ip, #983055
	eor	r10, r10, ip
	eor	r10, r10, ip, lsl #12
	rev16	r10, r10
	rev	r10, r10
	str	r10, [r0, #60]
	mov	r10, r4
	eor	r10, r10, r4, lsl #7
	eor	r10, r10, r1, lsr #25
	eor	r10, r10, r1, lsl #6
	eor	r10, r10, r2, lsr #26
	eor	r10, r10, r2, lsl #6
	eor	r10, r10, r3, lsr #26
	eor	r10, r10, r2, lsl #17
	eor	r10, r10, r3, lsr #15
	eor	r10, r3
	movs	r7, r4
	mov	r4, r10
	eor	r7, r8
	eor	r7, r7, r8, lsl #26
	eor	r7, r7, lr, lsr #6
	eor	r7, r7, lr, lsl #24
	eor	r7, r7, r5, lsr #8
	eor	r7, r7, r5, lsl #27
	eor	r7, r7, r6, lsr #5
	eors	r7, r6
	lsl	ip, r8, #3
	lsl	fp, r5, #3
	eor	ip, ip, lr, lsr #29
	eor	fp, fp, r6, lsr #29
	and	ip, fp
	eor	r7, ip
	lsl	ip, r8, #11
	lsl	fp, r8, #13
	eor	ip, ip, lr, lsr #21
	eor	fp, fp, lr, lsr #19
	and	ip, fp
	eor	r7, ip
	lsl	ip, r8, #17
	lsl	fp, r8, #18
	eor	ip, ip, lr, lsr #15
	eor	fp, fp, lr, lsr #14
	and	ip, fp
	eor	r7, ip
	lsl	ip, r8, #27
	lsl	fp, lr, #27
	eor	ip, ip, lr, lsr #5
	eor	fp, fp, r5, lsr #5
	and	ip, fp
	eor	r7, ip
	lsl	ip, lr, #8
	lsl	fp, lr, #16
	eor	ip, ip, r5, lsr #24
	eor	fp, fp, r5, lsr #16
	and	ip, fp
	eor	r7, ip
	lsl	ip, lr, #29
	lsl	fp, r5, #1
	eor	ip, ip, r5, lsr #3
	eor	fp, fp, r6, lsr #31
	and	ip, fp
	eor	r7, ip
	lsl	ip, r5, #4
	lsl	fp, r5, #20
	eor	ip, ip, r6, lsr #28
	eor	fp, fp, r6, lsr #12
	and	ip, fp
	eor	r7, ip
	lsl	ip, r8, #22
	lsl	fp, r8, #24
	eor	ip, ip, lr, lsr #10
	eor	fp, fp, lr, lsr #8
	and	ip, fp
	lsl	fp, r8, #25
	eor	fp, fp, lr, lsr #7
	and	ip, fp
	eor	r7, ip
	lsl	ip, r5, #6
	lsl	fp, r5, #14
	eor	ip, ip, r6, lsr #26
	eor	fp, fp, r6, lsr #18
	and	ip, fp
	lsl	fp, r5, #18
	eor	fp, fp, r6, lsr #14
	and	ip, fp
	eor	r7, ip
	lsl	ip, r5, #24
	lsl	fp, r5, #28
	eor	ip, ip, r6, lsr #8
	eor	fp, fp, r6, lsr #4
	and	ip, fp
	lsl	fp, r5, #29
	eor	fp, fp, r6, lsr #3
	and	ip, fp
	lsl	fp, r5, #31
	eor	fp, fp, r6, lsr #1
	and	ip, fp
	eor	r7, ip
	str	r1, [r0, #0]
	str	r2, [r0, #4]
	str	r3, [r0, #8]
	str	r4, [r0, #12]
	str	lr, [r0, #16]
	str	r5, [r0, #20]
	str	r6, [r0, #24]
	str	r7, [r0, #28]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	grain128_next_keystream, .-grain128_next_keystream

#endif
