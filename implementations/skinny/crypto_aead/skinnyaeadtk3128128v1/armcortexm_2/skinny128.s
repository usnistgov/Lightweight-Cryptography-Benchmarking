/*******************************************************************************
* Constant-time ARM assembly implementation of the SKINNY block cipher.
* Two blocks are processed in parallel.
* 
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     April 2020
*******************************************************************************/

.syntax unified
.thumb

/*******************************************************************************
* Applies P^2 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p2:
	movw 	r3, #0xcc00
	movt 	r3, #0xcc00 				//r1 <- 0xcc00cc00
	movw 	r4, #0xcc00
	movt 	r4, #0x0033 				//r10<- 0xcc000033
	and 	r1, r3, r5, ror #14
	bfi 	r1, r5, #16, #8
	and 	r2, r5, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r5
	orr 	r1, r1, r2, lsr #8
	and 	r2, r5, #0x00cc0000
	orr 	r5, r1, r2, lsr #18
	and 	r1, r3, r6, ror #14
	bfi 	r1, r6, #16, #8
	and 	r2, r6, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r6
	orr 	r1, r1, r2, lsr #8
	and 	r2, r6, #0x00cc0000
	orr 	r6, r1, r2, lsr #18
	and 	r1, r3, r7, ror #14
	bfi 	r1, r7, #16, #8
	and 	r2, r7, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r7
	orr 	r1, r1, r2, lsr #8
	and 	r2, r7, #0x00cc0000
	orr 	r7, r1, r2, lsr #18
	and 	r1, r3, r8, ror #14
	bfi 	r1, r8, #16, #8
	and 	r2, r8, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r8
	orr 	r1, r1, r2, lsr #8
	and 	r2, r8, #0x00cc0000
	orr 	r8, r1, r2, lsr #18
	and 	r1, r3, r9, ror #14
	bfi 	r1, r9, #16, #8
	and 	r2, r9, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r9
	orr 	r1, r1, r2, lsr #8
	and 	r2, r9, #0x00cc0000
	orr 	r9, r1, r2, lsr #18
	and 	r1, r3, r10, ror #14
	bfi 	r1, r10, #16, #8
	and 	r2, r10, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r10
	orr 	r1, r1, r2, lsr #8
	and 	r2, r10, #0x00cc0000
	orr 	r10, r1, r2, lsr #18
	and 	r1, r3, r11, ror #14
	bfi 	r1, r11, #16, #8
	and 	r2, r11, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r11
	orr 	r1, r1, r2, lsr #8
	and 	r2, r11, #0x00cc0000
	orr 	r11, r1, r2, lsr #18
	and 	r1, r3, r12, ror #14
	bfi 	r1, r12, #16, #8
	and 	r2, r12, #0xcc000000
	orr 	r1, r1, r2, lsr #2
	and 	r2, r4, r12
	orr 	r1, r1, r2, lsr #8
	and 	r2, r12, #0x00cc0000
	orr 	r12, r1, r2, lsr #18
	bx 		lr

/*******************************************************************************
* Applies P^4 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p4:
	str.w 	r14, [sp] 					//store r14 on the stack
	movw 	r14, #0x00cc
	movt 	r14, #0xcc00 				//r14<- 0xcc0000cc
	movw 	r3, #0xcc00
	movt 	r3, #0x3300 				//r3 <- 0x3300cc00
	movw 	r4, #0x00cc
	movt 	r4, #0x00cc 				//r4 <- 0x00cc00cc
 	and 	r2, r14, r5, ror #22
 	and 	r1, r3, r5, ror #16
 	orr 	r2, r2,  r1
 	and 	r1, r5, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r5, r5, r1
 	orr 	r5, r2, r5, ror #24
 	and 	r2, r14, r6, ror #22
 	and 	r1, r3, r6, ror #16
 	orr 	r2, r2,  r1
 	and 	r1, r6, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r6, r6, r1
 	orr 	r6, r2, r6, ror #24
 	and 	r2, r14, r7, ror #22
 	and 	r1, r3, r7, ror #16
 	orr 	r2, r2, r1
 	and 	r1, r7, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r7, r7, r1
 	orr 	r7, r2, r7, ror #24
 	and 	r2, r14, r8, ror #22
 	and 	r1, r3, r8, ror #16
 	orr 	r2, r2, r1
 	and 	r1, r8, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r8, r8, r1
 	orr 	r8, r2, r8, ror #24
 	and 	r2, r14, r9, ror #22
 	and 	r1, r3, r9, ror #16
 	orr 	r2, r2, r1
 	and 	r1, r9, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r9, r9, r1
 	orr 	r9, r2, r9, ror #24
 	and 	r2, r14, r10, ror #22
 	and 	r1, r3, r10, ror #16
 	orr 	r2, r2,  r1
 	and 	r1, r10, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r10, r10, r1
 	orr 	r10, r2, r10, ror #24
 	and 	r2, r14, r11, ror #22
 	and 	r1, r3, r11, ror #16
 	orr 	r2, r2,  r1
 	and 	r1, r11, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r11, r11, r1
 	orr 	r11, r2, r11, ror #24
 	and 	r2, r14, r12, ror #22
 	and 	r1, r3, r12, ror #16
 	orr 	r2, r2,  r1
 	and 	r1, r12, r4
 	orr 	r2, r2, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r12, r12, r1
 	orr 	r12, r2, r12, ror #24
 	ldr.w 	r14, [sp] 					//restore r14
 	bx 		lr

/*******************************************************************************
* Applies P^6 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p6:
	movw 	r3, #0x3333 				//r1 <- 0x00003333
	movw 	r4, #0x00cc
	movt 	r4, #0x3300 				//r12<- 0x330000cc
	and 	r1, r5, r3, ror #8 		// --- permute r5 6 times
	and 	r2, r4, r5, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r5, ror #10
	orr 	r2, r2, r1
	and 	r1, r5, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r5, #0x00003300
	orr 	r5, r2, r1, lsl #2 		// permute r5 6 times ---
	and 	r1, r6, r3, ror #8 		// --- permute r6 6 times
	and 	r2, r4, r6, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r6, ror #10
	orr 	r2, r2, r1
	and 	r1, r6, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r6, #0x00003300
	orr 	r6, r2, r1, lsl #2 		// permute r6 6 times ---
	and 	r1, r7, r3, ror #8 		// --- permute r7 6 times
	and 	r2, r4, r7, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r7, ror #10
	orr 	r2, r2, r1
	and 	r1, r7, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r7, #0x00003300
	orr 	r7, r2, r1, lsl #2 		// permute r7 6 times ---
	and 	r1, r8, r3, ror #8 		// --- permute r8 6 times
	and 	r2, r4, r8, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r8, ror #10
	orr 	r2, r2, r1
	and 	r1, r8, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r8, #0x00003300
	orr 	r8, r2, r1, lsl #2 		// permute r8 6 times ---
	and 	r1, r9, r3, ror #8 		// --- permute r9 6 times
	and 	r2, r4, r9, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r9, ror #10
	orr 	r2, r2, r1
	and 	r1, r9, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r9, #0x00003300
	orr 	r9, r2, r1, lsl #2 		 	// permute r9 6 times ---
	and 	r1, r10, r3, ror #8 		// --- permute r10 6 times
	and 	r2, r4, r10, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r10, ror #10
	orr 	r2, r2, r1
	and 	r1, r10, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r10, #0x00003300
	orr 	r10, r2, r1, lsl #2 	 	// permute r10 6 times ---
	and 	r1, r11, r3, ror #8 		// --- permute r11 6 times
	and 	r2, r4, r11, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r11, ror #10
	orr 	r2, r2, r1
	and 	r1, r11, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r11, #0x00003300
	orr 	r11, r2, r1, lsl #2 	 	// permute r11 6 times ---
	and 	r1, r12, r3, ror #8 		// --- permute r12 6 times
	and 	r2, r4, r12, ror #24
	orr 	r2, r2, r1, ror #6
	and 	r1, r3, r12, ror #10
	orr 	r2, r2, r1
	and 	r1, r12, #0x000000cc
	orr 	r2, r2, r1, lsl #14
	and 	r1, r12, #0x00003300
	orr 	r12, r2, r1, lsl #2 	 	// permute r12 6 times ---
 	bx 		lr

/*******************************************************************************
* Applies P^8 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p8:
	movw 	r3, #0x3333 				//r3 <- 0x00003333
	movw 	r4, #0x0000
	movt 	r4, #0x33cc 				//r4 <- 0x33cc0000
	and 	r1, r5, r4 				// --- permute r5 8 times
	and 	r2, r4, r5, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r5, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r5, r3, lsl #8
	orr 	r5, r2, r1, lsr #6 		// permute r5 8 times ---
	and 	r1, r6, r4 				// --- permute r6 8 times
	and 	r2, r4, r6, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r6, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r6, r3, lsl #8
	orr 	r6, r2, r1, lsr #6 		// permute r6 8 times ---
	and 	r1, r7, r4 				// --- permute r7 8 times
	and 	r2, r4, r7, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r7, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r7, r3, lsl #8
	orr 	r7, r2, r1, lsr #6 		// permute r7 8 times ---
	and 	r1, r8, r4 				// --- permute r8 8 times
	and 	r2, r4, r8, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r8, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r8, r3, lsl #8
	orr 	r8, r2, r1, lsr #6 		// permute r8 8 times ---
	and 	r1, r9, r4 				// --- permute r9 8 times
	and 	r2, r4, r9, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r9, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r9, r3, lsl #8
	orr 	r9, r2, r1, lsr #6 		// permute r9 8 times ---
	and 	r1, r10, r4 			// --- permute r10 8 times
	and 	r2, r4, r10, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r10, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r10, r3, lsl #8
	orr 	r10, r2, r1, lsr #6 		// permute r10 8 times ---
	and 	r1, r11, r4 			// --- permute r11 8 times
	and 	r2, r4, r11, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r11, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r11, r3, lsl #8
	orr 	r11, r2, r1, lsr #6 		// permute r11 8 times ---
	and 	r1, r12, r4 			// --- permute r12 8 times
	and 	r2, r4, r12, ror #8
	orr 	r2, r2, r1, ror #24
	and 	r1, r12, r3, lsl #2
	orr 	r2, r2, r1, ror #26
	and 	r1, r12, r3, lsl #8
	orr 	r12, r2, r1, lsr #6 		// permute r12 8 times ---
 	bx 		lr

/*******************************************************************************
* Applies P^10 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p10:
	movw 	r4, #0x0033
	movt 	r4, #0x3300 				//r4 <- 0x33000033
	movw 	r3, #0xcc33 				//r3 <- 0x0000cc33
	and 	r1, r5, r3, ror #8 		// --- permute r5 10 times
	and 	r2, r4, r5, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r5, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r5, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r5, #0x0000cc00
	orr 	r5, r2, r1, lsr #2 		// permute r5 10 times ---
	and 	r1, r6, r3, ror #8 		// --- permute r6 10 times
	and 	r2, r4, r6, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r6, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r6, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r6, #0x0000cc00
	orr 	r6, r2, r1, lsr #2 		// permute r6 10 times ---
	and 	r1, r7, r3, ror #8 		// --- permute r7 10 times
	and 	r2, r4, r7, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r7, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r7, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r7, #0x0000cc00
	orr 	r7, r2, r1, lsr #2 		// permute r7 10 times ---
	and 	r1, r8, r3, ror #8 		// --- permute r8 10 times
	and 	r2, r4, r8, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r8, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r8, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r8, #0x0000cc00
	orr 	r8, r2, r1, lsr #2 		// permute r8 10 times ---
	and 	r1, r9, r3, ror #8 		// --- permute r9 10 times
	and 	r2, r4, r9, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r9, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r9, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r9, #0x0000cc00
	orr 	r9, r2, r1, lsr #2 		// permute r9 10 times ---
	and 	r1, r10, r3, ror #8 	// --- permute r10 10 times
	and 	r2, r4, r10, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r10, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r10, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r10, #0x0000cc00
	orr 	r10, r2, r1, lsr #2 	// permute r10 10 times ---
	and 	r1, r11, r3, ror #8 	// --- permute r11 10 times
	and 	r2, r4, r11, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r11, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r11, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r11, #0x0000cc00
	orr 	r11, r2, r1, lsr #2 	// permute r11 10 times ---
	and 	r1, r12, r3, ror #8 	// --- permute r12 10 times
	and 	r2, r4, r12, ror #26
	orr 	r2, r2, r1, ror #8
	and 	r1, r12, r4, ror #24
	orr 	r2, r2, r1, ror #22
	and 	r1, r12, #0x00330000
	orr 	r2, r2, r1, lsr #14
	and 	r1, r12, #0x0000cc00
	orr 	r12, r2, r1, lsr #2 	// permute r12 10 times ---
 	bx 		lr

/*******************************************************************************
* Applies P^12 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p12:
	str.w 	r14, [sp] 					//store r14 on the stack
	movw 	r14, #0xcc33 				//r14<- 0x0000cc33
	movw 	r4, #0x00cc
	movt 	r4, #0x00cc 				//r4 <- 0x00cc00cc
	movw 	r3, #0x3300
	movt 	r3, #0xcc00 				//r3 <- 0xcc003300
	and 	r1, r14, r5, ror #8 		// --- permute r5 12 times
	and 	r2, r4, r5, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r5, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r5, r1, ror #8
	orr 	r5, r2, r1, ror #10 		// permute r5 12 times ---
	and 	r1, r14, r6, ror #8 		// --- permute r6 12 times
	and 	r2, r4, r6, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r6, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r6, r1, ror #8
	orr 	r6, r2, r1, ror #10 		// permute r6 12 times ---
	and 	r1, r14, r7, ror #8 		// --- permute r7 12 times
	and 	r2, r4, r7, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r7, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r7, r1, ror #8
	orr 	r7, r2, r1, ror #10 		// permute r7 12 times ---
	and 	r1, r14, r8, ror #8 		// --- permute r8 12 times
	and 	r2, r4, r8, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r8, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r8, r1, ror #8
	orr 	r8, r2, r1, ror #10 		// permute r8 12 times ---
	and 	r1, r14, r9, ror #8 		// --- permute r9 12 times
	and 	r2, r4, r9, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r9, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r9, r1, ror #8
	orr 	r9, r2, r1, ror #10 		// permute r9 12 times ---
	and 	r1, r14, r10, ror #8 		// --- permute r10 12 times
	and 	r2, r4, r10, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r10, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r10, r1, ror #8
	orr 	r10, r2, r1, ror #10 		// permute r10 12 times ---
	and 	r1, r14, r11, ror #8 		// --- permute r11 12 times
	and 	r2, r4, r11, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r11, ror #16
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r11, r1, ror #8
	orr 	r11, r2, r1, ror #10 		// permute r11 12 times ---
	and 	r1, r14, r12, ror #8 		// --- permute r12 12 times
	and 	r2, r4, r12, ror #30
	orr 	r2, r2, r1
	and 	r1, r3, r12, ror #16
	ldr.w 	r14, [sp]
	orr 	r2, r2, r1
	movw 	r1, #0xcccc 				//r1 <- 0x0000cccc
	and 	r1, r12, r1, ror #8
	orr 	r12, r2, r1, ror #10 		// permute r12 12 times ---
 	bx 		lr

/*******************************************************************************
* Applies P^14 on the tweakey state in a bitsliced manner.
*******************************************************************************/
.align 	2
p14:
	movw 	r3, #0xcc00
	movt 	r3, #0x0033 				//r3 <- 0x0033cc00
	movw 	r4, #0xcc00
	movt 	r4, #0xcc00 				//r4 <- 0x33003300
	and 	r1, r3, r5, ror #24 		// --- permute r5 14 times
	and 	r2, r5, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r5, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r5, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r5, r4
	orr 	r5, r2, r1, ror #18 		// permute r5 14 times ---
	and 	r1, r3, r6, ror #24 		// --- permute r6 14 times
	and 	r2, r6, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r6, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r6, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r6, r4
	orr 	r6, r2, r1, ror #18 		// permute r6 14 times ---
	and 	r1, r3, r7, ror #24 		// --- permute r7 14 times
	and 	r2, r7, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r7, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r7, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r7, r4
	orr 	r7, r2, r1, ror #18 		// permute r7 14 times ---
	and 	r1, r3, r8, ror #24 		// --- permute r8 14 times
	and 	r2, r8, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r8, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r8, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r8, r4
	orr 	r8, r2, r1, ror #18 		// permute r8 14 times ---
	and 	r1, r3, r9, ror #24 		// --- permute r9 14 times
	and 	r2, r9, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r9, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r9, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r9, r4
	orr 	r9, r2, r1, ror #18 		// permute r9 14 times ---
	and 	r1, r3, r10, ror #24 		// --- permute r10 14 times
	and 	r2, r10, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r10, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r10, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r10, r4
	orr 	r10, r2, r1, ror #18 		// permute r10 14 times ---
	and 	r1, r3, r11, ror #24 		// --- permute r11 14 times
	and 	r2, r11, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r11, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r11, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r11, r4
	orr 	r11, r2, r1, ror #18 		// permute r11 14 times ---
	and 	r1, r3, r12, ror #24 		// --- permute r12 14 times
	and 	r2, r12, #0x00000033
	orr 	r2, r1, r2, ror #14
	and 	r1, r12, #0x33000000
	orr 	r2, r2, r1, ror #30
	and 	r1, r12, #0x00ff0000
	orr 	r2, r2, r1, ror #16
	and 	r1, r12, r4
	orr 	r12, r2, r1, ror #18 		// permute r12 14 times ---
 	bx 		lr

/*******************************************************************************
* Packs the input byte array into the fixsliced representation.
*******************************************************************************/
.align 2
packing:
	eor 	r4, r5, r6, lsr #1
	and 	r4, r4, r2
	eor 	r5, r5, r4
	eor 	r6, r6, r4, lsl #1 		//SWAPMOVE(r6, r5, 0x55555555, 1)
	eor 	r4, r7, r8, lsr #1
	and 	r4, r4, r2
	eor 	r7, r7, r4
	eor 	r8, r8, r4, lsl #1 		//SWAPMOVE(r8, r7, 0x55555555, 1)
	eor 	r4, r9, r10, lsr #1
	and 	r4, r4, r2
	eor 	r9, r9, r4
	eor 	r10, r10, r4, lsl #1 	//SWAPMOVE(r10, r9, 0x55555555, 1)
	eor 	r4, r11, r12, lsr #1
	and 	r4, r4, r2
	eor 	r11, r11, r4
	eor 	r12, r12, r4, lsl #1 	//SWAPMOVE(r12, r11, 0x55555555, 1)
	eor 	r4, r5, r7, lsr #2
	and 	r4, r4, r3
	eor 	r5, r5, r4
	eor 	r7, r7, r4, lsl #2 		//SWAPMOVE(r7, r5, 0x30303030, 2)
	eor 	r4, r5, r9, lsr #4
	and 	r4, r4, r3, lsr #2
	eor 	r5, r5, r4
	eor 	r9, r9, r4, lsl #4 		//SWAPMOVE(r9, r5, 0x0c0c0c0c, 4)
	eor 	r4, r5, r11, lsr #6
	and 	r4, r4, r3, lsr #4
	eor 	r5, r5, r4
	eor 	r11, r11, r4, lsl #6 	//SWAPMOVE(r11, r5, 0x03030303, 6)
	eor 	r4, r6, r8, lsr #2
	and 	r4, r4, r3
	eor 	r6, r6, r4
	eor 	r8, r8, r4, lsl #2 		//SWAPMOVE(r8, r6, 0x30303030, 2)
	eor 	r4, r6, r10, lsr #4
	and 	r4, r4, r3, lsr #2
	eor 	r6, r6, r4
	eor 	r10, r10, r4, lsl #4 	//SWAPMOVE(r10, r6, 0x0c0c0c0c, 4)
	eor 	r4, r6, r12, lsr #6
	and 	r4, r4, r3, lsr #4
	eor 	r6, r6, r4
	eor 	r12, r12, r4, lsl #6 	//SWAPMOVE(r12, r6, 0x03030303, 6)
	eor 	r4, r7, r9, lsr #2
	and 	r4, r4, r3, lsr #2
	eor 	r7, r7, r4
	eor 	r9, r9, r4, lsl #2 		//SWAPMOVE(r9, r7, 0x0c0c0c0c, 2)
	eor 	r4, r7, r11, lsr #4
	and 	r4, r4, r3, lsr #4
	eor 	r7, r7, r4
	eor 	r11, r11, r4, lsl #4 	//SWAPMOVE(r11, r7, 0x03030303, 4)
	eor 	r4, r8, r10, lsr #2
	and 	r4, r4, r3, lsr #2
	eor 	r8, r8, r4
	eor 	r10, r10, r4, lsl #2 	//SWAPMOVE(r10, r8, 0x0c0c0c0c, 2)
	eor 	r4, r8, r12, lsr #4
	and 	r4, r4, r3, lsr #4
	eor 	r8, r8, r4
	eor 	r12, r12, r4, lsl #4	//SWAPMOVE(r12, r8, 0x03030303, 4)
	eor 	r4, r9, r11, lsr #2
	and 	r4, r4, r3, lsr #4
	eor 	r9, r9, r4
	eor 	r11, r11, r4, lsl #2	//SWAPMOVE(r11, r9, 0x03030303, 2)
	eor 	r4, r10, r12, lsr #2
	and 	r4, r4, r3, lsr #4
	eor 	r10, r10, r4
	eor 	r12, r12, r4, lsl #2	//SWAPMOVE(r12, r10, 0x03030303, 2)
	bx 		lr

/*******************************************************************************
* Unpacks the internal state in fixsliced representation into a byte array.
*******************************************************************************/
.align 2
unpacking:
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//r3 <- 0x30303030
	eor 	r4, r9, r11, lsr #2
	and 	r4, r4, r3, lsr #4
	eor 	r9, r9, r4
	eor 	r11, r11, r4, lsl #2	//SWAPMOVE(r11, r9, 0x03030303, 2)
	eor 	r4, r10, r12, lsr #2
	and 	r4, r4, r3, lsr #4
	eor 	r10, r10, r4
	eor 	r12, r12, r4, lsl #2	//SWAPMOVE(r12, r10, 0x03030303, 2)
	eor 	r4, r8, r10, lsr #2
	and 	r4, r4, r3, lsr #2
	eor 	r8, r8, r4
	eor 	r10, r10, r4, lsl #2 	//SWAPMOVE(r10, r8, 0x0c0c0c0c, 2)
	eor 	r4, r8, r12, lsr #4
	and 	r4, r4, r3, lsr #4
	eor 	r8, r8, r4
	eor 	r12, r12, r4, lsl #4	//SWAPMOVE(r12, r8, 0x03030303, 4)
	eor 	r4, r7, r9, lsr #2
	and 	r4, r4, r3, lsr #2
	eor 	r7, r7, r4
	eor 	r9, r9, r4, lsl #2 		//SWAPMOVE(r9, r7, 0x0c0c0c0c, 2)
	eor 	r4, r7, r11, lsr #4
	and 	r4, r4, r3, lsr #4
	eor 	r7, r7, r4
	eor 	r11, r11, r4, lsl #4 	//SWAPMOVE(r11, r7, 0x03030303, 4)
	eor 	r4, r6, r12, lsr #6
	and 	r4, r4, r3, lsr #4
	eor 	r6, r6, r4
	eor 	r12, r12, r4, lsl #6 	//SWAPMOVE(r12, r6, 0x03030303, 6)
	eor 	r4, r6, r10, lsr #4
	and 	r4, r4, r3, lsr #2
	eor 	r6, r6, r4
	eor 	r10, r10, r4, lsl #4 	//SWAPMOVE(r10, r6, 0x0c0c0c0c, 4)
	eor 	r4, r6, r8, lsr #2
	and 	r4, r4, r3
	eor 	r6, r6, r4
	eor 	r8, r8, r4, lsl #2 		//SWAPMOVE(r8, r6, 0x30303030, 2)
	eor 	r4, r5, r11, lsr #6
	and 	r4, r4, r3, lsr #4
	eor 	r5, r5, r4
	eor 	r11, r11, r4, lsl #6 	//SWAPMOVE(r11, r5, 0x03030303, 6)
	eor 	r4, r5, r9, lsr #4
	and 	r4, r4, r3, lsr #2
	eor 	r5, r5, r4
	eor 	r9, r9, r4, lsl #4 		//SWAPMOVE(r9, r5, 0x0c0c0c0c, 4)
	eor 	r4, r5, r7, lsr #2
	and 	r4, r4, r3
	eor 	r5, r5, r4
	eor 	r7, r7, r4, lsl #2 		//SWAPMOVE(r7, r5, 0x30303030, 2)
	eor 	r4, r5, r6, lsr #1
	and 	r4, r4, r2
	eor 	r5, r5, r4
	eor 	r6, r6, r4, lsl #1 		//SWAPMOVE(r6, r5, 0x55555555, 1)
	eor 	r4, r7, r8, lsr #1
	and 	r4, r4, r2
	eor 	r7, r7, r4
	eor 	r8, r8, r4, lsl #1 		//SWAPMOVE(r8, r7, 0x55555555, 1)
	eor 	r4, r9, r10, lsr #1
	and 	r4, r4, r2
	eor 	r9, r9, r4
	eor 	r10, r10, r4, lsl #1 	//SWAPMOVE(r10, r9, 0x55555555, 1)
	eor 	r4, r11, r12, lsr #1
	and 	r4, r4, r2
	eor 	r11, r11, r4
	eor 	r12, r12, r4, lsl #1 	//SWAPMOVE(r12, r11, 0x55555555, 1)
	bx 		lr



/******************************************************************************
* Compute TK = LFSR2(TK2) for all rounds.
******************************************************************************/
@ void 	tkschedule_lfsr_2(u32* rtk, const u8* tk2, const u8* tk2_bis, const int rounds)
.global tkschedule_lfsr_2
.type   tkschedule_lfsr_2,%function
.align	2
tkschedule_lfsr_2:
	push 	{r0-r12, r14}
	ldm 	r1, {r5,r7,r9,r11} 		// load the 1st block in r5,r7,r9,r11
	ldm 	r2, {r6,r8,r10,r12} 	// load the 2nd block in r6,r8,r10,r12
	mov.w 	r1, r3 					//load loop counter in r1
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//r3 <- 0x30303030
	bl 		packing
	stmia 	r0!, {r5-r12}
	loop_2:
		eor 	r5, r5, r7			// apply LFSR2 to tk2
		stmia 	r0!, {r6-r12}
		str.w 	r5, [r0], #36
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r6, r6, r8			// apply LFSR2 to tk2
		stmia 	r0!, {r7-r12}
		strd 	r5, r6, [r0], #40
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r7, r7, r9			// apply LFSR2 to tk2
		stmia 	r0!, {r8-r12}
		stmia 	r0!, {r5-r7}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r8, r8, r10			// apply LFSR2 to tk2
		stmia 	r0!, {r9-r12}
		stmia 	r0!, {r5-r8}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r9, r9, r11			// apply LFSR2 to tk2
		stmia 	r0!, {r10-r12}
		stmia 	r0!, {r5-r9}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r10, r10, r12		// apply LFSR2 to tk2
		strd 	r11, r12, [r0], #8
		stmia 	r0!, {r5-r10}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r11, r11, r5		// apply LFSR2 to tk2
		str.w 	r12, [r0], #4
		stmia 	r0!, {r5-r11}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// r1 = 0 => we are done
		eor 	r12, r12, r6		// apply LFSR2 to tk2
		stmia 	r0!, {r5-r12}
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		bne 	loop_2 				// if not 0 then we run the loop again
	exit_lfsr:
		pop 	{r0-r12, r14}
		bx 		lr


/******************************************************************************
* Compute TK ^= LFSR3(TK3) for all rounds.
******************************************************************************/
@ void 	tkschedule_lfsr_3(u32* rtk, const u8* tk2, const u8* tk2_bis,
@						const int rounds)
.global tkschedule_lfsr_3
.type   tkschedule_lfsr_3,%function
.align	2
tkschedule_lfsr_3:
	push 	{r0-r12, r14}
	ldm 	r1, {r5,r7,r9,r11} 		// load the 1st block in r5,r7,r9,r11
	ldm 	r2, {r6,r8,r10,r12} 	// load the 2nd block in r6,r8,r10,r12
	mov.w 	r1, r3 					//load loop counter in r1
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//r3 <- 0x30303030
	bl 		packing
	ldm 	r0, {r2-r4,r14} 		// load rtk (computed by tkschedule_lfsr_2)
	eor 	r2, r2, r5 				// rtk <- tk2 ^ tk3
	eor 	r3, r3, r6 				// rtk <- tk2 ^ tk3
	eor 	r4, r4, r7 				// rtk <- tk2 ^ tk3
	eor 	r14, r14, r8 			// rtk <- tk2 ^ tk3
	stmia 	r0!, {r2-r4,r14} 		// store rtk after adding tk3
	ldm 	r0, {r2-r4,r14} 		// load rtk (computed by tkschedule_lfsr_2)
	eor 	r2, r2, r9 				// rtk <- tk2 ^ tk3
	eor 	r3, r3, r10 			// rtk <- tk2 ^ tk3
	eor 	r4, r4, r11 			// rtk <- tk2 ^ tk3
	eor 	r14, r14, r12 			// rtk <- tk2 ^ tk3
	stmia 	r0!, {r2-r4,r14} 		// store rtk after adding tk3
	loop_3:
		eor 	r12, r12, r6		// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r12 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r5 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r6 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r7 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r8 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r9 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r10 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r11 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r11, r11, r5		// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r11 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r12 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r5 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r6 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r7 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r8 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r9 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r10 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r10, r10, r12		// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r10 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r11 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r12 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r5 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r6 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r7 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r8 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r9 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r9, r9, r11			// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r9 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r10 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r11 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r12 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r5 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r6 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r7 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r8 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r8, r8, r10			// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r8 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r9 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r10 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r11 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r12 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r5 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r6 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r7 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r7, r7, r9			// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r7 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r8 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r9 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r10 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r11 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r12 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r5 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r6 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r6, r6, r8			// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r6 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r7 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r8 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r9 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r10 		// rtk <- tk2 ^ tk3
		eor 	r3, r3, r11 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r12 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r5 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 2
		beq 	exit_lfsr 			// if 0 then we are done
		eor 	r5, r5, r7			// apply LFSR3 to tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r5 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r6 			// rtk <- tk2 ^ tk3
		eor 	r4, r4, r7 			// rtk <- tk2 ^ tk3
		eor 	r14, r14, r8 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		ldm 	r0, {r2-r4,r14} 	// load rtk (computed by tkschedule_lfsr_2)
		eor 	r2, r2, r9 			// rtk <- tk2 ^ tk3
		eor 	r3, r3, r10 		// rtk <- tk2 ^ tk3
		eor 	r4, r4, r11 		// rtk <- tk2 ^ tk3
		eor 	r14, r14, r12 		// rtk <- tk2 ^ tk3
		stmia 	r0!, {r2-r4,r14} 	// store rtk after adding tk3
		add 	r0, r0, #32 		// same round tweakey every 2 rounds
		subs 	r1, r1, #2 			// decrease loop counter by 8
		bne 	loop_3
	pop 	{r0-r12, r14}
	bx 		lr

/******************************************************************************
* Compute TK = rearrange(perm(TK ^ TK1)) for all rounds.
* The function 'rearrange' aims at reording bits for all round tweakeys to
* match the fixsliced implementation of the SKINNY block cipher.
******************************************************************************/
@ void 	tkschedule_perm(u32* rtk)
.global tkschedule_perm
.type   tkschedule_perm,%function
.align	2
tkschedule_perm:
	push 	{r0-r12, r14}
	sub.w 	sp, #4 					// to store 'lr' during subroutines
	movw 	r4, #0xf0f0
	movt 	r4, #0xf0f0
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000000c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000c0 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	and 	r3, r4, r11, ror #26
	mvn 	r1, r1
	eor 	r2, r2, #0x00000300
	eor 	r3, r3, #0x00000300
	eor 	r3, r3, #0x30000000
	mvn 	r3, r3
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #26
	and 	r2, r4, r6, ror #26
	and 	r3, r4, r7, ror #26
	mvn 	r1, r1
	mvn 	r2, r2
	mvn 	r3, r3
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1
	stmia.w r0!, {r1-r2}
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x0c000000 	// add rconst
	str.w 	r8, [r0], #4
	stmia 	r0!, {r7,r9,r12}
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	str.w 	r10, [r0], #4
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xcc000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	stmia 	r0!, {r5,r6,r11}
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p4 						// apply the permutation 4 times
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x00cc0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x00c00000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00f00000 	// add rconst
	eor 	r9, r9, #0x00c00000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p6
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00c00000 	// add rconst
	eor 	r3, r3, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	eor 	r9, r9, #0x00000c00 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000c00 	// add rconst
	eor 	r12, r12, #0x03000000 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x00000c00 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x0000c000 	// add rconst
	eor 	r11, r11, #0x03000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p8
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000c30 	// add rconst
	eor 	r3, r3, #0x00000c30 	// add rconst
	eor 	r3, r3, #0x00030000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00000030 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x000000fc 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x000000c0 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000f0 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p10
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	eor 	r1, r1, #0x00000300 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00000300 	// add rconst
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r11, ror #26
	and 	r2, r4, r10, ror #26
	eor 	r1, r1, #0x30000000 	// add rconst
	eor 	r1, r1, #0x000003c0 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00000300 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r6, ror #26
	and 	r2, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	eor 	r9, r9, #0x0c000000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000300 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xcc000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p12
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r3, r3, #0x0c000000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	eor 	r2, r2, #0x0c000000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x003c0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00f00000 	// add rconst
	strd 	r8, r12, [r0], #8
	eor 	r9, r9, #0x00c00000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p14
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000c00 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x00000c00 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x0000cc00 	// add rconst
	eor 	r11, r11, #0x03000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r3, r3, #0x00000030 	// add rconst
	eor 	r3, r3, #0x00030000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000030 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00000030 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000000c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x000000c0 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000f0 	// add rconst
	strd 	r8, r12, [r0], #8
	eor 	r9, r9, #0x000000c0 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	and 	r3, r4, r11, ror #26
	eor 	r1, r1, #0x00000300 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x000000c0 	// add rconst
	eor 	r3, r3, #0x000003c0 	// add rconst
	eor 	r3, r3, #0x30000000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #26
	and 	r2, r4, r6, ror #26
	and 	r3, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r2}
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x0c000000 	// add rconst
	eor 	r12, r12, #0x00000300 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xc0000000 	// add rconst
	eor 	r11, r11, #0x00000300 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p4 						// apply the permutation 4 times
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x0c300000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x00cc0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x00c00000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00300000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p6
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	eor 	r9, r9, #0x00000c00 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x03000000 	// add rconst
	strd 	r9, r12, [r0], #8
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x0000c000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p8
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000c00 	// add rconst
	eor 	r3, r3, #0x00030c00 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000003c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000c0 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p10
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r11, ror #26
	and 	r2, r4, r10, ror #26
	eor 	r1, r1, #0x30000000 	// add rconst
	eor 	r1, r1, #0x00000300 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r6, ror #26
	and 	r2, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x0c000000 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xc0000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p12
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r3, r3, #0x00300000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x00cc0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x00c00000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00f00000 	// add rconst
	strd 	r8, r12, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p14
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	eor 	r9, r9, #0x00000c00 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x03000000 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x00000c00 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x0000c000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000c00 	// add rconst
	eor 	r3, r3, #0x00030c00 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00000030 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000003c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000f0 	// add rconst
	strd 	r8, r12, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	and 	r3, r4, r11, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00000300 	// add rconst
	eor 	r3, r3, #0x000003c0 	// add rconst
	eor 	r3, r3, #0x30000000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #26
	and 	r2, r4, r6, ror #26
	and 	r3, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r2}
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xcc000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p4 						// apply the permutation 4 times
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r3, r3, #0x00300000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x00cc0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00f00000 	// add rconst
	eor 	r9, r9, #0x00c00000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p6
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00c00000 	// add rconst
	eor 	r3, r3, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	eor 	r1, r1, #0x03000000 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	eor 	r9, r9, #0x00000c00 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000c00 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x00000c00 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x03000000 	// add rconst
	eor 	r11, r11, #0x0000c000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p8
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000c00 	// add rconst
	eor 	r3, r3, #0x00000030 	// add rconst
	eor 	r3, r3, #0x00030000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00000030 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	// COMMENT HERE FOR SKINNY-128-128
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000003c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	eor 	r10, r10, #0x000000c0 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000030 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p10
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	eor 	r1, r1, #0x00000300 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00000300 	// add rconst
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r11, ror #26
	and 	r2, r4, r10, ror #26
	eor 	r1, r1, #0x30000000 	// add rconst
	eor 	r1, r1, #0x000000c0 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r6, ror #26
	and 	r2, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000300 	// add rconst
	strd 	r9, r12, [r0], #8
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xcc000000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p12
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x0c000000 	// add rconst
	eor 	r2, r2, #0x00000003 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r3, r3, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x000c0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r12, [r0], #8
	eor 	r9, r9, #0x00c00000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p14
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	strd 	r9, r12, [r0], #8
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x03000000 	// add rconst
	eor 	r11, r11, #0x0000cc00 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r3, r3, #0x00030000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r1, r1, #0x00000030 	// add rconst
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	// COMMENT HERE FOR SKINNY-128-256
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x0000000c 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r11, r10, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	strd 	r5, r6, [r0], #8
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x000000c0 	// add rconst
	strd 	r8, r12, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r9, r9, #0x000000c0 	// add rconst
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	and 	r3, r4, r11, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x000003c0 	// add rconst
	eor 	r3, r3, #0x00000300 	// add rconst
	eor 	r3, r3, #0x30000000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #26
	and 	r2, r4, r6, ror #26
	and 	r3, r4, r7, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r2}
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #28 	// --- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #12
	and 	r1, r4, r6, ror #28
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #12
	and 	r1, r4, r7, ror #28
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #12
	and 	r1, r4, r8, ror #28
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #12
	and 	r1, r4, r9, ror #28
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #12
	and 	r1, r4, r10, ror #28
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #12
	and 	r1, r4, r11, ror #28
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #12
	and 	r1, r4, r12, ror #28
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #12 	// ror and masks to match fixslicing ---
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x0c000000 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0xcc000000 	// add rconst
	eor 	r11, r11, #0x00000300 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 		p4 						// apply the permutation 4 times
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00000003 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	eor 	r2, r2, #0x00300000 	// add rconst
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00300000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r5, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r6, r4, r6, ror #16  	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r7, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r8, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r9, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r10, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r11, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r12, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	eor 	r11, r11, #0x000c0000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00f00000 	// add rconst
	eor 	r9, r9, #0x00c00000 	// add rconst
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	mvn 	r7, r7
	strd 	r11, r10, [r0], #8
	strd 	r5, r6, [r0], #8
	strd 	r8, r12, [r0], #8
	strd 	r9, r7, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p6
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r2, r2, #0x00c00000 	// add rconst
	eor 	r3, r3, #0x03c00000 	// add rconst
	eor 	r3, r3, #0x00003000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r2, r2 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r5, ror #12 	//--- ror and masks to match fixslicing
	and 	r5, r5, r4, lsl #6
	orr 	r5, r1, r5, ror #28
	and 	r1, r4, r6, ror #12
	and 	r6, r6, r4, lsl #6
	orr 	r6, r1, r6, ror #28
	and 	r1, r4, r7, ror #12
	and 	r7, r7, r4, lsl #6
	orr 	r7, r1, r7, ror #28
	and 	r1, r4, r8, ror #12
	and 	r8, r8, r4, lsl #6
	orr 	r8, r1, r8, ror #28
	and 	r1, r4, r9, ror #12
	and 	r9, r9, r4, lsl #6
	orr 	r9, r1, r9, ror #28
	and 	r1, r4, r10, ror #12
	and 	r10, r10, r4, lsl #6
	orr 	r10, r1, r10, ror #28
	and 	r1, r4, r11, ror #12
	and 	r11, r11, r4, lsl #6
	orr 	r11, r1, r11, ror #28
	and 	r1, r4, r12, ror #12
	and 	r12, r12, r4, lsl #6
	orr 	r12, r1, r12, ror #28		//ror and masks to match fixslicing ---
	mvn 	r7, r7 					// to save 1 NOT in Sbox calculations
	mvn 	r8, r8 					// to save 1 NOT in Sbox calculations
	strd 	r8, r7, [r0], #8
	mvn 	r9, r9 					// to save 1 NOT in Sbox calculations
	eor 	r12, r12, #0x00000c00 	// add rconst
	strd 	r9, r12, [r0], #8
	eor 	r10, r10, #0x00000c00 	// add rconst
	mvn 	r10, r10 				// to save 1 NOT in Sbox calculations
	strd 	r10, r5, [r0], #8
	mvn 	r6, r6 					// to save 1 NOT in Sbox calculations
	eor 	r11, r11, #0x03000000 	// add rconst
	eor 	r11, r11, #0x0000c000 	// add rconst
	mvn 	r11, r11 				// to save 1 NOT in Sbox calculations
	strd 	r6, r11, [r0], #8
	ldm 	r0, {r5-r12} 			// load rtk = tk1 ^ lfsr2(tk2) ^ lfsr3(tk3)
	bl 	 	p8
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	eor 	r3, r3, #0x00000030 	// add rconst
	eor 	r3, r3, #0x00030000 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	mvn 	r1, r1 					// to save 1 NOT in Sbox calculations
	eor 	r3, r3, #0x00000030 	// add rconst
	mvn 	r3, r3 					// to save 1 NOT in Sbox calculations
	strd 	r1, r3, [r0]
	add.w 	sp, #4
	pop 	{r0-r12, r14}
	bx 		lr

/******************************************************************************
* Compute TK = rearrange(perm(TK ^ TK1)) for all rounds.
* The function 'rearrange' aims at reording bits for all round tweakeys to
* match the fixsliced implementation of the SKINNY block cipher.
******************************************************************************/
@ void 	tkschedule_perm_tk1(u32* rtk)
.global tkschedule_perm_tk1
.type   tkschedule_perm_tk1,%function
.align	2
tkschedule_perm_tk1:
	push 	{r0-r12, r14}
	sub.w 	sp, #32 				// to store packed tk1
	ldm 	r1, {r5,r7,r9,r11} 		// load the 1st block in r5,r7,r9,r11
	ldm 	r2, {r6,r8,r10,r12} 	// load the 1st block in r5,r7,r9,r11
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//	r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//	r3 <- 0x30303030
	bl 		packing
	stm 	sp, {r5-r12}
	movw 	r4, #0xf0f0
	movt 	r4, #0xf0f0
	and 	r1, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	strd 	r1, r2, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	and 	r3, r4, r11, ror #26
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #26
	and 	r2, r4, r6, ror #26
	and 	r3, r4, r7, ror #26
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	stmia.w r0!, {r1-r2}
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r8, ror #28 	// --- ror and masks to match fixslicing
	and 	r2, r8, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r7, ror #28
	and 	r3, r7, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r9, ror #28
	and 	r2, r9, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r12, ror #28
	and 	r3, r12, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r10, ror #28
	and 	r2, r10, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r5, ror #28
	and 	r3, r5, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r6, ror #28
	and 	r2, r6, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r11, ror #28
	and 	r3, r11, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r1, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r6, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	strd 	r1, r2, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r8, ror #12 	// --- ror and masks to match fixslicing
	and 	r2, r8, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r7, ror #12
	and 	r3, r7, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r9, ror #12
	and 	r2, r9, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r12, ror #12
	and 	r3, r12, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r10, ror #12
	and 	r2, r10, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r5, ror #12
	and 	r3, r5, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r6, ror #12
	and 	r2, r6, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r11, ror #12
	and 	r3, r11, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r1, r11, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r10, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r5, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r6, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r8, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r12, r4 			// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r9, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r7, r4 				// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	strd 	r1, r2, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #26
	and 	r2, r4, r12, ror #26
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r11, ror #26
	and 	r2, r4, r10, ror #26
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r6, ror #26
	and 	r2, r4, r7, ror #26
	strd 	r1, r2, [r0], #8
	and 	r1, r4, r8, ror #26
	and 	r2, r4, r5, ror #26
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r8, ror #28 	// --- ror and masks to match fixslicing
	and 	r2, r8, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r7, ror #28
	and 	r3, r7, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r9, ror #28
	and 	r2, r9, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r12, ror #28
	and 	r3, r12, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r10, ror #28
	and 	r2, r10, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r5, ror #28
	and 	r3, r5, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r6, ror #28
	and 	r2, r6, r4, lsl #6
	orr 	r2, r1, r2, ror #12
	and 	r1, r4, r11, ror #28
	and 	r3, r11, r4, lsl #6
	orr 	r3, r1, r3, ror #12
	strd 	r2, r3, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r5, ror #14 	// --- ror and masks to match fixslicing
	and 	r2, r5, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r6, ror #14
	and 	r3, r6, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r7, ror #14
	and 	r2, r7, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r8, ror #14
	and 	r3, r8, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r11, ror #14
	and 	r2, r11, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r12, ror #14
	and 	r3, r12, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	and 	r1, r4, r9, ror #14
	and 	r2, r9, r4, ror #4
	orr 	r2, r1, r2, ror #6
	and 	r1, r4, r10, ror #14
	and 	r3, r10, r4, ror #4
	orr 	r3, r1, r3, ror #6
	strd 	r3, r2, [r0], #8
	orr 	r4, r4, r4, lsl #2 		// r4 <- 0xf0f0f0f0
	and 	r1, r4, r11, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r10, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r4, r5, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r6, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r8, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r3, r4, r12, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	stmia 	r0!, {r1-r3}
	and 	r1, r4, r9, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	and 	r2, r4, r7, ror #16 	// tk &= 0xf0f0f0f0 (extract rows 1&2 only)
	strd 	r1, r2, [r0], #8
	bl 		p2 						// apply the permutation twice
	movw 	r4, #0xc3c3
	movt 	r4, #0xc3c3 			// r4 <- 0xc3c3c3c3
	and 	r1, r4, r9, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r12, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r11, ror #10 	// ror and mask to match fixslicing
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r10, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r6, ror #10 	// ror and mask to match fixslicing
	and 	r3, r4, r7, ror #10 	// ror and mask to match fixslicing
	stmia.w r0!, {r1-r3}
	and 	r1, r4, r8, ror #10 	// ror and mask to match fixslicing
	and 	r2, r4, r5, ror #10 	// ror and mask to match fixslicing
	strd 	r1, r2, [r0], #8
	and 	r4, r4, r4, lsr #6 		// r4 <- 0x03030303
	and 	r1, r4, r8, ror #12 	// --- ror and masks to match fixslicing
	and 	r2, r8, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r7, ror #12
	and 	r3, r7, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r9, ror #12
	and 	r2, r9, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r12, ror #12
	and 	r3, r12, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r10, ror #12
	and 	r2, r10, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r5, ror #12
	and 	r3, r5, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	and 	r1, r4, r6, ror #12
	and 	r2, r6, r4, lsl #6
	orr 	r2, r1, r2, ror #28
	and 	r1, r4, r11, ror #12
	and 	r3, r11, r4, lsl #6
	orr 	r3, r1, r3, ror #28
	strd 	r2, r3, [r0], #8
	ldmia.w sp!, {r5-r12}
	movw 	r4, #0x3030
	movt 	r4, #0x3030 			// r4 <- 0x30303030
	and 	r1, r4, r6, ror #30
	and 	r2, r6, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r5, ror #30
	and 	r2, r5, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r8, ror #30
	and 	r2, r8, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r7, ror #30
	and 	r2, r7, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r12, ror #30
	and 	r2, r12, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r11, ror #30
	and 	r2, r11, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0], #8
	and 	r1, r4, r10, ror #30
	and 	r2, r10, r4, ror #4
	orr 	r1, r1, r2, ror #22
	and 	r3, r4, r9, ror #30
	and 	r2, r9, r4, ror #4
	orr 	r3, r3, r2, ror #22
	strd 	r1, r3, [r0]
	pop 	{r0-r12, r14}
	bx 		lr

/******************************************************************************
* Quadruple round of the SKINNY block cipher in a bitsliced manner.
******************************************************************************/
.align 	2
quadruple_round:
	str.w 	r14, [sp] 				// store r14 on the stack
	orr 	r4, r5, r6 				// state[0] | state[1]
	eor 	r8, r8, r4 				// state[3] ^= (state[0] | state[1])
	orr 	r4, r9, r10 			// state[4] | state[5]
	eor 	r12, r12, r4 			// state[7] ^= (state[4] | state[5])
	orr 	r4, r11, r10 			// state[6] | state[5]
	eor 	r6, r6, r4 				// state[1] ^= (state[6] | state[5])
	and 	r4, r8, r12 			// state[3] & state[7]
	eor 	r7, r7, r4 				// state[2] ^= (state[3] & state[7])
	orn 	r4, r9, r12 			// ~state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (~state[7] | state[4])
	orn 	r4, r7, r6 				// state[2] | ~state[1]
	eor 	r5, r5, r4 				// state[0] ^= (state[2] | ~state[1])
	orn 	r4, r7, r8 				// ~state[3] | state[2]
	eor 	r9, r9, r4 				// state[4] ^= (~state[3] | state[2])
	and 	r4, r5, r11 			// state[0] & state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] & state[0])
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldmia.w r0!, {r2-r4,r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_1
	eor 	r6, r6, r3 				// add rtk_1
	eor 	r7, r7, r4 				// add rtk_1
	eor 	r8, r8, r14 			// add rtk_1
	ldmia.w r0!, {r2-r4, r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_1
	eor 	r10, r10, r3 			// add rtk_1
	eor 	r11, r11, r4 			// add rtk_1
	eor 	r12, r12, r14 			// add rtk_1
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// r2 <- 0x30303030
	and 	r4, r2, r5, ror #30 	// --- mixcolumns
	eor 	r5, r5, r4, ror #24
	and 	r4, r2, r5, ror #18
	eor 	r5, r5, r4, ror #2
	and 	r4, r2, r5, ror #6
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r6, ror #30
	eor 	r6, r6, r4, ror #24
	and 	r4, r2, r6, ror #18
	eor 	r6, r6, r4, ror #2
	and 	r4, r2, r6, ror #6
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r7, ror #30
	eor 	r7, r7, r4, ror #24
	and 	r4, r2, r7, ror #18
	eor 	r7, r7, r4, ror #2
	and 	r4, r2, r7, ror #6
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r8, ror #30
	eor 	r8, r8, r4, ror #24
	and 	r4, r2, r8, ror #18
	eor 	r8, r8, r4, ror #2
	and 	r4, r2, r8, ror #6
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r9, ror #30
	eor 	r9, r9, r4, ror #24
	and 	r4, r2, r9, ror #18
	eor 	r9, r9, r4, ror #2
	and 	r4, r2, r9, ror #6
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r10, ror #30
	eor 	r10, r10, r4, ror #24
	and 	r4, r2, r10, ror #18
	eor 	r10, r10, r4, ror #2
	and 	r4, r2, r10, ror #6
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r11, ror #30
	eor 	r11, r11, r4, ror #24
	and 	r4, r2, r11, ror #18
	eor 	r11, r11, r4, ror #2
	and 	r4, r2, r11, ror #6
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r12, ror #30
	eor 	r12, r12, r4, ror #24
	and 	r4, r2, r12, ror #18
	eor 	r12, r12, r4, ror #2
	and 	r4, r2, r12, ror #6
	eor 	r12, r12, r4, ror #4 	// mixcolumns ---
	orr 	r4, r7, r8 				// state[2] | state[3]
	eor 	r9, r9, r4 				// state[4] ^= (state[2] | state[3])
	orr 	r4, r6, r11 			// state[1] | state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] | state[1])
	orr 	r4, r5, r6 				// state[0] | state[1]
	eor 	r8, r8, r4 				// state[3] ^= (state[0] | state[1])
	and 	r4, r9, r10 			// state[4] & state[5]
	eor 	r12, r12, r4 			// state[7] ^= (state[4] & state[5])
	orn 	r4, r11, r10 			// ~state[5] | state[6]
	eor 	r5, r5, r4 				// state[0] ^= (~state[5] | state[6])
	orn 	r4, r12, r8 			// state[7] | ~state[3]
	eor 	r7, r7, r4 				// state[2] ^= (state[7] | ~state[3])
	orn 	r4, r12, r9 			// state[7] | ~state[4]
	eor 	r11, r11, r4 			// state[6] ^= (~state[4] | state[7])
	and 	r4, r5, r7 				// state[0] & state[2]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] & state[2])
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldmia.w r0!, {r2-r4,r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_1
	eor 	r6, r6, r3 				// add rtk_1
	eor 	r7, r7, r4 				// add rtk_1
	eor 	r8, r8, r14 			// add rtk_1
	ldmia.w r0!, {r2-r4, r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_1
	eor 	r10, r10, r3 			// add rtk_1
	eor 	r11, r11, r4 			// add rtk_1
	eor 	r12, r12, r14 			// add rtk_1
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			//r2 <- 0x30303030
	and 	r4, r2, r5, ror #16 	// --- mixcolumns
	eor 	r5, r5, r4, ror #30
	and 	r4, r2, r5, ror #28
	eor 	r5, r5, r4
	and 	r4, r2, r5, ror #16
	eor 	r5, r5, r4, ror #2
	and 	r4, r2, r6, ror #16
	eor 	r6, r6, r4, ror #30
	and 	r4, r2, r6, ror #28
	eor 	r6, r6, r4
	and 	r4, r2, r6, ror #16
	eor 	r6, r6, r4, ror #2
	and 	r4, r2, r7, ror #16
	eor 	r7, r7, r4, ror #30
	and 	r4, r2, r7, ror #28
	eor 	r7, r7, r4
	and 	r4, r2, r7, ror #16
	eor 	r7, r7, r4, ror #2
	and 	r4, r2, r8, ror #16
	eor 	r8, r8, r4, ror #30
	and 	r4, r2, r8, ror #28
	eor 	r8, r8, r4
	and 	r4, r2, r8, ror #16
	eor 	r8, r8, r4, ror #2
	and 	r4, r2, r9, ror #16
	eor 	r9, r9, r4, ror #30
	and 	r4, r2, r9, ror #28
	eor 	r9, r9, r4
	and 	r4, r2, r9, ror #16
	eor 	r9, r9, r4, ror #2
	and 	r4, r2, r10, ror #16
	eor 	r10, r10, r4, ror #30
	and 	r4, r2, r10, ror #28
	eor 	r10, r10, r4
	and 	r4, r2, r10, ror #16
	eor 	r10, r10, r4, ror #2
	and 	r4, r2, r11, ror #16
	eor 	r11, r11, r4, ror #30
	and 	r4, r2, r11, ror #28
	eor 	r11, r11, r4
	and 	r4, r2, r11, ror #16
	eor 	r11, r11, r4, ror #2
	and 	r4, r2, r12, ror #16
	eor 	r12, r12, r4, ror #30
	and 	r4, r2, r12, ror #28
	eor 	r12, r12, r4
	and 	r4, r2, r12, ror #16
	eor 	r12, r12, r4, ror #2 	// mixcolumns ---
	orr 	r4, r12, r9 			// state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (state[7] | state[4])
	orr 	r4, r5, r8 				// state[0] | state[3]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] | state[3])
	orr 	r4, r7, r8 				// state[2] | state[3]
	eor 	r9, r9, r4 				// state[4] ^= (state[2] | state[3])
	and 	r4, r6, r11 			// state[1] & state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] & state[1])
	orn 	r4, r5, r6 				// ~state[1] | state[0]
	eor 	r7, r7, r4 				// state[2] ^= (~state[1] | state[0])
	orn 	r4, r10, r9 			// state[5] | ~state[4]
	eor 	r12, r12, r4 			// state[7] ^= (state[5] | ~state[4])
	orn 	r4, r10, r11 			// ~state[6] | state[5]
	eor 	r5, r5, r4 				// state[0] ^= (~state[6] | state[5])
	and 	r4, r7, r12 			// state[2] & state[7]
	eor 	r8, r8, r4 				// state[3] ^= (state[2] & state[7])
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldmia.w r0!, {r2-r4,r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_1
	eor 	r6, r6, r3 				// add rtk_1
	eor 	r7, r7, r4 				// add rtk_1
	eor 	r8, r8, r14 			// add rtk_1
	ldmia.w r0!, {r2-r4, r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_1
	eor 	r10, r10, r3 			// add rtk_1
	eor 	r11, r11, r4 			// add rtk_1
	eor 	r12, r12, r14 			// add rtk_1
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// r2 <- 0x30303030
	and 	r4, r2, r5, ror #10 	// --- mixcolumns
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r5, ror #6
	eor 	r5, r5, r4, ror #6
	and 	r4, r2, r5, ror #26
	eor 	r5, r5, r4
	and 	r4, r2, r6, ror #10
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r6, ror #6
	eor 	r6, r6, r4, ror #6
	and 	r4, r2, r6, ror #26
	eor 	r6, r6, r4
	and 	r4, r2, r7, ror #10
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r7, ror #6
	eor 	r7, r7, r4, ror #6
	and 	r4, r2, r7, ror #26
	eor 	r7, r7, r4
	and 	r4, r2, r8, ror #10
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r8, ror #6
	eor 	r8, r8, r4, ror #6
	and 	r4, r2, r8, ror #26
	eor 	r8, r8, r4
	and 	r4, r2, r9, ror #10
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r9, ror #6
	eor 	r9, r9, r4, ror #6
	and 	r4, r2, r9, ror #26
	eor 	r9, r9, r4
	and 	r4, r2, r10, ror #10
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r10, ror #6
	eor 	r10, r10, r4, ror #6
	and 	r4, r2, r10, ror #26
	eor 	r10, r10, r4
	and 	r4, r2, r11, ror #10
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r11, ror #6
	eor 	r11, r11, r4, ror #6
	and 	r4, r2, r11, ror #26
	eor 	r11, r11, r4
	and 	r4, r2, r12, ror #10
	eor 	r12, r12, r4, ror #4
	and 	r4, r2, r12, ror #6
	eor 	r12, r12, r4, ror #6
	and 	r4, r2, r12, ror #26
	eor 	r12, r12, r4 			// mixcolumns ---
	orr 	r4, r10, r11 			// state[5] | state[6]
	eor 	r5, r5, r4 				// state[0] ^= (state[5] | state[6])
	orr 	r4, r7, r9 				// state[2] | state[4]
	eor 	r8, r8, r4 				// state[3] ^= (state[2] | state[4])
	orr 	r4, r9, r12 			// state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (state[7] | state[4])
	and 	r4, r5, r8 				// state[0] & state[3]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] & state[3])
	orn 	r4, r7, r8 				// ~state[3] | state[2]
	eor 	r12, r12, r4 			// state[7] ^= (~state[3] | state[2])
	orn 	r4, r6, r11 			// state[1] | ~state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[1] | ~state[6])
	orn 	r4, r6, r5 				// ~state[0] | state[1]
	eor 	r7, r7, r4 				// state[2] ^= (~state[0] | state[1])
	and 	r4, r12, r10 			// state[7] & state[5]
	eor 	r9, r9, r4 				// state[4] ^= (state[7] & state[5])
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldmia.w r1!, {r2-r4,r14} 		// load rtk_2_3 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldmia.w r0!, {r2-r4,r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r5, r5, r2 				// add rtk_1
	eor 	r6, r6, r3 				// add rtk_1
	eor 	r7, r7, r4 				// add rtk_1
	eor 	r8, r8, r14 			// add rtk_1
	ldmia.w r0!, {r2-r4, r14} 		// load rtk_1 in r0,r2,r3,r4
	eor 	r9, r9, r2 				// add rtk_1
	eor 	r10, r10, r3 			// add rtk_1
	eor 	r11, r11, r4 			// add rtk_1
	eor 	r12, r12, r14 			// add rtk_1
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// r2 <- 0x30303030
	and 	r4, r2, r5, ror #4 		// --- mixcolumns
	eor 	r5, r5, r4, ror #26
	and 	r4, r2, r5
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r5, ror #4
	eor 	r5, r5, r4, ror #22
	and 	r4, r2, r6, ror #4
	eor 	r6, r6, r4, ror #26
	and 	r4, r2, r6
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r6, ror #4
	eor 	r6, r6, r4, ror #22
	and 	r4, r2, r7, ror #4
	eor 	r7, r7, r4, ror #26
	and 	r4, r2, r7
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r7, ror #4
	eor 	r7, r7, r4, ror #22
	and 	r4, r2, r8, ror #4
	eor 	r8, r8, r4, ror #26
	and 	r4, r2, r8
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r8, ror #4
	eor 	r8, r8, r4, ror #22
	and 	r4, r2, r9, ror #4
	eor 	r9, r9, r4, ror #26
	and 	r4, r2, r9
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r9, ror #4
	eor 	r9, r9, r4, ror #22
	and 	r4, r2, r10, ror #4
	eor 	r10, r10, r4, ror #26
	and 	r4, r2, r10
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r10, ror #4
	eor 	r10, r10, r4, ror #22
	and 	r4, r2, r11, ror #4
	eor 	r11, r11, r4, ror #26
	and 	r4, r2, r11
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r11, ror #4
	eor 	r11, r11, r4, ror #22
	and 	r4, r2, r12, ror #4
	eor 	r12, r12, r4, ror #26
	and 	r4, r2, r12
	eor 	r12, r12, r4, ror #4
	and 	r4, r2, r12, ror #4
	eor 	r12, r12, r4, ror #22 	// mixcolumns ---
	// renaming slices for the sbox calculations
	// can be avoided with an octuple_round routine=>increase of the code size
	ldr.w 	r14, [sp] 				// restore link register
	eor 	r5, r5, r6 				// --- swap state[0] with state[1]
	eor 	r6, r6, r5
	eor 	r5, r5, r6 				// swap state[0] with state[1] ---
	eor 	r7, r7, r8 				// --- swap state[2] with state[3]
	eor 	r8, r8, r7
	eor 	r7, r7, r8 				// swap state[2] with state[3] ---
	eor 	r9, r9, r12 			// --- swap state[4] with state[7]
	eor 	r12, r12, r9
	eor 	r9, r9, r12 			// swap state[4] with state[7] ---
	eor 	r11, r11, r10 			// --- swap state[6] with state[5]
	eor 	r10, r10, r11
	eor 	r11, r11, r10 			// swap state[6] with state[5] ---
	bx 		lr

/******************************************************************************
* Inverse quadruple round of fixsliced SKINNY-128 tweakable block cipher.
* The 2 blocks are stored in r5-r12 (fixsliced representation).
******************************************************************************/
.align 	2
inv_quadruple_round:
	str.w 	r14, [sp] 				// store r14 on the stack
	eor 	r5, r5, r6 				// --- swap state[0] with state[1]
	eor 	r6, r6, r5
	eor 	r5, r5, r6 				// swap state[0] with state[1] ---
	eor 	r7, r7, r8 				// --- swap state[2] with state[3]
	eor 	r8, r8, r7
	eor 	r7, r7, r8 				// swap state[2] with state[3] ---
	eor 	r9, r9, r12 			// --- swap state[4] with state[7]
	eor 	r12, r12, r9
	eor 	r9, r9, r12 			// swap state[4] with state[7] ---
	eor 	r11, r11, r10 			// --- swap state[6] with state[5]
	eor 	r10, r10, r11
	eor 	r11, r11, r10 			// swap state[6] with state[5] ---
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// mask for ininv_mixcolumns
	and 	r4, r2, r5, ror #4 		// --- inv_mixcolumns_3
	eor 	r5, r5, r4, ror #22
	and 	r4, r2, r5
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r5, ror #4
	eor 	r5, r5, r4, ror #26
	and 	r4, r2, r6, ror #4
	eor 	r6, r6, r4, ror #22
	and 	r4, r2, r6
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r6, ror #4
	eor 	r6, r6, r4, ror #26
	and 	r4, r2, r7, ror #4
	eor 	r7, r7, r4, ror #22
	and 	r4, r2, r7
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r7, ror #4
	eor 	r7, r7, r4, ror #26
	and 	r4, r2, r8, ror #4
	eor 	r8, r8, r4, ror #22
	and 	r4, r2, r8
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r8, ror #4
	eor 	r8, r8, r4, ror #26
	and 	r4, r2, r9, ror #4
	eor 	r9, r9, r4, ror #22
	and 	r4, r2, r9
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r9, ror #4
	eor 	r9, r9, r4, ror #26
	and 	r4, r2, r10, ror #4
	eor 	r10, r10, r4, ror #22
	and 	r4, r2, r10
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r10, ror #4
	eor 	r10, r10, r4, ror #26
	and 	r4, r2, r11, ror #4
	eor 	r11, r11, r4, ror #22
	and 	r4, r2, r11
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r11, ror #4
	eor 	r11, r11, r4, ror #26
	and 	r4, r2, r12, ror #4
	eor 	r12, r12, r4, ror #22
	and 	r4, r2, r12
	eor 	r12, r12, r4, ror #4
	and 	r4, r2, r12, ror #4
	eor 	r12, r12, r4, ror #26 	// inv_mixcolumns_3 ---
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r11, r11, r4 			// add rtk1
	eor 	r12, r12, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r9, r9, r2 				// add rtk1
	eor 	r10, r10, r3 			// add rtk1
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r7, r7, r4 				// add rtk1
	eor 	r8, r8, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r5, r5, r2 				// add rtk1
	eor 	r6, r6, r3 				// add rtk1
	and 	r4, r12, r10 			// state[7] & state[5]
	eor 	r9, r9, r4 				// state[4] ^= (state[7] & state[5])
	orn 	r4, r6, r5 				// ~state[0] | state[1]
	eor 	r7, r7, r4 				// state[2] ^= (~state[0] | state[1])
	orn 	r4, r6, r11 			// state[1] | ~state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[1] | ~state[6])
	orn 	r4, r7, r8 				// ~state[3] | state[2]
	eor 	r12, r12, r4 			// state[7] ^= (~state[3] | state[2])
	and 	r4, r5, r8 				// state[0] & state[3]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] & state[3])
	orr 	r4, r9, r12 			// state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (state[7] | state[4])
	orr 	r4, r7, r9 				// state[2] | state[4]
	eor 	r8, r8, r4 				// state[3] ^= (state[2] | state[4])
	orr 	r4, r10, r11 			// state[5] | state[6]
	eor 	r5, r5, r4 				// state[0] ^= (state[5] | state[6])
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// mask for inv_mixcolumns
	and 	r4, r2, r5, ror #26 	// --- inv_mixcolumns_2
	eor 	r5, r5, r4
	and 	r4, r2, r5, ror #6
	eor 	r5, r5, r4, ror #6
	and 	r4, r2, r5, ror #10
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r6, ror #26
	eor 	r6, r6, r4
	and 	r4, r2, r6, ror #6
	eor 	r6, r6, r4, ror #6
	and 	r4, r2, r6, ror #10
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r7, ror #26
	eor 	r7, r7, r4
	and 	r4, r2, r7, ror #6
	eor 	r7, r7, r4, ror #6
	and 	r4, r2, r7, ror #10
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r8, ror #26
	eor 	r8, r8, r4
	and 	r4, r2, r8, ror #6
	eor 	r8, r8, r4, ror #6
	and 	r4, r2, r8, ror #10
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r9, ror #26
	eor 	r9, r9, r4
	and 	r4, r2, r9, ror #6
	eor 	r9, r9, r4, ror #6
	and 	r4, r2, r9, ror #10
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r10, ror #26
	eor 	r10, r10, r4
	and 	r4, r2, r10, ror #6
	eor 	r10, r10, r4, ror #6
	and 	r4, r2, r10, ror #10
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r11, ror #26
	eor 	r11, r11, r4
	and 	r4, r2, r11, ror #6
	eor 	r11, r11, r4, ror #6
	and 	r4, r2, r11, ror #10
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r12, ror #26
	eor 	r12, r12, r4
	and 	r4, r2, r12, ror #6
	eor 	r12, r12, r4, ror #6
	and 	r4, r2, r12, ror #10
	eor 	r12, r12, r4, ror #4 	// inv_mixcolumns_2 ---
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r11, r11, r4 			// add rtk1
	eor 	r12, r12, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r9, r9, r2 				// add rtk1
	eor 	r10, r10, r3 			// add rtk1
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r7, r7, r4 				// add rtk1
	eor 	r8, r8, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r5, r5, r2 				// add rtk1
	eor 	r6, r6, r3 				// add rtk1
	and 	r4, r7, r12 			// state[2] & state[7]
	eor 	r8, r8, r4 				// state[3] ^= (state[2] & state[7])
	orn 	r4, r10, r11 			// ~state[6] | state[5]
	eor 	r5, r5, r4 				// state[0] ^= (~state[6] | state[5])
	orn 	r4, r10, r9 			// state[5] | ~state[4]
	eor 	r12, r12, r4 			// state[7] ^= (state[5] | ~state[4])
	orn 	r4, r5, r6 				// ~state[1] | state[0]
	eor 	r7, r7, r4 				// state[2] ^= (~state[1] | state[0])
	and 	r4, r6, r11 			// state[1] & state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] & state[1])
	orr 	r4, r7, r8 				// state[2] | state[3]
	eor 	r9, r9, r4 				// state[4] ^= (state[2] | state[3])
	orr 	r4, r5, r8 				// state[0] | state[3]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] | state[3])
	orr 	r4, r12, r9 			// state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (state[7] | state[4])
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// mask for inv_mixcolumns
	and 	r4, r2, r5, ror #16 	// --- inv_mixcolumns_1
	eor 	r5, r5, r4, ror #2
	and 	r4, r2, r5, ror #28
	eor 	r5, r5, r4
	and 	r4, r2, r5, ror #16
	eor 	r5, r5, r4, ror #30
	and 	r4, r2, r6, ror #16
	eor 	r6, r6, r4, ror #2
	and 	r4, r2, r6, ror #28
	eor 	r6, r6, r4
	and 	r4, r2, r6, ror #16
	eor 	r6, r6, r4, ror #30
	and 	r4, r2, r7, ror #16
	eor 	r7, r7, r4, ror #2
	and 	r4, r2, r7, ror #28
	eor 	r7, r7, r4
	and 	r4, r2, r7, ror #16
	eor 	r7, r7, r4, ror #30
	and 	r4, r2, r8, ror #16
	eor 	r8, r8, r4, ror #2
	and 	r4, r2, r8, ror #28
	eor 	r8, r8, r4
	and 	r4, r2, r8, ror #16
	eor 	r8, r8, r4, ror #30
	and 	r4, r2, r9, ror #16
	eor 	r9, r9, r4, ror #2
	and 	r4, r2, r9, ror #28
	eor 	r9, r9, r4
	and 	r4, r2, r9, ror #16
	eor 	r9, r9, r4, ror #30
	and 	r4, r2, r10, ror #16
	eor 	r10, r10, r4, ror #2
	and 	r4, r2, r10, ror #28
	eor 	r10, r10, r4
	and 	r4, r2, r10, ror #16
	eor 	r10, r10, r4, ror #30
	and 	r4, r2, r11, ror #16
	eor 	r11, r11, r4, ror #2
	and 	r4, r2, r11, ror #28
	eor 	r11, r11, r4
	and 	r4, r2, r11, ror #16
	eor 	r11, r11, r4, ror #30
	and 	r4, r2, r12, ror #16
	eor 	r12, r12, r4, ror #2
	and 	r4, r2, r12, ror #28
	eor 	r12, r12, r4
	and 	r4, r2, r12, ror #16
	eor 	r12, r12, r4, ror #30 	// inv_mixcolumns_1 ---
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r11, r11, r4 			// add rtk1
	eor 	r12, r12, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r9, r9, r2 				// add rtk1
	eor 	r10, r10, r3 			// add rtk1
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r7, r7, r4 				// add rtk1
	eor 	r8, r8, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r5, r5, r2 				// add rtk1
	eor 	r6, r6, r3 				// add rtk1
	and 	r4, r5, r7 				// state[0] & state[2]
	eor 	r6, r6, r4 				// state[1] ^= (state[0] & state[2])
	orn 	r4, r12, r9 			// state[7] | ~state[4]
	eor 	r11, r11, r4 			// state[6] ^= (~state[4] | state[7])
	orn 	r4, r12, r8 			// state[7] | ~state[3]
	eor 	r7, r7, r4 				// state[2] ^= (state[7] | ~state[3])
	orn 	r4, r11, r10 			// ~state[5] | state[6]
	eor 	r5, r5, r4 				// state[0] ^= (~state[5] | state[6])
	and 	r4, r9, r10 			// state[4] & state[5]
	eor 	r12, r12, r4 			// state[7] ^= (state[4] & state[5])
	orr 	r4, r5, r6 				// state[0] | state[1]
	eor 	r8, r8, r4 				// state[3] ^= (state[0] | state[1])
	orr 	r4, r6, r11 			// state[1] | state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] | state[1])
	orr 	r4, r7, r8 				// state[2] | state[3]
	eor 	r9, r9, r4 				// state[4] ^= (state[2] | state[3])
	movw 	r2, #0x3030
	movt 	r2, #0x3030 			// mask for inv_mixcolumns
	and 	r4, r2, r5, ror #6 		// --- inv_mixcolumns_0
	eor 	r5, r5, r4, ror #4
	and 	r4, r2, r5, ror #18
	eor 	r5, r5, r4, ror #2
	and 	r4, r2, r5, ror #30
	eor 	r5, r5, r4, ror #24
	and 	r4, r2, r6, ror #6
	eor 	r6, r6, r4, ror #4
	and 	r4, r2, r6, ror #18
	eor 	r6, r6, r4, ror #2
	and 	r4, r2, r6, ror #30
	eor 	r6, r6, r4, ror #24
	and 	r4, r2, r7, ror #6
	eor 	r7, r7, r4, ror #4
	and 	r4, r2, r7, ror #18
	eor 	r7, r7, r4, ror #2
	and 	r4, r2, r7, ror #30
	eor 	r7, r7, r4, ror #24
	and 	r4, r2, r8, ror #6
	eor 	r8, r8, r4, ror #4
	and 	r4, r2, r8, ror #18
	eor 	r8, r8, r4, ror #2
	and 	r4, r2, r8, ror #30
	eor 	r8, r8, r4, ror #24
	and 	r4, r2, r9, ror #6
	eor 	r9, r9, r4, ror #4
	and 	r4, r2, r9, ror #18
	eor 	r9, r9, r4, ror #2
	and 	r4, r2, r9, ror #30
	eor 	r9, r9, r4, ror #24
	and 	r4, r2, r10, ror #6
	eor 	r10, r10, r4, ror #4
	and 	r4, r2, r10, ror #18
	eor 	r10, r10, r4, ror #2
	and 	r4, r2, r10, ror #30
	eor 	r10, r10, r4, ror #24
	and 	r4, r2, r11, ror #6
	eor 	r11, r11, r4, ror #4
	and 	r4, r2, r11, ror #18
	eor 	r11, r11, r4, ror #2
	and 	r4, r2, r11, ror #30
	eor 	r11, r11, r4, ror #24
	and 	r4, r2, r12, ror #6
	eor 	r12, r12, r4, ror #4
	and 	r4, r2, r12, ror #18
	eor 	r12, r12, r4, ror #2
	and 	r4, r2, r12, ror #30
	eor 	r12, r12, r4, ror #24
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r11, r11, r4 			// add rtk_2_3 + rconst
	eor 	r12, r12, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r9, r9, r2 				// add rtk_2_3 + rconst
	eor 	r10, r10, r3 			// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r1], #-8 		// load rtk_2_3
	eor 	r7, r7, r4 				// add rtk_2_3 + rconst
	eor 	r8, r8, r14 			// add rtk_2_3 + rconst
	ldrd 	r2, r3, [r1], #-8 		// load rtk_2_3
	eor 	r5, r5, r2 				// add rtk_2_3 + rconst
	eor 	r6, r6, r3 				// add rtk_2_3 + rconst
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r11, r11, r4 			// add rtk1
	eor 	r12, r12, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r9, r9, r2 				// add rtk1
	eor 	r10, r10, r3 			// add rtk1
	ldrd 	r4, r14, [r0], #-8 		// load rtk1
	eor 	r7, r7, r4 				// add rtk1
	eor 	r8, r8, r14 			// add rtk1
	ldrd 	r2, r3, [r0], #-8 		// load rtk1
	eor 	r5, r5, r2 				// add rtk1
	eor 	r6, r6, r3 				// add rtk1
	ldr.w 	r14, [sp] 				// restore link register
	and 	r4, r5, r11 			// state[0] & state[6]
	eor 	r10, r10, r4 			// state[5] ^= (state[6] & state[0])
	orn 	r4, r7, r8 				// ~state[3] | state[2]
	eor 	r9, r9, r4 				// state[4] ^= (~state[3] | state[2])
	orn 	r4, r7, r6 				// state[2] | ~state[1]
	eor 	r5, r5, r4 				// state[0] ^= (state[2] | ~state[1])
	orn 	r4, r9, r12 			// ~state[7] | state[4]
	eor 	r11, r11, r4 			// state[6] ^= (~state[7] | state[4])
	and 	r4, r8, r12 			// state[3] & state[7]
	eor 	r7, r7, r4 				// state[2] ^= (state[3] & state[7])
	orr 	r4, r11, r10 			// state[6] | state[5]
	eor 	r6, r6, r4 				// state[1] ^= (state[6] | state[5])
	orr 	r4, r9, r10 			// state[4] | state[5]
	eor 	r12, r12, r4 			// state[7] ^= (state[4] | state[5])
	orr 	r4, r5, r6 				// state[0] | state[1]
	eor 	r8, r8, r4 				// state[3] ^= (state[0] | state[1])
	bx 		lr

/******************************************************************************
* Compute the SKINNY block cipher on a single block in a fixsliced manner.
******************************************************************************/
@ void skinny128_384(u8* ctext, u8* ctext_bis, const u8* ptext,
@	const u8* ptext_bis,  const u32* rtk_1, const u32* rtk_2_3)
.global skinny128_384
.type   skinny128_384,%function
.align 2
skinny128_384:
	push 	{r0-r12, r14}
	sub.w 	sp, #4 					// to store r14 during subroutines
	ldm 	r2, {r5,r7,r9,r11} 		// load the 2nd block in r6,r8,r10,r12
	ldm 	r3, {r6,r8,r10,r12} 	// load the 2nd block in r6,r8,r10,r12
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//r3 <- 0x30303030
	bl 		packing
	ldrd 	r0, r1, [sp, #60] 		// get rtk addr (1st stack argument)
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	sub.w 	r0, #512
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	sub.w 	r0, #512
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	sub.w 	r0, #512
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		unpacking
	ldrd 	r0, r1, [sp, #4]
	add.w 	sp, #12
	stm 	r0, {r5, r7, r9, r11} 	// store the 1st enc block in [r0]
	stm 	r1, {r6, r8, r10, r12} 	// store the 2nd enc block in [r1]
    pop 	{r2-r12, r14}
    bx 		lr

/******************************************************************************
* Compute the SKINNY block cipher on a single block in a fixsliced manner.
******************************************************************************/
@ void skinny128_384_inv(u8* ptext, u8* ptext_bis, const u8* ctext,
@	const u8* ctext_bis,  const u32* rtk_1, const u32* rtk_2_3)
.global skinny128_384_inv
.type   skinny128_384_inv,%function
.align 2
skinny128_384_inv:
	push 	{r0-r12, r14}
	sub.w 	sp, #4 					// to store r14 during subroutines
	ldm 	r2, {r5,r7,r9,r11} 		// load the 2nd block in r6,r8,r10,r12
	ldm 	r3, {r6,r8,r10,r12} 	// load the 2nd block in r6,r8,r10,r12
	movw 	r2, #0x5555
	movt 	r2, #0x5555 			//r2 <- 0x55555555
	movw 	r3, #0x3030
	movt 	r3, #0x3030 			//r3 <- 0x30303030
	bl 		packing
	ldrd 	r0, r1, [sp, #60] 		// get rtk addr (1st stack argument)
	add.w 	r0, #248 				// points to the last rtk1
	add.w 	r1, #1784 				// points to the last rtk2_3
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	add.w 	r0, #512
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	add.w 	r0, #512
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	add.w 	r0, #512
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		inv_quadruple_round
	bl 		unpacking
	ldrd 	r0, r1, [sp, #4]
	add.w 	sp, #12
	stm 	r0, {r5, r7, r9, r11} 	// store the 1st enc block in [r0]
	stm 	r1, {r6, r8, r10, r12} 	// store the 2nd enc block in [r1]
    pop 	{r2-r12,r14}
    bx 		lr
