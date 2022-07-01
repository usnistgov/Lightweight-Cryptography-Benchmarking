/*******************************************************************************
* ARM assembly implementation of fixsliced SKINNY-128-384.
*
* For more details, see the paper at
* https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020
* /documents/papers/fixslicing-lwc2020.pdf
* 
* 
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     May 2020
*******************************************************************************/

.syntax unified
.thumb

/*******************************************************************************
* applies P^2 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p2:
	movw 	r1, #0xcc00
	movt 	r1, #0xcc00 				//r1 <- 0xcc00cc00
	movw 	r10, #0xcc00
	movt 	r10, #0x0033 				//r10<- 0xcc000033
	and 	r11, r1, r6, ror #14
	bfi 	r11, r6, #16, #8
	and 	r12, r6, #0xcc000000
	orr 	r11, r11, r12, lsr #2
	and 	r12, r10, r6
	orr 	r11, r11, r12, lsr #8
	and 	r12, r6, #0x00cc0000
	orr 	r6, r11, r12, lsr #18
	and 	r11, r1, r7, ror #14
	bfi 	r11, r7, #16, #8
	and 	r12, r7, #0xcc000000
	orr 	r11, r11, r12, lsr #2
	and 	r12, r10, r7
	orr 	r11, r11, r12, lsr #8
	and 	r12, r7, #0x00cc0000
	orr 	r7, r11, r12, lsr #18
	and 	r11, r1, r8, ror #14
	bfi 	r11, r8, #16, #8
	and 	r12, r8, #0xcc000000
	orr 	r11, r11, r12, lsr #2
	and 	r12, r10, r8
	orr 	r11, r11, r12, lsr #8
	and 	r12, r8, #0x00cc0000
	orr 	r8, r11, r12, lsr #18
	and 	r11, r1, r9, ror #14
	bfi 	r11, r9, #16, #8
	and 	r12, r9, #0xcc000000
	orr 	r11, r11, r12, lsr #2
	and 	r12, r10, r9
	orr 	r11, r11, r12, lsr #8
	and 	r12, r9, #0x00cc0000
	orr 	r9, r11, r12, lsr #18
	bx 		lr

/*******************************************************************************
* applies P^4 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p4:
	str.w 	r14, [sp] 					//store r14 on the stack
	movw 	r14, #0x00cc
	movt 	r14, #0xcc00 				//r14<- 0xcc0000cc
	movw 	r12, #0xcc00
	movt 	r12, #0x3300 				//r12<- 0x3300cc00
	movw 	r11, #0x00cc
	movt 	r11, #0x00cc 				//r11<- 0x00cc00cc
 	and 	r10, r14, r6, ror #22
 	and 	r1, r12, r6, ror #16
 	orr 	r10, r10,  r1
 	and 	r1, r6, r11
 	orr 	r10, r10, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r6, r6, r1
 	orr 	r6, r10, r6, ror #24
 	and 	r10, r14, r7, ror #22
 	and 	r1, r12, r7, ror #16
 	orr 	r10, r10, r1
 	and 	r1, r7, r11
 	orr 	r10, r10, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r7, r7, r1
 	orr 	r7, r10, r7, ror #24
 	and 	r10, r14, r8, ror #22
 	and 	r1, r12, r8, ror #16
 	orr 	r10, r10, r1
 	and 	r1, r8, r11
 	orr 	r10, r10, r1, lsr #2
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r8, r8, r1
 	orr 	r8, r10, r8, ror #24
 	and 	r10, r14, r9, ror #22
 	ldr.w 	r14, [sp] 					//restore r14
 	and 	r12, r12, r9, ror #16
 	orr 	r10, r10, r12
 	and 	r12, r9, r11
 	orr 	r10, r10, r12, lsr #2
	movw 	r12, #0xcc33 				//r1 <- 0x0000cc33
 	and 	r9, r9, r12
 	orr 	r9, r10, r9, ror #24
 	bx 		lr

/*******************************************************************************
* applies P^6 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p6:
	movw 	r1, #0x3333 				//r1 <- 0x00003333
	movw 	r12, #0x00cc
	movt 	r12, #0x3300 				//r12<- 0x330000cc
	and 	r10, r6, r1, ror #8 		// --- permute r6 6 times
	and 	r11, r12, r6, ror #24
	orr 	r11, r11, r10, ror #6
	and 	r10, r1, r6, ror #10
	orr 	r11, r11, r10
	and 	r10, r6, #0x000000cc
	orr 	r11, r11, r10, lsl #14
	and 	r10, r6, #0x00003300
	orr 	r6, r11, r10, lsl #2 		// permute r6 6 times ---
	and 	r10, r7, r1, ror #8 		// --- permute r7 6 times
	and 	r11, r12, r7, ror #24
	orr 	r11, r11, r10, ror #6
	and 	r10, r1, r7, ror #10
	orr 	r11, r11, r10
	and 	r10, r7, #0x000000cc
	orr 	r11, r11, r10, lsl #14
	and 	r10, r7, #0x00003300
	orr 	r7, r11, r10, lsl #2 		// permute r7 6 times ---
	and 	r10, r8, r1, ror #8 		// --- permute r8 6 times
	and 	r11, r12, r8, ror #24
	orr 	r11, r11, r10, ror #6
	and 	r10, r1, r8, ror #10
	orr 	r11, r11, r10
	and 	r10, r8, #0x000000cc
	orr 	r11, r11, r10, lsl #14
	and 	r10, r8, #0x00003300
	orr 	r8, r11, r10, lsl #2 		// permute r8 6 times ---
	and 	r10, r9, r1, ror #8 		// --- permute r9 6 times
	and 	r11, r12, r9, ror #24
	orr 	r11, r11, r10, ror #6
	and 	r10, r1, r9, ror #10
	orr 	r11, r11, r10
	and 	r10, r9, #0x000000cc
	orr 	r11, r11, r10, lsl #14
	and 	r10, r9, #0x00003300 		// permute r9 6 times ---
	orr 	r9, r11, r10, lsl #2
 	bx 		lr

/*******************************************************************************
* applies P^8 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p8:
	movw 	r12, #0x3333 				//r12<- 0x00003333
	movw 	r1, #0x0000
	movt 	r1, #0x33cc 				//r1 <- 0x33cc0000
	and 	r10, r6, r1 				// --- permute r6 8 times
	and 	r11, r1, r6, ror #8
	orr 	r11, r11, r10, ror #24
	and 	r10, r6, r12, lsl #2
	orr 	r11, r11, r10, ror #26
	and 	r10, r6, r12, lsl #8
	orr 	r6, r11, r10, lsr #6 		// permute r6 8 times ---
	and 	r10, r7, r1 				// --- permute r7 8 times
	and 	r11, r1, r7, ror #8
	orr 	r11, r11, r10, ror #24
	and 	r10, r7, r12, lsl #2
	orr 	r11, r11, r10, ror #26
	and 	r10, r7, r12, lsl #8
	orr 	r7, r11, r10, lsr #6 		// permute r7 8 times ---
	and 	r10, r8, r1 				// --- permute r8 8 times
	and 	r11, r1, r8, ror #8
	orr 	r11, r11, r10, ror #24
	and 	r10, r8, r12, lsl #2
	orr 	r11, r11, r10, ror #26
	and 	r10, r8, r12, lsl #8
	orr 	r8, r11, r10, lsr #6 		// permute r8 8 times ---
	and 	r10, r9, r1 				// --- permute r9 8 times
	and 	r11, r1, r9, ror #8
	orr 	r11, r11, r10, ror #24
	and 	r10, r9, r12, lsl #2
	orr 	r11, r11, r10, ror #26
	and 	r10, r9, r12, lsl #8
	orr 	r9, r11, r10, lsr #6 		// permute r9 8 times ---
 	bx 		lr

/*******************************************************************************
* applies P^10 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p10:
	movw 	r12, #0x0033
	movt 	r12, #0x3300 				//r12<- 0x33000033
	movw 	r1, #0xcc33 				//r1 <- 0x0000cc33
	and 	r10, r6, r1, ror #8 		// --- permute r6 10 times
	and 	r11, r12, r6, ror #26
	orr 	r11, r11, r10, ror #8
	and 	r10, r6, r12, ror #24
	orr 	r11, r11, r10, ror #22
	and 	r10, r6, #0x00330000
	orr 	r11, r11, r10, lsr #14
	and 	r10, r6, #0x0000cc00
	orr 	r6, r11, r10, lsr #2 		// permute r6 10 times ---
	and 	r10, r7, r1, ror #8 		// --- permute r6 10 times
	and 	r11, r12, r7, ror #26
	orr 	r11, r11, r10, ror #8
	and 	r10, r7, r12, ror #24
	orr 	r11, r11, r10, ror #22
	and 	r10, r7, #0x00330000
	orr 	r11, r11, r10, lsr #14
	and 	r10, r7, #0x0000cc00
	orr 	r7, r11, r10, lsr #2 		// permute r6 10 times ---
	and 	r10, r8, r1, ror #8 		// --- permute r6 10 times
	and 	r11, r12, r8, ror #26
	orr 	r11, r11, r10, ror #8
	and 	r10, r8, r12, ror #24
	orr 	r11, r11, r10, ror #22
	and 	r10, r8, #0x00330000
	orr 	r11, r11, r10, lsr #14
	and 	r10, r8, #0x0000cc00
	orr 	r8, r11, r10, lsr #2 		// permute r6 10 times ---
	and 	r10, r9, r1, ror #8 		// --- permute r6 10 times
	and 	r11, r12, r9, ror #26
	orr 	r11, r11, r10, ror #8
	and 	r10, r9, r12, ror #24
	orr 	r11, r11, r10, ror #22
	and 	r10, r9, #0x00330000
	orr 	r11, r11, r10, lsr #14
	and 	r10, r9, #0x0000cc00
	orr 	r9, r11, r10, lsr #2 		// permute r6 10 times ---
 	bx 		lr

/*******************************************************************************
* applies P^12 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p12:
	str.w 	r14, [sp] 					//store r14 on the stack
	movw 	r14, #0xcc33 				//r14<- 0x0000cc33
	movw 	r12, #0x00cc
	movt 	r12, #0x00cc 				//r12<- 0x00cc00cc
	movw 	r1, #0x3300
	movt 	r1, #0xcc00 				//r1 <- 0xcc003300
	and 	r10, r14, r6, ror #8 		// --- permute r6 12 times
	and 	r11, r12, r6, ror #30
	orr 	r11, r11, r10
	and 	r10, r1, r6, ror #16
	orr 	r11, r11, r10
	movw 	r10, #0xcccc 				//r10<- 0x0000cccc
	and 	r10, r6, r10, ror #8
	orr 	r6, r11, r10, ror #10 		// permute r6 12 times ---
	and 	r10, r14, r7, ror #8 		// --- permute r7 12 times
	and 	r11, r12, r7, ror #30
	orr 	r11, r11, r10
	and 	r10, r1, r7, ror #16
	orr 	r11, r11, r10
	movw 	r10, #0xcccc 				//r10<- 0x0000cccc
	and 	r10, r7, r10, ror #8
	orr 	r7, r11, r10, ror #10 		// permute r7 12 times ---
	and 	r10, r14, r8, ror #8 		// --- permute r8 12 times
	and 	r11, r12, r8, ror #30
	orr 	r11, r11, r10
	and 	r10, r1, r8, ror #16
	orr 	r11, r11, r10
	movw 	r10, #0xcccc 				//r10<- 0x0000cccc
	and 	r10, r8, r10, ror #8
	orr 	r8, r11, r10, ror #10 		// permute r8 12 times ---
	and 	r10, r14, r9, ror #8 		// --- permute r9 12 times
	and 	r11, r12, r9, ror #30
	orr 	r11, r11, r10
	and 	r10, r1, r9, ror #16
	ldr.w 	r14, [sp]
	orr 	r11, r11, r10
	movw 	r10, #0xcccc 				//r10<- 0x0000cccc
	and 	r10, r9, r10, ror #8
	orr 	r9, r11, r10, ror #10 		// permute r9 12 times ---
 	bx 		lr

/*******************************************************************************
* applies P^14 on the tweakey state in a bitsliced manner
*******************************************************************************/
.align 	2
p14:
	movw 	r1, #0xcc00
	movt 	r1, #0x0033 				//r1 <- 0x0033cc00
	movw 	r12, #0xcc00
	movt 	r12, #0xcc00 				//r12<- 0x33003300
	and 	r10, r1, r6, ror #24 		// --- permute r6 14 times
	and 	r11, r6, #0x00000033
	orr 	r11, r10, r11, ror #14
	and 	r10, r6, #0x33000000
	orr 	r11, r11, r10, ror #30
	and 	r10, r6, #0x00ff0000
	orr 	r11, r11, r10, ror #16
	and 	r10, r6, r12
	orr 	r6, r11, r10, ror #18 		// permute r6 14 times ---
	and 	r10, r1, r7, ror #24 		// --- permute r7 14 times
	and 	r11, r7, #0x00000033
	orr 	r11, r10, r11, ror #14
	and 	r10, r7, #0x33000000
	orr 	r11, r11, r10, ror #30
	and 	r10, r7, #0x00ff0000
	orr 	r11, r11, r10, ror #16
	and 	r10, r7, r12
	orr 	r7, r11, r10, ror #18 		// permute r7 14 times ---
	and 	r10, r1, r8, ror #24 		// --- permute r8 14 times
	and 	r11, r8, #0x00000033
	orr 	r11, r10, r11, ror #14
	and 	r10, r8, #0x33000000
	orr 	r11, r11, r10, ror #30
	and 	r10, r8, #0x00ff0000
	orr 	r11, r11, r10, ror #16
	and 	r10, r8, r12
	orr 	r8, r11, r10, ror #18 		// permute r8 14 times ---
	and 	r10, r1, r9, ror #24 		// --- permute r9 14 times
	and 	r11, r9, #0x00000033
	orr 	r11, r10, r11, ror #14
	and 	r10, r9, #0x33000000
	orr 	r11, r11, r10, ror #30
	and 	r10, r9, #0x00ff0000
	orr 	r11, r11, r10, ror #16
	and 	r10, r9, r12
	orr 	r9, r11, r10, ror #18 		// permute r9 14 times ---
 	bx 		lr

.align 2
packing:
	eor 	r12, r2, r2, lsr #3
	and 	r12, r12, r10
	eor 	r2, r2, r12
	eor 	r2, r2, r12, lsl #3 		//SWAPMOVE(r2, r2, 0x0a0a0a0a, 3)
	eor 	r12, r3, r3, lsr #3
	and 	r12, r12, r10
	eor 	r3, r3, r12
	eor 	r3, r3, r12, lsl #3 		//SWAPMOVE(r3, r3, 0x0a0a0a0a, 3)
	eor 	r12, r4, r4, lsr #3
	and 	r12, r12, r10
	eor 	r4, r4, r12
	eor 	r4, r4, r12, lsl #3 		//SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
	eor 	r12, r5, r5, lsr #3
	and 	r12, r12, r10
	eor 	r5, r5, r12
	eor 	r5, r5, r12, lsl #3 		//SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
	eor 	r12, r2, r4, lsr #2
	and 	r12, r12, r11
	eor 	r2, r2, r12
	eor 	r4, r4, r12, lsl #2 		//SWAPMOVE(r4, r2, 0x30303030, 2)
	eor 	r12, r2, r3, lsr #4
	and 	r12, r12, r11, lsr #2
	eor 	r2, r2, r12
	eor 	r3, r3, r12, lsl #4 		//SWAPMOVE(r3, r2, 0x0c0c0c0c, 4)
	eor 	r12, r2, r5, lsr #6
	and 	r12, r12, r11, lsr #4
	eor 	r2, r2, r12
	eor 	r5, r5, r12, lsl #6 		//SWAPMOVE(r5, r2, 0x03030303, 6)
	eor 	r12, r4, r3, lsr #2
	and 	r12, r12, r11, lsr #2
	eor 	r4, r4, r12
	eor 	r3, r3, r12, lsl #2 		//SWAPMOVE(r3, r4, 0x0c0c0c0c, 2)
	eor 	r12, r4, r5, lsr #4
	and 	r12, r12, r11, lsr #4
	eor 	r4, r4, r12
	eor 	r5, r5, r12, lsl #4 		//SWAPMOVE(r5, r4, 0x03030303, 4)
	eor 	r12, r3, r5, lsr #2
	and 	r12, r12, r11, lsr #4
	eor 	r3, r3, r12
	eor 	r5, r5, r12, lsl #2 		//SWAPMOVE(r5, r3, 0x03030303, 2)
	bx 		lr

/******************************************************************************
* Compute LFSR2(TK2) ^ LFSR3(TK3) for all rounds.
* Performing both at the same time allows to save some memory accesses.
******************************************************************************/
@ void 	tkschedule_lfsr(u32* tk, const u8* tk2, const u8* tk3, const int rounds)
.global tkschedule_lfsr
.type   tkschedule_lfsr,%function
.align	2
tkschedule_lfsr:
	push 	{r0-r12, r14}
	ldr.w 	r3, [r1, #8] 				//load tk2 (3rd word)
	ldr.w 	r4, [r1, #4] 				//load tk2 (2nd word)
	ldr.w 	r5, [r1, #12] 				//load tk2 (4th word)
	ldr.w 	r12, [r1] 					//load tk2 (1st word)
	mov 	r1, r2 						//move tk3 address in r1
	mov 	r2, r12 					//move 1st tk2 word in r2
	movw 	r10, #0x0a0a
	movt 	r10, #0x0a0a 				//r10 <- 0x0a0a0a0a
	movw 	r11, #0x3030
	movt 	r11, #0x3030 				//r7 <- 0x30303030
	bl 		packing 					//pack tk2
	mov 	r6, r2 						//move tk2 from r2-r5 to r6-r9
	mov 	r7, r3 						//move tk2 from r2-r5 to r6-r9
	mov 	r8, r4 						//move tk2 from r2-r5 to r6-r9
	mov 	r9, r5 						//move tk2 from r2-r5 to r6-r9
	ldr.w 	r3, [r1, #8] 				//load tk3 (3rd word)
	ldr.w 	r4, [r1, #4] 				//load tk3 (2nd word)
	ldr.w 	r5, [r1, #12] 				//load tk3 (4th) word)
	ldr.w 	r2, [r1] 					//load tk3 (1st) word)
	bl 		packing 					//pack tk3
	eor 	r10, r10, r10, lsl #4 		//r10<- 0xaaaaaaaa
	ldr.w 	r1, [sp, #12] 				//load loop counter in r1
	eor 	r11, r2, r6 				//tk2 ^ tk3 (1st word)
	eor 	r12, r3, r7 				//tk2 ^ tk3 (2nd word)
	strd 	r11, r12, [r0], #8 			//store in tk
	eor 	r11, r4, r8 				//tk2 ^ tk3 (3rd word)
	eor 	r12, r5, r9					//tk2 ^ tk3 (4th word)
	strd 	r11, r12, [r0], #8 			//store in tk
	loop:
		and 	r12, r8, r10 			// --- apply LFSR2 to tk2
		eor 	r12, r12, r6
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10 				
		orr 	r6, r14, r12, lsr #1	// apply LFSR2 to tk2 ---
		and 	r12, r3, r10 			// --- apply LFSR3 to tk3
		eor 	r12, r5, r12, lsr #1
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10
		orr 	r5, r14, r12, lsr #1 	// apply LFSR3 to tk3 ---
		eor 	r11, r5, r7 			//tk2 ^ tk3 (1st word)
		eor 	r12, r2, r8 			//tk2 ^ tk3 (2nd word)
		strd 	r11, r12, [r0], #8 		//store in tk
		eor 	r11, r3, r9 			//tk2 ^ tk3 (3rd word)
		eor 	r12, r4, r6				//tk2 ^ tk3 (4th word)
		strd 	r11, r12, [r0], #24 	//store in tk
		and 	r12, r9, r10 			// --- apply LFSR2 to tk2
		eor 	r12, r12, r7
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10 				
		orr 	r7, r14, r12, lsr #1	// apply LFSR2 to tk2 ---
		and 	r12, r2, r10 			// --- apply LFSR3 to tk3
		eor 	r12, r4, r12, lsr #1
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10
		orr 	r4, r14, r12, lsr #1 	// apply LFSR3 to tk3 ---
		eor 	r11, r4, r8 			//tk2 ^ tk3 (1st word)
		eor 	r12, r5, r9 			//tk2 ^ tk3 (2nd word)
		strd 	r11, r12, [r0], #8 		//store in tk
		eor 	r11, r2, r6 			//tk2 ^ tk3 (3rd word)
		eor 	r12, r3, r7				//tk2 ^ tk3 (4th word)
		strd 	r11, r12, [r0], #24 	//store in tk
		and 	r12, r6, r10 			// --- apply LFSR2 to tk2
		eor 	r12, r12, r8
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10 				
		orr 	r8, r14, r12, lsr #1	// apply LFSR2 to tk2 ---
		and 	r12, r5, r10 			// --- apply LFSR3 to tk3
		eor 	r12, r3, r12, lsr #1
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10
		orr 	r3, r14, r12, lsr #1 	// apply LFSR3 to tk3 ---
		eor 	r11, r3, r9 			//tk2 ^ tk3 (1st word)
		eor 	r12, r4, r6 			//tk2 ^ tk3 (2nd word)
		strd 	r11, r12, [r0], #8 		//store in tk
		eor 	r11, r5, r7 			//tk2 ^ tk3 (3rd word)
		eor 	r12, r2, r8				//tk2 ^ tk3 (4th word)
		strd 	r11, r12, [r0], #24 	//store in tk
		and 	r12, r7, r10 			// --- apply LFSR2 to tk2
		eor 	r12, r12, r9
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10 				
		orr 	r9, r14, r12, lsr #1	// apply LFSR2 to tk2 ---
		and 	r12, r4, r10 			// --- apply LFSR3 to tk3
		eor 	r12, r2, r12, lsr #1
		and 	r14, r10, r12, lsl #1
		and 	r12, r12, r10
		orr 	r2, r14, r12, lsr #1 	// apply LFSR3 to tk3 ---
		eor 	r11, r2, r6 			//tk2 ^ tk3 (1st word)
		eor 	r12, r3, r7 			//tk2 ^ tk3 (2nd word)
		strd 	r11, r12, [r0], #8 		//store in tk
		eor 	r11, r4, r8 			//tk2 ^ tk3 (3rd word)
		eor 	r12, r5, r9				//tk2 ^ tk3 (4th word)
		strd 	r11, r12, [r0], #24 	//store in tk
		subs.w 	r1, r1, #8 				//decrease loop counter by 8
		bne 	loop
	pop 	{r0-r12, r14}
	bx 		lr

@ void 	tkschedule_perm(u32* tk)
.global tkschedule_perm
.type   tkschedule_perm,%function
.align	2
tkschedule_perm:
	push 	{r0-r12, lr}
	sub.w 	sp, #4 						//to store r14 in subroutines
	ldm 	r0, {r6-r9} 				//load tk
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r6, r6, r10 				//tk &= 0xf0f0f0f0 (1st word)
	and 	r7, r7, r10 				//tk &= 0xf0f0f0f0 (2nd word)
	and 	r8, r8, r10 				//tk &= 0xf0f0f0f0 (3rd word)
	and 	r9, r9, r10 				//tk &= 0xf0f0f0f0 (4th word)
	eor 	r8, r8, #0x00000004 		//add rconst
	eor 	r9, r9, #0x00000040 		//add rconst
	mvn 	r9, r9 						//to remove a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 1st round
	strd 	r6, r7, [r0], #8  			//store 2nd half tk for 1st round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p2 							//apply the permutation twice
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #26 		//ror and mask to match fixslicing
	strd	r11, r12, [r0], #8 			//store 1st half tk for 2nd round
	and 	r11, r10, r8, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x10000000 		//add rconst
	eor 	r11, r11, #0x00000100 		//add rconst
	eor 	r12, r12, #0x00000100 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd	r11, r12, [r0], #8 			//store 2nd half tk for 2nd round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #12
	and 	r11, r10, r7, ror #28
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #12
	and 	r11, r10, r8, ror #28
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #12
	and 	r11, r10, r9, ror #28
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #12		//ror and masks to match fixslicing ---
	eor 	r7, r7, #0x04000000 		//add rconst
	eor 	r8, r8, #0x44000000 		//add rconst
	eor 	r9, r9, #0x04000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 3rd round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 3rd round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p4 							//apply the permutation 4 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00400000 		//add rconst
	eor 	r12, r12, #0x00400000 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 5th round
	and 	r11, r10, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00440000 		//add rconst
	eor 	r12, r12, #0x00500000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 5th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #14 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #6
	and 	r11, r10, r7, ror #14
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #6
	and 	r11, r10, r8, ror #14
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #6
	and 	r11, r10, r9, ror #14
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #6			//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00100000 		//add rconst
	eor 	r7, r7, #0x00100000 		//add rconst
	eor 	r8, r8, #0x00100000 		//add rconst
	eor 	r8, r8, #0x00000001 		//add rconst
	eor 	r9, r9, #0x00100000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 4th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 4th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p6 							//apply the permutation 6 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01000000 		//add rconst
	eor 	r12, r12, #0x01000000 		//add rconst
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 6th round
	and 	r11, r10, r8, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01400000 		//add rconst
	eor 	r11, r11, #0x00001000 		//add rconst
	eor 	r12, r12, #0x00400000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0], #8 			//store 2nd half tk for 6th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #28
	and 	r11, r10, r7, ror #12
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #28
	and 	r11, r10, r8, ror #12
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #28
	and 	r11, r10, r9, ror #12
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #28		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00000400 		//add rconst
	eor 	r7, r7, #0x00000400 		//add rconst
	eor 	r8, r8, #0x01000000 		//add rconst
	eor 	r8, r8, #0x00004000 		//add rconst
	eor 	r9, r9, #0x01000000 		//add rconst
	eor 	r9, r9, #0x00000400 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 7th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 7th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p8 							//apply the permutation 8 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6 				//ror and mask to match fixslicing
	and 	r12, r10, r7 				//ror and mask to match fixslicing
	eor 	r12, r12, #0x00000040 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 9th round
	and 	r11, r10, r8 				//ror and mask to match fixslicing
	and 	r12, r10, r9 				//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000054 		//add rconst
	eor 	r12, r12, #0x00000050 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 9th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #30 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #22
	and 	r11, r10, r7, ror #30
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #22
	and 	r11, r10, r8, ror #30
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #22
	and 	r11, r10, r9, ror #30
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #22		//ror and masks to match fixslicing ---
	eor 	r6 ,r6, #0x00000010
	eor 	r8, r8, #0x00010000
	eor 	r8, r8, #0x00000410
	eor 	r9, r9, #0x00000410
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 8th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 8th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p10 						//apply the permutation 10 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000100 		//add rconst
	eor 	r12, r12, #0x00000100 		//add rconst
	strd	r11, r12, [r0], #8 			//store 1st half tk for 10th round
	and 	r11, r10, r8, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x10000000 		//add rconst
	eor 	r11, r11, #0x00000140 		//add rconst
	eor 	r12, r12, #0x00000100 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd	r11, r12, [r0], #8 			//store 2nd half tk for 10th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #12
	and 	r11, r10, r7, ror #28
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #12
	and 	r11, r10, r8, ror #28
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #12
	and 	r11, r10, r9, ror #28
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #12		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x04000000 		//add rconst
	eor 	r7, r7, #0x04000000 		//add rconst
	eor 	r8, r8, #0x44000000 		//add rconst
	eor 	r9, r9, #0x00000100 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 11th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 11th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p12 						//apply the permutation 4 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00400000 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 13th round
	and 	r11, r10, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00140000 		//add rconst
	eor 	r12, r12, #0x00500000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 13th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #14 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #6
	and 	r11, r10, r7, ror #14
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #6
	and 	r11, r10, r8, ror #14
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #6
	and 	r11, r10, r9, ror #14
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #6			//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00100000 		//add rconst
	eor 	r7, r7, #0x00100000 		//add rconst
	eor 	r8, r8, #0x04000000 		//add rconst
	eor 	r8, r8, #0x00000001 		//add rconst
	eor 	r9, r9, #0x04000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 12th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 12th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p14 						//apply the permutation 6 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #10 		//ror and mask to match fixslicing
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 14th round
	and 	r11, r10, r8, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01400000 		//add rconst
	eor 	r11, r11, #0x00001000 		//add rconst
	eor 	r12, r12, #0x01400000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0], #8 			//store 2nd half tk for 14th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #28
	and 	r11, r10, r7, ror #12
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #28
	and 	r11, r10, r8, ror #12
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #28
	and 	r11, r10, r9, ror #12
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #28		//ror and masks to match fixslicing ---
	eor 	r7, r7, #0x00000400 		//add rconst
	eor 	r8, r8, #0x01000000 		//add rconst
	eor 	r8, r8, #0x00004400 		//add rconst
	eor 	r9, r9, #0x00000400 		//add const
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 15th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 15th round
	ldm 	r0, {r6-r9} 				//load tk
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6 				//ror and mask to match fixslicing
	and 	r12, r10, r7 				//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000040 		//add rconst
	eor 	r12, r12, #0x00000040 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 17th round
	and 	r11, r10, r8 				//ror and mask to match fixslicing
	and 	r12, r10, r9 				//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000004 		//add rconst
	eor 	r12, r12, #0x00000050 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 17th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #30 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #22
	and 	r11, r10, r7, ror #30
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #22
	and 	r11, r10, r8, ror #30
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #22
	and 	r11, r10, r9, ror #30
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #22		//ror and masks to match fixslicing ---
	eor 	r6 ,r6, #0x00000010
	eor 	r7 ,r7, #0x00000010
	eor 	r8, r8, #0x00000010
	eor 	r8, r8, #0x00010000
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 16th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 16th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p2 							//apply the permutation twice
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000100 		//add rconst
	strd	r11, r12, [r0], #8 			//store 1st half tk for 18th round
	and 	r11, r10, r8, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x10000000 		//add rconst
	eor 	r11, r11, #0x00000140 		//add rconst
	eor 	r12, r12, #0x00000040 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd	r11, r12, [r0], #8 			//store 2nd half tk for 18th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #12
	and 	r11, r10, r7, ror #28
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #12
	and 	r11, r10, r8, ror #28
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #12
	and 	r11, r10, r9, ror #28
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #12		//ror and masks to match fixslicing ---
	eor 	r7, r7, #0x04000000 		//add rconst
	eor 	r8, r8, #0x40000000 		//add rconst
	eor 	r8, r8, #0x00000100 		//add rconst
	eor 	r9, r9, #0x04000000 		//add rconst
	eor 	r9, r9, #0x00000100 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 19th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 19th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p4 							//apply the permutation 4 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #16 		//ror and mask to match fixslicing
	eor 	r12, r12, #0x00400000 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 21th round
	and 	r11, r10, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00440000 		//add rconst
	eor 	r12, r12, #0x00100000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 21th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #14 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #6
	and 	r11, r10, r7, ror #14
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #6
	and 	r11, r10, r8, ror #14
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #6
	and 	r11, r10, r9, ror #14
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #6			//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00100000 		//add rconst
	eor 	r8, r8, #0x04100000 		//add rconst
	eor 	r8, r8, #0x00000001 		//add rconst
	eor 	r9, r9, #0x00100000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 20th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 20th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p6 							//apply the permutation 6 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01000000 		//add rconst
	eor 	r12, r12, #0x01000000 		//add rconst
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 22th round
	and 	r11, r10, r8, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00400000 		//add rconst
	eor 	r11, r11, #0x00001000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0], #8 			//store 2nd half tk for 22th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #28
	and 	r11, r10, r7, ror #12
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #28
	and 	r11, r10, r8, ror #12
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #28
	and 	r11, r10, r9, ror #12
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #28		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00000400 		//add rconst
	eor 	r8, r8, #0x00004000 		//add rconst
	eor 	r9, r9, #0x01000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 23th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 23th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p8 							//apply the permutation 8 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6 				//ror and mask to match fixslicing
	and 	r12, r10, r7 				//ror and mask to match fixslicing
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 25th round
	and 	r11, r10, r8 				//ror and mask to match fixslicing
	and 	r12, r10, r9 				//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000014 		//add rconst
	eor 	r12, r12, #0x00000040 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 25th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #30 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #22
	and 	r11, r10, r7, ror #30
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #22
	and 	r11, r10, r8, ror #30
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #22
	and 	r11, r10, r9, ror #30
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #22		//ror and masks to match fixslicing ---
	eor 	r8, r8, #0x00010400
	eor 	r9, r9, #0x00000400
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 24th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 24th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p10 						//apply the permutation 10 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #26 		//ror and mask to match fixslicing
	strd	r11, r12, [r0], #8 			//store 1st half tk for 26th round
	and 	r11, r10, r8, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x10000000 		//add rconst
	eor 	r11, r11, #0x00000100 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd	r11, r12, [r0], #8 			//store 2nd half tk for 26th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #12
	and 	r11, r10, r7, ror #28
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #12
	and 	r11, r10, r8, ror #28
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #12
	and 	r11, r10, r9, ror #28
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #12		//ror and masks to match fixslicing ---
	eor 	r7, r7, #0x04000000 		//add rconst
	eor 	r8, r8, #0x40000000 		//add rconst
	eor 	r9, r9, #0x04000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 27th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 27th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p12 						//apply the permutation 4 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #16 		//ror and mask to match fixslicing
	eor 	r12, r12, #0x00400000 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 29th round
	and 	r11, r10, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00440000 		//add rconst
	eor 	r12, r12, #0x00500000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 29th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #14 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #6
	and 	r11, r10, r7, ror #14
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #6
	and 	r11, r10, r8, ror #14
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #6
	and 	r11, r10, r9, ror #14
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #6			//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00100000 		//add rconst
	eor 	r8, r8, #0x00100000 		//add rconst
	eor 	r8, r8, #0x00000001 		//add rconst
	eor 	r9, r9, #0x00100000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 28th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 28th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p14 						//apply the permutation 6 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01000000 		//add rconst
	eor 	r12, r12, #0x01000000 		//add rconst
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 30th round
	and 	r11, r10, r8, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01400000 		//add rconst
	eor 	r11, r11, #0x00001000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0], #8 			//store 2nd half tk for 30th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #28
	and 	r11, r10, r7, ror #12
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #28
	and 	r11, r10, r8, ror #12
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #28
	and 	r11, r10, r9, ror #12
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #28		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00000400 		//add rconst
	eor 	r7, r7, #0x00000400 		//add rconst
	eor 	r8, r8, #0x00004000 		//add rconst
	eor 	r9, r9, #0x01000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 31th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 31th round
	ldm 	r0, {r6-r9} 				//load tk
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6 				//ror and mask to match fixslicing
	and 	r12, r10, r7 				//ror and mask to match fixslicing
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 33th round
	and 	r11, r10, r8 				//ror and mask to match fixslicing
	and 	r12, r10, r9 				//ror and mask to match fixslicing
	eor 	r11, r11, #0x00000014 		//add rconst
	eor 	r12, r12, #0x00000050 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 33th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #30 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #22
	and 	r11, r10, r7, ror #30
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #22
	and 	r11, r10, r8, ror #30
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #22
	and 	r11, r10, r9, ror #30
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #22		//ror and masks to match fixslicing ---
	eor 	r6 ,r6, #0x00000010
	eor 	r8, r8, #0x00010400
	eor 	r9, r9, #0x00000400
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 32th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 32th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p2 							//apply the permutation twice
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #26 		//ror and mask to match fixslicing
	strd	r11, r12, [r0], #8 			//store 1st half tk for 34th round
	and 	r11, r10, r8, ror #26 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #26 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x10000000 		//add rconst
	eor 	r11, r11, #0x00000140 		//add rconst
	eor 	r12, r12, #0x00000100 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd	r11, r12, [r0], #8 			//store 2nd half tk for 34th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #12
	and 	r11, r10, r7, ror #28
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #12
	and 	r11, r10, r8, ror #28
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #12
	and 	r11, r10, r9, ror #28
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #12		//ror and masks to match fixslicing ---
	eor 	r7, r7, #0x04000000 		//add rconst
	eor 	r8, r8, #0x44000000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 35th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 35th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p4 							//apply the permutation 4 times
	movw 	r10, #0xf0f0
	movt 	r10, #0xf0f0 				//r10<- 0xf0f0f0f0
	and 	r11, r10, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00400000 		//add rconst
	strd 	r11, r12, [r0, #24] 		//store 2nd half tk for 37th round
	and 	r11, r10, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #16 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x00440000 		//add rconst
	eor 	r12, r12, #0x00500000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0, #16] 		//store 1st half tk for 37th round
	and 	r10, r10, r10, lsr #2 		//r10<- 0x30303030
	and 	r11, r10, r6, ror #14 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #6
	and 	r11, r10, r7, ror #14
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #6
	and 	r11, r10, r8, ror #14
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #6
	and 	r11, r10, r9, ror #14
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #6			//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00100000 		//add rconst
	eor 	r7, r7, #0x00100000 		//add rconst
	eor 	r8, r8, #0x00000001 		//add rconst
	eor 	r9, r9, #0x00100000 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 36th round
	strd 	r8, r9, [r0], #24 			//store 2nd half tk for 36th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p6 							//apply the permutation 6 times
	movw 	r10, #0xc3c3
	movt 	r10, #0xc3c3 				//r10<- 0xc3c3c3c3
	and 	r11, r10, r6, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r7, ror #10 		//ror and mask to match fixslicing
	eor 	r12, r12, #0x01000000 		//add rconst
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 38th round
	and 	r11, r10, r8, ror #10 		//ror and mask to match fixslicing
	and 	r12, r10, r9, ror #10 		//ror and mask to match fixslicing
	eor 	r11, r11, #0x01400000 		//add rconst
	eor 	r11, r11, #0x00001000 		//add rconst
	eor 	r12, r12, #0x00400000 		//add rconst
	mvn 	r12, r12 					//to save a NOT in sbox calculations
	strd 	r11, r12, [r0], #8 			//store 2nd half tk for 38th round
	and 	r10, r10, r10, lsr #6 		//r10<- 0x03030303
	and 	r11, r10, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, lsl #6
	orr 	r6, r11, r6, ror #28
	and 	r11, r10, r7, ror #12
	and 	r7, r7, r10, lsl #6
	orr 	r7, r11, r7, ror #28
	and 	r11, r10, r8, ror #12
	and 	r8, r8, r10, lsl #6
	orr 	r8, r11, r8, ror #28
	and 	r11, r10, r9, ror #12
	and 	r9, r9, r10, lsl #6
	orr 	r9, r11, r9, ror #28		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00000400 		//add rconst
	eor 	r7, r7, #0x00000400 		//add rconst
	eor 	r8, r8, #0x01000000
	eor 	r8, r8, #0x00004000 		//add rconst
	eor 	r9, r9, #0x00000400 		//add rconst
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r8, r9, [r0], #8 			//store 1st half tk for 39th round
	strd 	r6, r7, [r0], #8 			//store 2nd half tk for 39th round
	ldm 	r0, {r6-r9} 				//load tk
	bl 		p8 							//apply the permutation 8 times
	movw 	r10, #0x3030
	movt 	r10, #0x3030 				//r10<- 0x30303030
	and 	r11, r10, r6, ror #30 		//--- ror and masks to match fixslicing
	and 	r6, r6, r10, ror #4
	orr 	r6, r11, r6, ror #22
	and 	r11, r10, r7, ror #30
	and 	r7, r7, r10, ror #4
	orr 	r7, r11, r7, ror #22
	and 	r11, r10, r8, ror #30
	and 	r8, r8, r10, ror #4
	orr 	r8, r11, r8, ror #22
	and 	r11, r10, r9, ror #30
	and 	r9, r9, r10, ror #4
	orr 	r9, r11, r9, ror #22		//ror and masks to match fixslicing ---
	eor 	r6, r6, #0x00000010
	eor 	r8, r8, #0x00010000
	eor 	r8, r8, #0x00000010
	eor 	r9, r9, #0x00000400
	mvn 	r9, r9 						//to save a NOT in sbox calculations
	strd 	r6, r7, [r0], #8 			//store 1st half tk for 40th round
	strd 	r8, r9, [r0] 			//store 2nd half tk for 40th round
	add.w 	sp, #4
	pop 	{r0-r12, lr}
	bx 		lr

/******************************************************************************
* Applies the permutations P^2, ..., P^14 for rounds 0 to 16. Since P^16=Id, we
* don't need more calculations as no LFSR is applied to TK1.
******************************************************************************/
@ void 	tkschedule_perm_tk1(u32* tk, const u8* key)
.global tkschedule_perm_tk1
.type   tkschedule_perm_tk1,%function
.align	2
tkschedule_perm_tk1:
	push 	{r0-r12, lr}
	ldr.w 	r3, [r1, #8] 				//load tk1 (3rd word)
	ldr.w 	r4, [r1, #4] 				//load tk1 (2nd word)
	ldr.w 	r5, [r1, #12] 				//load tk1 (4th word)
	ldr.w 	r2, [r1] 					//load tk1 (1st word)
	movw 	r10, #0x0a0a
	movt 	r10, #0x0a0a 				//r6 <- 0x0a0a0a0a
	movw 	r11, #0x3030
	movt 	r11, #0x3030 				//r7 <- 0x30303030
	bl 		packing 					//pack tk1
	mov 	r6, r2 						//move tk1 from r2-r5 to r6-r9
	mov 	r7, r3 						//move tk1 from r2-r5 to r6-r9
	mov 	r8, r4 						//move tk1 from r2-r5 to r6-r9
	mov 	r9, r5 						//move tk1 from r2-r5 to r6-r9
	movw 	r2, #0xf0f0
	movt 	r2, #0xf0f0 				//r2<- 0xf0f0f0f0
	and 	r11, r8, r2 				//tk &= 0xf0f0f0f0 (3rd word)
	and 	r12, r9, r2 				//tk &= 0xf0f0f0f0 (4th word)
	strd 	r11, r12, [r0], #8 			//store 1st half tk for 1st round
	and 	r11, r6, r2 				//tk &= 0xf0f0f0f0 (1st word)
	and 	r12, r7, r2 				//tk &= 0xf0f0f0f0 (2nd word)
	strd 	r11, r12, [r0], #8  			//store 2nd half tk for 1st round

	bl 		p2 							//apply the permutation twice
	movw 	r3, #0x0303
	movt 	r3, #0x0303 				//r3<- 0x03030303
	and 	r11, r3, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r12, r6, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #8]
	and 	r11, r3, r7, ror #28
	and 	r12, r7, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #12]
	and 	r11, r3, r9, ror #28
	and 	r12, r9, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #4]
	and 	r11, r3, r8, ror #28
	and 	r12, r8, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0], #16				//ror and masks to match fixslicing ---
	bl 		p2 							//apply the permutation 4 times
	and 	r11, r2, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r2, r7, ror #16 		//ror and mask to match fixslicing
	strd 	r11, r12, [r0, #8] 			//store 2nd half tk for 5th round
	and 	r11, r2, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r2, r9, ror #16 		//ror and mask to match fixslicing
	strd 	r11, r12, [r0], #16 		//store 1st half tk for 5th round
	bl 		p2 							//apply the permutation 6 times
	and 	r11, r3, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r12, r6, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #8]
	and 	r11, r3, r7, ror #12
	and 	r12, r7, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #12]
	and 	r11, r3, r9, ror #12
	and 	r12, r9, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #4]
	and 	r11, r3, r8, ror #12
	and 	r12, r8, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0], #16 				//ror and masks to match fixslicing ---
	bl 		p2 							//apply the permutation 8 times
	and 	r11, r2, r6 				//ror and mask to match fixslicing
	and 	r12, r2, r7 				//ror and mask to match fixslicing
	strd 	r11, r12, [r0, #8] 			//store 2nd half tk for 9th round
	and 	r11, r2, r8 				//ror and mask to match fixslicing
	and 	r12, r2, r9 				//ror and mask to match fixslicing
	strd 	r11, r12, [r0], #16 		//store 1st half tk for 9th round
	bl 		p2 							//apply the permutation 10
	and 	r11, r3, r6, ror #28 		//--- ror and masks to match fixslicing
	and 	r12, r6, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #8]
	and 	r11, r3, r7, ror #28
	and 	r12, r7, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #12]
	and 	r11, r3, r9, ror #28
	and 	r12, r9, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0, #4]
	and 	r11, r3, r8, ror #28
	and 	r12, r8, r3, lsl #6
	orr 	r12, r11, r12, ror #12
	str.w 	r12, [r0], #16				//ror and masks to match fixslicing ---
	bl 		p2 							//apply the permutation 12 times
	and 	r11, r2, r6, ror #16 		//ror and mask to match fixslicing
	and 	r12, r2, r7, ror #16 		//ror and mask to match fixslicing
	strd 	r11, r12, [r0, #8] 			//store 2nd half tk for 5th round
	and 	r11, r2, r8, ror #16 		//ror and mask to match fixslicing
	and 	r12, r2, r9, ror #16 		//ror and mask to match fixslicing
	strd 	r11, r12, [r0], #16 		//store 1st half tk for 5th round
	bl 		p2 							//apply the permutation 14 times
	and 	r11, r3, r6, ror #12 		//--- ror and masks to match fixslicing
	and 	r12, r6, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #8]
	and 	r11, r3, r7, ror #12
	and 	r12, r7, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #12]
	and 	r11, r3, r9, ror #12
	and 	r12, r9, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0, #4]
	and 	r11, r3, r8, ror #12
	and 	r12, r8, r3, lsl #6
	orr 	r12, r11, r12, ror #28
	str.w 	r12, [r0] 					//ror and masks to match fixslicing ---
	pop 	{r0-r12, lr}
	bx 		lr

.align 2
quadruple_round:
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	eor 	r8, r2, r5
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r5, r5, r8				//SWAPMOVE(r5, r2, 0x55555555, 0);
	ldmia.w r1!, {r8-r11} 			//load rkeys in r8,...,r11
	eor 	r2, r2, r8 				//add rtk_2_3 + rconst
	eor 	r3, r3, r9 				//add rtk_2_3 + rconst
	eor 	r4, r4, r10 			//add rtk_2_3 + rconst
	eor 	r5, r5, r11 			//add rtk_2_3 + rconst
	ldmia.w r0!,{r8-r11}
	eor 	r2, r2, r8 				//add rtk_1
	eor 	r3, r3, r9 				//add rtk_1
	eor 	r4, r4, r10 			//add rtk_1
	eor 	r5, r5, r11 			//add rtk_1
	and 	r8, r7, r2, ror #30 	// --- mixcolumns 0 ---
	eor 	r2, r2, r8, ror #24
	and 	r8, r7, r2, ror #18
	eor 	r2, r2, r8, ror #2
	and 	r8, r7, r2, ror #6
	eor 	r2, r2, r8, ror #4
	and 	r8, r7, r3, ror #30
	eor 	r3, r3, r8, ror #24
	and 	r8, r7, r3, ror #18
	eor 	r3, r3, r8, ror #2
	and 	r8, r7, r3, ror #6
	eor 	r3, r3, r8, ror #4
	and 	r8, r7, r4, ror #30
	eor 	r4, r4, r8, ror #24
	and 	r8, r7, r4, ror #18
	eor 	r4, r4, r8, ror #2
	and 	r8, r7, r4, ror #6
	eor 	r4, r4, r8, ror #4
	and 	r8, r7, r5, ror #30
	eor 	r5, r5, r8, ror #24
	and 	r8, r7, r5, ror #18
	eor 	r5, r5, r8, ror #2
	and 	r8, r7, r5, ror #6
	eor 	r5, r5, r8, ror #4
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	eor 	r8, r3, r4
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8 				//SWAPMOVE(r4, r3, 0x55555555, 0);
	ldmia.w r1!, {r8-r11} 			//load rkeys in r8,...,r11
	eor 	r2, r2, r8 				//add rkey + rconst
	eor 	r3, r3, r9 				//add rkey + rconst
	eor 	r4, r4, r10 			//add rkey + rconst
	eor 	r5, r5, r11 			//add rkey + rconst
	and 	r8, r7, r2, ror #16		// --- mixcolumns 1 ---
	eor 	r2, r2, r8, ror #30
	and 	r8, r7, r2, ror #28
	eor 	r2, r2, r8
	and 	r8, r7, r2, ror #16
	eor 	r2, r2, r8, ror #2
	and 	r8, r7, r3, ror #16
	eor 	r3, r3, r8, ror #30
	and 	r8, r7, r3, ror #28
	eor 	r3, r3, r8
	and 	r8, r7, r3, ror #16
	eor 	r3, r3, r8, ror #2
	and 	r8, r7, r4, ror #16
	eor 	r4, r4, r8, ror #30
	and 	r8, r7, r4, ror #28
	eor 	r4, r4, r8
	and 	r8, r7, r4, ror #16
	eor 	r4, r4, r8, ror #2
	and 	r8, r7, r5, ror #16
	eor 	r5, r5, r8, ror #30
	and 	r8, r7, r5, ror #28
	eor 	r5, r5, r8
	and 	r8, r7, r5, ror #16
	eor 	r5, r5, r8, ror #2
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	eor 	r8, r2, r5
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r5, r5, r8				//SWAPMOVE(r5, r2, 0x55555555, 0);
	ldmia.w r1!, {r8-r11} 			//load rkeys in r8,...,r11
	eor 	r2, r2, r8 				//add rtk_2_3 + rconst
	eor 	r3, r3, r9 				//add rtk_2_3 + rconst
	eor 	r4, r4, r10 			//add rtk_2_3 + rconst
	eor 	r5, r5, r11 			//add rtk_2_3 + rconst
	ldmia.w r0!,{r8-r11}
	eor 	r2, r2, r8 				//add rtk_1
	eor 	r3, r3, r9 				//add rtk_1
	eor 	r4, r4, r10 			//add rtk_1
	eor 	r5, r5, r11 			//add rtk_1
	and 	r8, r7, r2, ror #10		// --- mixcolumns 2 ---
	eor 	r2, r2, r8, ror #4
	and 	r8, r7, r2, ror #6
	eor 	r2, r2, r8, ror #6
	and 	r8, r7, r2, ror #26
	eor 	r2, r2, r8
	and 	r8, r7, r3, ror #10
	eor 	r3, r3, r8, ror #4
	and 	r8, r7, r3, ror #6
	eor 	r3, r3, r8, ror #6
	and 	r8, r7, r3, ror #26
	eor 	r3, r3, r8
	and 	r8, r7, r4, ror #10
	eor 	r4, r4, r8, ror #4
	and 	r8, r7, r4, ror #6
	eor 	r4, r4, r8, ror #6
	and 	r8, r7, r4, ror #26
	eor 	r4, r4, r8
	and 	r8, r7, r5, ror #10
	eor 	r5, r5, r8, ror #4
	and 	r8, r7, r5, ror #6
	eor 	r5, r5, r8, ror #6
	and 	r8, r7, r5, ror #26
	eor 	r5, r5, r8
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	mvn 	r5, r5
	eor 	r8, r3, r4, lsr #1
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r3, 0x55555555, 1);
	eor 	r8, r4, r5, lsr #1
	and 	r8, r8, r6
	eor 	r4, r4, r8
	eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r4, 0x55555555, 1);
	orr 	r8, r4, r5
	eor 	r3, r3, r8
	mvn 	r3, r3
	eor 	r8, r2, r3, lsr #1
	and 	r8, r8, r6
	eor 	r2, r2, r8
	eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r2, 0x55555555, 1);
	eor 	r8, r5, r2, lsr #1
	and 	r8, r8, r6
	eor 	r5, r5, r8
	eor 	r2, r2, r8, lsl #1 		//SWAPMOVE(r2, r5, 0x55555555, 1);
	orr 	r8, r2, r3
	eor 	r5, r5, r8
	eor 	r8, r3, r4
	and 	r8, r8, r6
	eor 	r3, r3, r8
	eor 	r4, r4, r8 				//SWAPMOVE(r4, r3, 0x55555555, 0);
	ldmia 	r1!, {r8-r11} 			//load rkeys in r8,...,r11
	eor 	r2, r2, r8 				//add rkey + rconst
	eor 	r3, r3, r9 				//add rkey + rconst
	eor 	r4, r4, r10 			//add rkey + rconst
	eor 	r5, r5, r11 			//add rkey + rconst
	and 	r8, r7, r2, ror #4		// --- mixcolumns 3 ---
	eor 	r2, r2, r8, ror #26
	and 	r8, r7, r2
	eor 	r2, r2, r8, ror #4
	and 	r8, r7, r2, ror #4
	eor 	r2, r2, r8, ror #22
	and 	r8, r7, r3, ror #4
	eor 	r3, r3, r8, ror #26
	and 	r8, r7, r3
	eor 	r3, r3, r8, ror #4
	and 	r8, r7, r3, ror #4
	eor 	r3, r3, r8, ror #22
	and 	r8, r7, r4, ror #4
	eor 	r4, r4, r8, ror #26
	and 	r8, r7, r4
	eor 	r4, r4, r8, ror #4
	and 	r8, r7, r4, ror #4
	eor 	r4, r4, r8, ror #22
	and 	r8, r7, r5, ror #4
	eor 	r5, r5, r8, ror #26
	and 	r8, r7, r5
	eor 	r5, r5, r8, ror #4
	and 	r8, r7, r5, ror #4
	eor 	r5, r5, r8, ror #22
	bx 		lr

/******************************************************************************
* Encrypt a single block using fixsliced SKINNY-128-128.
******************************************************************************/
@ void 	skinny128_384(u8* ctext, const u32* tk, const u8* ptext)
.global skinny128_384
.type   skinny128_384,%function
.align 2
skinny128_384:
	push 	{r0-r12, r14}
	mov.w 	r0, r3
	ldr.w 	r3, [r2, #8]
	ldr.w 	r4, [r2, #4]
	ldr.w 	r5, [r2, #12]
	ldr.w 	r2, [r2]
	movw 	r6, #0x0a0a
	movt 	r6, #0x0a0a 			//r6 <- 0x0a0a0a0a
	movw 	r7, #0x3030
	movt 	r7, #0x3030 			//r7 <- 0x30303030
	eor 	r12, r2, r2, lsr #3
	and 	r12, r12, r6
	eor 	r2, r2, r12
	eor 	r2, r2, r12, lsl #3 	//SWAPMOVE(r2, r2, 0x0a0a0a0a, 3)
	eor 	r12, r3, r3, lsr #3
	and 	r12, r12, r6
	eor 	r3, r3, r12
	eor 	r3, r3, r12, lsl #3 	//SWAPMOVE(r3, r3, 0x0a0a0a0a, 3)
	eor 	r12, r4, r4, lsr #3
	and 	r12, r12, r6
	eor 	r4, r4, r12
	eor 	r4, r4, r12, lsl #3 	//SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
	eor 	r12, r5, r5, lsr #3
	and 	r12, r12, r6
	eor 	r5, r5, r12
	eor 	r5, r5, r12, lsl #3 	//SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
	eor 	r12, r2, r4, lsr #2
	and 	r12, r12, r7
	eor 	r2, r2, r12
	eor 	r4, r4, r12, lsl #2 	//SWAPMOVE(r4, r2, 0x30303030, 2)
	eor 	r12, r2, r3, lsr #4
	and 	r12, r12, r7, lsr #2
	eor 	r2, r2, r12
	eor 	r3, r3, r12, lsl #4 	//SWAPMOVE(r3, r2, 0x0c0c0c0c, 4)
	eor 	r12, r2, r5, lsr #6
	and 	r12, r12, r7, lsr #4
	eor 	r2, r2, r12
	eor 	r5, r5, r12, lsl #6 	//SWAPMOVE(r5, r2, 0x03030303, 6)
	eor 	r12, r4, r3, lsr #2
	and 	r12, r12, r7, lsr #2
	eor 	r4, r4, r12
	eor 	r3, r3, r12, lsl #2 	//SWAPMOVE(r3, r4, 0x0c0c0c0c, 2)
	eor 	r12, r4, r5, lsr #4
	and 	r12, r12, r7, lsr #4
	eor 	r4, r4, r12
	eor 	r5, r5, r12, lsl #4 	//SWAPMOVE(r5, r4, 0x03030303, 4)
	eor 	r12, r3, r5, lsr #2
	and 	r12, r12, r7, lsr #4
	eor 	r3, r3, r12
	eor 	r5, r5, r12, lsl #2 	//SWAPMOVE(r5, r3, 0x03030303, 2)
	movw 	r6, #0x5555
	movt 	r6, #0x5555 			//r6 <- 0x55555555
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	sub.w 	r0, #128 				// rtk1 repeats every 16 rounds
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	bl 		quadruple_round
	sub.w 	r0, #128 				// rtk1 repeats every 16 rounds
	bl 		quadruple_round
	bl 		quadruple_round
	movw 	r6, #0x0a0a
	movt 	r6, #0x0a0a 			//r6 <- 0x0a0a0a0a
	eor 	r10, r3, r5, lsr #2
	and 	r10, r10, r7, lsr #4
	eor 	r3, r3, r10
	eor 	r5, r5, r10, lsl #2 	//SWAPMOVE(r5, r3, 0x03030303, 2)
	eor 	r10, r4, r5, lsr #4
	and 	r10, r10, r7, lsr #4
	eor 	r4, r4, r10
	eor 	r5, r5, r10, lsl #4 	//SWAPMOVE(r5, r4, 0x03030303, 4)
	eor 	r10, r4, r3, lsr #2
	and 	r10, r10, r7, lsr #2
	eor 	r4, r4, r10
	eor 	r3, r3, r10, lsl #2 	//SWAPMOVE(r3, r4, 0x0c0c0c0c, 2)
	eor 	r10, r2, r5, lsr #6
	and 	r10, r10, r7, lsr #4
	eor 	r2, r2, r10
	eor 	r5, r5, r10, lsl #6 	//SWAPMOVE(r5, r2, 0x03030303, 6)
	eor 	r10, r2, r3, lsr #4
	and 	r10, r10, r7, lsr #2
	eor 	r2, r2, r10
	eor 	r3, r3, r10, lsl #4 	//SWAPMOVE(r3, r2, 0x0c0c0c0c, 4)
	eor 	r10, r2, r4, lsr #2
	and 	r10, r10, r7
	eor 	r2, r2, r10
	eor 	r4, r4, r10, lsl #2 	//SWAPMOVE(r4, r2, 0x30303030, 2)
	eor 	r10, r5, r5, lsr #3
	and 	r10, r10, r6
	eor 	r5, r5, r10
	eor 	r5, r5, r10, lsl #3 	//SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
	eor 	r10, r4, r4, lsr #3
	and 	r10, r10, r6
	eor 	r4, r4, r10
	eor 	r4, r4, r10, lsl #3 	//SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
	eor 	r10, r3, r3, lsr #3
	and 	r10, r10, r6
	eor 	r3, r3, r10
	eor 	r3, r3, r10, lsl #3 		//SWAPMOVE(r3, r3, 0x0a0a0a0a, 3)
	eor 	r10, r2, r2, lsr #3
	and 	r10, r10, r6
	eor 	r2, r2, r10
	eor 	r2, r2, r10, lsl #3 	//SWAPMOVE(r2, r2, 0x0a0a0a0a, 3)
	ldr.w 	r0, [sp], #4
	strd 	r2, r4, [r0]
	strd 	r3, r5, [r0, #8]
    pop 	{r1-r12,r14}
    bx 		lr
    