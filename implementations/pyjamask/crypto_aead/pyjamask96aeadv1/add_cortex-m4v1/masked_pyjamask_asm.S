/*
  ===============================================================================

 Copyright (c) 2019, CryptoExperts and PQShield Ltd.
 
 All rights reserved. A copyright license for redistribution and use in
 source and binary forms, with or without modification, is hereby granted for
 non-commercial, experimental, research, public review and evaluation
 purposes, provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

  Authors: Dahmun Goudarzi, Matthieu Rivain

  ===============================================================================
*/


.text
.syntax unified

//==============================================================================
//=== Includes and definitions
//==============================================================================

#include "param.h"

#define SS96  3  // state size for Pyjamask-96
#define SS128 4  // state size for Pyjamask-128

	
//==============================================================================
//=== get_random_32 
//==============================================================================


// Macro random_init: 
// initialise rng_add to STM32F4 RNG address

.macro random_init rng_add
#ifdef FAST
    LDR \rng_add, =addr_rng  
#endif
.endm

// Macro get_random_32: 
// Get 32-bit random values from STM32F4 TRNG
// 2 options: 
//    - POOLING: checks the availability of fresh randomness then read it
//    - FAST:    simply reads the RNG

.macro get_random_32 rng_add, rnd


#ifdef FAST
    LDR \rnd, [\rng_add]	
#elif POOLING
    push {R9}
    BL get_random_32_pulling
    MOV \rnd, R9
    pop {R9}
	
#endif

.endm

// RNG_MODE = POOLING	
#ifdef POOLING

pull_random:
	push {LR}

	ANDS	R8, R3, R4
	BNE	enddata

	ORR	R8, R5, R6
	ANDS	R8, R8, R3
	BEQ	enderrors

	LDR	R9, =addr_rng  
	LDR	R9, [R9]
	MOV	R7, #1
	
enddata:
enderrors:	
	
	pop {LR}
	BX LR
	
get_random_32_pulling:
	push {R1-R8, LR}

	LDR	R1, =MY_RNG_CR
	MOV	R2, #MY_RNG_CR_RNGEN
	
	LDR	R3, =MY_RNG_SR
	MOV	R4, #MY_RNG_SR_DRDY
	MOV	R5, #MY_RNG_SR_CECS
	MOV	R6, #MY_RNG_SR_SECS
	
	MOV	R7, #0
while_pulling:

	ANDS	R8, R3, R6
	IT	ne
	BICNE	R1, R1, R2
	IT	ne
	ORRNE	R1, R1, R2

	
	BL pull_random
	
	CMP	R7, #1
	BNE	while_pulling
	
	pop {R1-R8, LR}
	BX LR

#endif


	
//==============================================================================
//=== Function mat_mult
//==============================================================================

// -----------------------------------------------------------------------------
// Prototype: uint32_t mat_mult(uint32_t mat_col, uint32_t vec)
// -----------------------------------------------------------------------------
// Computes a matrix vector multiplication between a 32x32 circulant binary
// and a 32-bit vector
// -----------------------------------------------------------------------------
// Inputs:  
//   R0: mat_col (matrix column)
//   R1: vec (vector to be multiplied)
// Output: 
//   R0: product
// -----------------------------------------------------------------------------

// Macro acc_col: 
// accumulate the i-th column (which is mat_col rotated by i positions) 
// i.e. add the i-th column to the accumulator if the i-th bit of vec 
// equals 1 and add 0 otherwise
	
.macro acc_col acc, mat_col, vec, tmp, i
	
	// tmp <- ith bit of vec (into the left most bit i.e. sign bit)
	LSL	\tmp, \vec, #\i	 
	
	// tmp <- mat_col AND mask 
	// (where mask = 0 if sign bit = 0 / mask = 0xffffffff if sign bit = 1)
	AND	\tmp, \mat_col, \tmp, ASR #32
	
	// acc <- acc XOR (tmp <<< i)
	EOR	\acc, \acc, \tmp, ROR #\i

.endm
	
// Function mat_mult:
	
.global mat_mult
.type mat_mult, %function
	
mat_mult:
	push {LR}
	// Input:  R0 = Matrix Column M[i]
	// 	   R1 = State[i]
	// Output: R0 = Acc

	MOV	R2, #0					// Init accumulator register
	MOV	R3, #0					// Init temporary register
	
	acc_col R2, R0, R1, R3, 0 
	acc_col R2, R0, R1, R3, 1 
	acc_col R2, R0, R1, R3, 2 
	acc_col R2, R0, R1, R3, 3 
	acc_col R2, R0, R1, R3, 4 
	acc_col R2, R0, R1, R3, 5 
	acc_col R2, R0, R1, R3, 6 
	acc_col R2, R0, R1, R3, 7 
	acc_col R2, R0, R1, R3, 8 
	acc_col R2, R0, R1, R3, 9 
	acc_col R2, R0, R1, R3, 10
	acc_col R2, R0, R1, R3, 11
	acc_col R2, R0, R1, R3, 12
	acc_col R2, R0, R1, R3, 13
	acc_col R2, R0, R1, R3, 14
	acc_col R2, R0, R1, R3, 15
	acc_col R2, R0, R1, R3, 16
	acc_col R2, R0, R1, R3, 17
	acc_col R2, R0, R1, R3, 18
	acc_col R2, R0, R1, R3, 19
	acc_col R2, R0, R1, R3, 20
	acc_col R2, R0, R1, R3, 21
	acc_col R2, R0, R1, R3, 22
	acc_col R2, R0, R1, R3, 23
	acc_col R2, R0, R1, R3, 24
	acc_col R2, R0, R1, R3, 25
	acc_col R2, R0, R1, R3, 26
	acc_col R2, R0, R1, R3, 27
	acc_col R2, R0, R1, R3, 28
	acc_col R2, R0, R1, R3, 29
	acc_col R2, R0, R1, R3, 30
	acc_col R2, R0, R1, R3, 31

	MOV	R0, R2

	pop {LR}
	BX LR



//==============================================================================
//=== Function isw_macc_96
//==============================================================================

// -----------------------------------------------------------------------------
// Prototype: void isw_macc_96(uint32_t state[MASKING_ORDER][3], 
//                             int acc, int op1, int op2)
// -----------------------------------------------------------------------------
// Computes an ISW 32-AND between the state rows of index 'op1' and 'op2'
// and accumulate the product in the state row of index 'acc'
// -----------------------------------------------------------------------------
// Inputs:  
//   R0: state
//   R1: acc
//   R2: op1
//   R3: op2
// -----------------------------------------------------------------------------

.global isw_macc_96
.align 4

isw_macc_96:

    PUSH    {R4-R12, LR}

    MOV     R12, #0      // loop index i (x3)

    random_init R10      // R10: RNG address

    ADD     R1, R0, R1, LSL #2   // init c_i pointer 
    ADD     R2, R0, R2, LSL #2   // init a_i pointer 
    ADD     R3, R0, R3, LSL #2   // init b_i pointer 

loop_isw_macc_96:

    LDR     R4, [R2, R12, LSL #2]      // R4 = a_i
    LDR     R5, [R3, R12, LSL #2]      // R5 = b_i
    AND     R6, R4, R5                 // R6 = a_i AND b_i
    LDR     R0, [R1, R12, LSL #2]      // R0 = c_i
    EOR     R0, R0, R6                 // c_i = c_i XOR (a_i AND b_i)

    ADD     R11, R12, #3  // inner loop index j (x3)

inner_loop_isw_macc_96:

    get_random_32 R10, R6              // R6 = r (random)
    
    EOR     R0, R0, R6                 // c_i = c_i XOR r

    LDR     R8, [R1, R11, LSL #2]      // R8 = c_j
    LDR     R7, [R3, R11, LSL #2]      // R7 = b_j
    AND     R7, R7, R4                 // R7 = a_i AND b_j
    EOR     R7, R7, R6                 // R7 = (a_i AND b_j) XOR r
    EOR     R8, R8, R7                 // c_j = c_j XOR ((a_i AND b_j) XOR r)

    LDR     R7, [R2, R11, LSL #2]      // R7 = a_j
    AND     R7, R7, R5                 // R7 = a_j AND b_i
    EOR     R8, R8, R7                 // c_j = c_j XOR (a_j AND b_i)
    STR     R8, [R1, R11, LSL #2]      // store c_j
    
    // loop increment & test

    ADD     R11, R11, #3
    CMP     R11, #(3*MASKING_ORDER)
    BNE     inner_loop_isw_macc_96

// end inner_loop_isw_macc_96

    STR     R0, [R1, R12, LSL #2]      // store c_i

    // loop increment & test

    ADD     R12, R12, #3
    MOV     R11, #(3*MASKING_ORDER)
    SUB     R11, #3	
    CMP     R12, R11
    BNE     loop_isw_macc_96

// end loop_isw_macc_96

    // last iteration (without inner loop)

    LDR     R4, [R2, R12, LSL #2]      // R4 = a_i
    LDR     R5, [R3, R12, LSL #2]      // R5 = b_i
    AND     R6, R4, R5                 // R6 = a_i AND b_i
    LDR     R0, [R1, R12, LSL #2]      // R0 = c_i
    EOR     R0, R0, R6                 // c_i = c_i XOR (a_i AND b_i)
    STR     R0, [R1, R12, LSL #2]      // store c_i

    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_96



//==============================================================================
//=== Function isw_macc_128
//==============================================================================

// -----------------------------------------------------------------------------
// Prototype: void isw_macc_128(uint32_t state[MASKING_ORDER][3], 
//                             int acc, int op1, int op2)
// -----------------------------------------------------------------------------
// Computes an ISW 32-AND between the state rows of index 'op1' and 'op2'
// and accumulate the product in the state row of index 'acc'
// -----------------------------------------------------------------------------
// Inputs:  
//   R0: state
//   R1: acc
//   R2: op1
//   R3: op2
// -----------------------------------------------------------------------------

.global isw_macc_128
.align 4

isw_macc_128:

    PUSH    {R4-R12, LR}

    MOV     R12, #0      // loop index i (x4)

    random_init R10      // R10: RNG address

    ADD     R1, R0, R1, LSL #2   // init c_i pointer 
    ADD     R2, R0, R2, LSL #2   // init a_i pointer 
    ADD     R3, R0, R3, LSL #2   // init b_i pointer 

loop_isw_macc_128:

    LDR     R4, [R2, R12, LSL #2]      // R4 = a_i
    LDR     R5, [R3, R12, LSL #2]      // R5 = b_i
    AND     R6, R4, R5                 // R6 = a_i AND b_i
    LDR     R0, [R1, R12, LSL #2]      // R0 = c_i
    EOR     R0, R0, R6                 // c_i = c_i XOR (a_i AND b_i)

    ADD     R11, R12, #4  // inner loop index j (x4)

inner_loop_isw_macc_128:

    get_random_32 R10, R6              // R6 = r (random)

    EOR     R0, R0, R6                 // c_i = c_i XOR r

    LDR     R8, [R1, R11, LSL #2]      // R8 = c_j
    LDR     R7, [R3, R11, LSL #2]      // R7 = b_j
    AND     R7, R7, R4                 // R7 = a_i AND b_j
    EOR     R7, R7, R6                 // R7 = (a_i AND b_j) XOR r
    EOR     R8, R8, R7                 // c_j = c_j XOR ((a_i AND b_j) XOR r)

    LDR     R7, [R2, R11, LSL #2]      // R7 = a_j
    AND     R7, R7, R5                 // R7 = a_j AND b_i
    EOR     R8, R8, R7                 // c_j = c_j XOR (a_j AND b_i)
    STR     R8, [R1, R11, LSL #2]      // store c_j
    
    // loop increment & test

    ADD     R11, R11, #4
    CMP     R11, #(4*MASKING_ORDER)
    BNE     inner_loop_isw_macc_128

// end inner_loop_isw_macc_128

    STR     R0, [R1, R12, LSL #2]      // store c_i

    // loop increment & test

    ADD     R12, R12, #4
    CMP     R12, #(4*(MASKING_ORDER-1))
    BNE     loop_isw_macc_128

// end loop_isw_macc_128

    // last iteration (without inner loop)

    LDR     R4, [R2, R12, LSL #2]      // R4 = a_i
    LDR     R5, [R3, R12, LSL #2]      // R5 = b_i
    AND     R6, R4, R5                 // R6 = a_i AND b_i
    LDR     R0, [R1, R12, LSL #2]      // R0 = c_i
    EOR     R0, R0, R6                 // c_i = c_i XOR (a_i AND b_i)
    STR     R0, [R1, R12, LSL #2]      // store c_i

    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_128
