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
//=== Functions   isw_macc_96_XYZ   with XYZ in {201, 012, 102}
//===             isw_macc_128_XYZ  with XYZ in {301, 012, 123, 203}
//==============================================================================

// -----------------------------------------------------------------------------
// Prototypes: 
//       void isw_macc_96_XYZ  (uint32_t state[MASKING_ORDER][3])
//       void isw_macc_128_XYZ (uint32_t state[MASKING_ORDER][4])
// -----------------------------------------------------------------------------
// Compute an ISW multiply-and-accumulate (MACC):
//    - compute 32-AND between the state rows of index Y and Z
//    - accumulate the product in the state row of index X
// (these computations are done by processing the shares of the state rows)
// -----------------------------------------------------------------------------
// Inputs:  
//   R0: state
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Notations:
//
//    - accumulator: c shared as (c_0, ..., c_MASKING_ORDER-1)
//    - operand 1:   a shared as (a_0, ..., a_MASKING_ORDER-1)
//    - operand 2:   b shared as (b_0, ..., b_MASKING_ORDER-1)
//
// The function computes c = c XOR (a AND b) by processing the shares 
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Register usage:
//
//   R0:       state address
//   R1-R3:    a_i, b_i, c_i
//   R4-R6:    a_i+1, b_i+1, c_i+1
//   R7-R9:    a_j, b_j, c_j
//   R10:      temporary register
//   R11:      loop counter j
//   R12:      loop counter i / random 
//   R14:      rng address
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Common macros
// -----------------------------------------------------------------------------

.macro isw_loop_iteration ai0, bi0, ci0, ai1, bi1, ci1

    AND     R10, \ai0, \bi0         // R10 = a_i AND b_i
    EOR     \ci0, \ci0, R10         // c_i = c_i XOR (a_i AND b_i)

    get_random_32 R14, R7           // R7 = r (random)

    EOR     \ci0, \ci0, R7          // c_i = c_i XOR r

    AND     R10,  \ai0, \bi1        // R10 = a_i AND b_i+1
    EOR     R10,  R10,  R7          // R10 = (a_i AND b_i+1) XOR r
    EOR     \ci1, \ci1, R10         // c_i+1 = c_i+1 XOR ((a_i AND b_i+1) XOR r)

    AND     R10,  \bi0, \ai1        // R10 = a_i+1 AND b_i
    EOR     \ci1, \ci1,  R10        // c_i+1 = c_i+1 XOR (a_i+1 AND b_i)    

    AND     R10,  \ai1, \bi1        // R10 = a_i+1 AND b_i+1
    EOR     \ci1, \ci1, R10         // c_i+1 = c_i+1 XOR (a_i+1 AND b_i+1)    

.endm

// -----------------------------------------------------------------------------

.macro isw_inner_loop_iteration ai0, bi0, ci0, ai1, bi1, ci1, aj, bj, cj

    // process pair (i, j) 

    get_random_32 R14, R12          // R12 = r (random)

    EOR     \ci0, \ci0, R12         // c_i = c_i XOR r

    AND     R10, \ai0, \bj          // R10 = a_i AND b_j
    EOR     R10, R10,  R12          // R10 = (a_i AND b_j) XOR r
    EOR     \cj, \cj,  R10          // c_j = c_j XOR ((a_i AND b_j) XOR r)

    AND     R10, \aj, \bi0          // R10 = a_j AND b_i
    EOR     \cj, \cj, R10           // c_j = c_j XOR (a_j AND b_i)

    // process pair (i+1, j) 

    get_random_32 R14, R12          // R12 = r (random)
    
    EOR     \ci1, \ci1, R12         // c_i+1 = c_i+1 XOR r

    AND     R10, \ai1, \bj          // R10 = a_i+1 AND b_j
    EOR     R10, R10,  R12          // R10 = (a_i+1 AND b_j) XOR r
    EOR     \cj, \cj,  R10          // c_j = c_j XOR ((a_i+1 AND b_j) XOR r)

    AND     R10, \aj, \bi1          // R10 = a_j AND b_i+1
    EOR     \cj, \cj, R10           // c_j = c_j XOR (a_j AND b_i+1)    

.endm

// -----------------------------------------------------------------------------

.macro isw_load_shares_96

    ADD     R10, R0, R12, LSL #2        // pointer to state[i] 
    LDM     R10, {R1,R2,R3,R4,R5,R6}    // load state[i] and state[i+1] 

.endm

// -----------------------------------------------------------------------------

.macro isw_inner_load_shares_96

    ADD     R10, R0, R11, LSL #2        // pointer to state[j]
    LDM     R10, {R7,R8,R9}             // load state[j]


.endm

// -----------------------------------------------------------------------------

.macro isw_store_shares_96 ci, cip1, shift

    ADD     R10, R0, R12, LSL #2              // pointer to state[i]
    STR     \ci,   [R10, #(4*\shift)]         // store c_i
    STR     \cip1, [R10, #(4*SS96+4*\shift)]  // store c_i+1

.endm

// -----------------------------------------------------------------------------

.macro isw_inner_store_shares_96 cj, shift
    
    ADD     R10, R0, R11, LSL #2       // pointer to state[j]
    STR     \cj, [R10, #(4*\shift)]     // store c_j

.endm

// -----------------------------------------------------------------------------

.macro isw_load_shares_128 cshift, ashift, bshift

    ADD     R10, R0, R12, LSL #2       // pointer to state[i] 

    LDR     R1, [R10, #(4*\ashift)]    // load a_i
    LDR     R2, [R10, #(4*\bshift)]    // load b_i
    LDR     R3, [R10, #(4*\cshift)]    // load c_i

    LDR     R4, [R10, #(4*SS128+4*\ashift)]    // load a_i+1
    LDR     R5, [R10, #(4*SS128+4*\bshift)]    // load b_i+1
    LDR     R6, [R10, #(4*SS128+4*\cshift)]    // load c_i+1

.endm

// -----------------------------------------------------------------------------

.macro isw_inner_load_shares_128 cshift, ashift, bshift

    ADD     R10, R0, R11, LSL #2        // pointer to state[j]
   
    LDR     R7, [R10, #(4*\ashift)]    // load a_j
    LDR     R8, [R10, #(4*\bshift)]    // load b_j
    LDR     R9, [R10, #(4*\cshift)]    // load c_j

.endm

// -----------------------------------------------------------------------------

.macro isw_store_shares_128 cshift

    ADD     R10, R0, R12, LSL #2              // pointer to state[i]
    STR     R3, [R10, #(4*\cshift)]           // store c_i
    STR     R6, [R10, #(4*SS128+4*\cshift)]    // store c_i+1

.endm

// -----------------------------------------------------------------------------

.macro isw_inner_store_shares_128 cshift
    
    ADD     R10, R0, R11, LSL #2        // pointer to state[j]
    STR     R9, [R10, #(4*\cshift)]     // store c_j

.endm

// -----------------------------------------------------------------------------
// isw_macc_96_201
// -----------------------------------------------------------------------------

.global isw_macc_96_201
.align 4

isw_macc_96_201:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_96_201:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_96 

        // process iteration (i,i+1)                 
        isw_loop_iteration R1, R2, R3, R4, R5, R6     

        ADD     R11, R12, #(2*SS96)      // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_96_201:

            // load a_j, b_j, c_j
            isw_inner_load_shares_96         

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R1, R2, R3, R4, R5, R6, R7, R8, R9
            
            // store c_j
            isw_inner_store_shares_96 R9, 2
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS96             
            CMP     R11, #(SS96*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_96_201
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_96 R3, R6, 2

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS96)
        CMP     R12, #(SS96*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_96_201
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_96 

    // process iteration (i,i+1)                 
    isw_loop_iteration R1, R2, R3, R4, R5, R6   
           
    // store c_i, c_i+1
    isw_store_shares_96 R3, R6, 2  
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_96_201

// -----------------------------------------------------------------------------
// isw_macc_96_012
// -----------------------------------------------------------------------------

.global isw_macc_96_012
.align 4

isw_macc_96_012:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_96_012:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_96 

        // process iteration (i,i+1)                 
        isw_loop_iteration R2, R3, R1, R5, R6, R4

        ADD     R11, R12, #(2*SS96)      // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_96_012:

            // load a_j, b_j, c_j
            isw_inner_load_shares_96         

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R2, R3, R1, R5, R6, R4, R8, R9, R7
            
            // store c_j
            isw_inner_store_shares_96 R7, 0
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS96             
            CMP     R11, #(SS96*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_96_012
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_96 R1, R4, 0

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS96)
        CMP     R12, #(SS96*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_96_012
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_96 

    // process iteration (i,i+1)                 
    isw_loop_iteration R2, R3, R1, R5, R6, R4
           
    // store c_i, c_i+1
    isw_store_shares_96 R1, R4, 0  
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_96_012

// -----------------------------------------------------------------------------
// isw_macc_96_102
// -----------------------------------------------------------------------------

.global isw_macc_96_102
.align 4

isw_macc_96_102:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_96_102:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_96 

        // process iteration (i,i+1)                 
        isw_loop_iteration R3, R1, R2, R6, R4, R5

        ADD     R11, R12, #(2*SS96)      // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_96_102:

            // load a_j, b_j, c_j
            isw_inner_load_shares_96         

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R3, R1, R2, R6, R4, R5, R9, R7, R8
            
            // store c_j
            isw_inner_store_shares_96 R8, 1
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS96             
            CMP     R11, #(SS96*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_96_102
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_96 R2, R5, 1

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS96)
        CMP     R12, #(SS96*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_96_102
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_96 

    // process iteration (i,i+1)                 
    isw_loop_iteration R3, R1, R2, R6, R4, R5
           
    // store c_i, c_i+1
    isw_store_shares_96 R2, R5, 1
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_96_102

// -----------------------------------------------------------------------------
// isw_macc_128_301
// -----------------------------------------------------------------------------

.global isw_macc_128_301
.align 4

isw_macc_128_301:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_128_301:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_128 3, 0, 1

        // process iteration (i,i+1)                 
        isw_loop_iteration R1, R2, R3, R4, R5, R6

        ADD     R11, R12, #(2*SS128)     // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_128_301:

            // load a_j, b_j, c_j
            isw_inner_load_shares_128 3, 0, 1

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R1, R2, R3, R4, R5, R6, R7, R8, R9
            
            // store c_j
            isw_inner_store_shares_128 3
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS128             
            CMP     R11, #(SS128*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_128_301
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_128 3

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS128)
        CMP     R12, #(SS128*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_128_301
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_128 3, 0, 1

    // process iteration (i,i+1)                 
    isw_loop_iteration R1, R2, R3, R4, R5, R6   
           
    // store c_i, c_i+1
    isw_store_shares_128 3
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_128_301

// -----------------------------------------------------------------------------
// isw_macc_128_012
// -----------------------------------------------------------------------------

.global isw_macc_128_012
.align 4

isw_macc_128_012:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_128_012:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_128 0, 1, 2

        // process iteration (i,i+1)                 
        isw_loop_iteration R1, R2, R3, R4, R5, R6

        ADD     R11, R12, #(2*SS128)     // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_128_012:

            // load a_j, b_j, c_j
            isw_inner_load_shares_128 0, 1, 2

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R1, R2, R3, R4, R5, R6, R7, R8, R9
            
            // store c_j
            isw_inner_store_shares_128 0
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS128             
            CMP     R11, #(SS128*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_128_012
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_128 0

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS128)
        CMP     R12, #(SS128*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_128_012
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_128 0, 1, 2

    // process iteration (i,i+1)                 
    isw_loop_iteration R1, R2, R3, R4, R5, R6   
           
    // store c_i, c_i+1
    isw_store_shares_128 0
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_128_012

// -----------------------------------------------------------------------------
// isw_macc_128_123
// -----------------------------------------------------------------------------

.global isw_macc_128_123
.align 4

isw_macc_128_123:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_128_123:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_128 1, 2, 3

        // process iteration (i,i+1)                 
        isw_loop_iteration R1, R2, R3, R4, R5, R6

        ADD     R11, R12, #(2*SS128)     // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_128_123:

            // load a_j, b_j, c_j
            isw_inner_load_shares_128 1, 2, 3

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R1, R2, R3, R4, R5, R6, R7, R8, R9
            
            // store c_j
            isw_inner_store_shares_128 1
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS128             
            CMP     R11, #(SS128*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_128_123
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_128 1

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS128)
        CMP     R12, #(SS128*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_128_123
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_128 1, 2, 3

    // process iteration (i,i+1)                 
    isw_loop_iteration R1, R2, R3, R4, R5, R6   
           
    // store c_i, c_i+1
    isw_store_shares_128 1
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_128_123

// -----------------------------------------------------------------------------
// isw_macc_128_203
// -----------------------------------------------------------------------------

.global isw_macc_128_203
.align 4

isw_macc_128_203:

    PUSH    {R4-R12, LR} 

    random_init R14               // R14 = RNG address

    MOV     R12, #0               // R12 = loop index i (x3)

____loop_isw_macc_128_203:

        // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
        isw_load_shares_128 2, 0, 3

        // process iteration (i,i+1)                 
        isw_loop_iteration R1, R2, R3, R4, R5, R6

        ADD     R11, R12, #(2*SS128)     // R11 = inner loop index j (x3)
        PUSH    {R12}                    // save R12 on stack

________inner_loop_isw_macc_128_203:

            // load a_j, b_j, c_j
            isw_inner_load_shares_128 2, 0, 3

            // process iterations (i,j) and (i+1,j)
            isw_inner_loop_iteration R1, R2, R3, R4, R5, R6, R7, R8, R9
            
            // store c_j
            isw_inner_store_shares_128 2
           
            //------------------------- loop increment and test
            ADD     R11, R11, #SS128             
            CMP     R11, #(SS128*MASKING_ORDER)
            BNE     ________inner_loop_isw_macc_128_203
            //---------------------------------------- end loop

        POP     {R12}             // restore R12 from stack
        
        // store c_i, c_i+1
        isw_store_shares_128 2

        //------------------------- loop increment and test
        ADD     R12, R12, #(2*SS128)
        CMP     R12, #(SS128*(MASKING_ORDER-2))
        BNE     ____loop_isw_macc_128_203
        //---------------------------------------- end loop


    // last iteration (without inner loop)
   
    // load a_i, b_i, c_i, a_i+1, b_i+1, c_i+1
    isw_load_shares_128 2, 0, 3

    // process iteration (i,i+1)                 
    isw_loop_iteration R1, R2, R3, R4, R5, R6   
           
    // store c_i, c_i+1
    isw_store_shares_128 2
    
    POP     {R4-R12, LR}
    BX      LR

// end isw_macc_128_203

