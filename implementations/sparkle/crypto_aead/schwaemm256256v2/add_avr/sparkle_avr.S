///////////////////////////////////////////////////////////////////////////////
// sparkle_avr.S: AVR Assembler implementation of the SPARKLE permutation.   //
// This file is part of the SPARKLE submission to NIST's LW Crypto Project.  //
// Version 1.1.2 (2020-10-30), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019-2020 University of Luxembourg <http://www.uni.lu/>.    //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////


#include "avr/io.h"


// 32-bit word registers
#define WR0 R0,R1,R2,R3
#define WR1 R4,R5,R6,R7
#define WR2 R8,R9,R10,R11
#define WR3 R12,R13,R14,R15
#define WR4 R16,R17,R18,R19
#define WR5 R20,R21,R22,R23

// Temporary registers
#define t0 R16
#define t1 R17
#define t2 R18
#define t3 R19

// Other register names
#define ZERO R20
#define NS R22
#define SCNT R23
#define NB R24
#define BCNT R25

// 32-bit offset values
#define OF0 0,1,2,3
#define OF1 4,5,6,7
#define OF2 8,9,10,11
#define OF3 12,13,14,15


// Start of the code section (placed in flash memory)
.section .text
.balign 2


///////////////////////////////////////////////////////////////////////////////
///////////// MACROS FOR 32-BIT ARITHMETIC AND LOGICAL OPERATIONS /////////////
///////////////////////////////////////////////////////////////////////////////

// Addition of two 32-bit words: A = A + B
.macro ADDWORD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    ADD  \a0, \b0
    ADC  \a1, \b1
    ADC  \a2, \b2
    ADC  \a3, \b3
.endm

// Bitwise AND of two 32-bit words: A = A AND B
.macro ANDWORD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    AND  \a0, \b0
    AND  \a1, \b1
    AND  \a2, \b2
    AND  \a3, \b3
.endm

// Bitwise XOR of two 32-bit words: A = A XOR B
.macro XORWORD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    EOR  \a0, \b0
    EOR  \a1, \b1
    EOR  \a2, \b2
    EOR  \a3, \b3
.endm

// Moving 32-bit word B to 32-bit word A: A = B
.macro MOVWORD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    MOVW \a0, \b0
    MOVW \a2, \b2
.endm

// ELL-Operation of a 32-bit word: A = ELL(B)
.macro ELLWORD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    MOVW t0, \b2
    MOVW \a2, \b0
    MOVW \a0, t0
    EOR  \a0, \a2
    EOR  \a1, \a3
.endm


///////////////////////////////////////////////////////////////////////////////
////////// MACROS FOR LOADING/STORING STATE WORDS AND ROUND CONSTANTS /////////
///////////////////////////////////////////////////////////////////////////////

// Load 32-bit word via X-pointer from RAM using post-increment addressing mode
.macro LDXINCR a0:req, a1:req, a2:req, a3:req
    LD   \a0, X+
    LD   \a1, X+
    LD   \a2, X+
    LD   \a3, X+
.endm

// Load 32-bit word via Z-pointer from RAM using displacement addressing mode
.macro LDZDISP a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    LDD  \a0, Z+\b0
    LDD  \a1, Z+\b1
    LDD  \a2, Z+\b2
    LDD  \a3, Z+\b3
.endm

// Load 32-bit word via Z-pointer from RAM using post-increment addressing mode
.macro LDZINCR a0:req, a1:req, a2:req, a3:req
    LD   \a0, Z+
    LD   \a1, Z+
    LD   \a2, Z+
    LD   \a3, Z+
.endm

// Load 32-bit word from program memory using post-increment addressing mode
.macro LDZPCMI a0:req, a1:req, a2:req, a3:req
    LPM  \a0, Z+
    LPM  \a1, Z+
    LPM  \a2, Z+
    LPM  \a3, Z+
.endm

// Store 32-bit word via X-pointer to RAM using pre-decrement addressing mode
.macro STXDECR a0:req, a1:req, a2:req, a3:req
    ST   -X, \a3
    ST   -X, \a2
    ST   -X, \a1
    ST   -X, \a0
.endm

// Store 32-bit word via X-pointer to RAM using post-increment addressing mode
.macro STXINCR a0:req, a1:req, a2:req, a3:req
    ST   X+, \a0
    ST   X+, \a1
    ST   X+, \a2
    ST   X+, \a3
.endm

// Store 32-bit word via Z-pointer to RAM using pre-decrement addressing mode
.macro STZDECR a0:req, a1:req, a2:req, a3:req
    ST   -Z, \a3
    ST   -Z, \a2
    ST   -Z, \a1
    ST   -Z, \a0
.endm

// Store 32-bit word via Z-pointer to RAM using displacement addressing mode
.macro STZDISP a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    STD  Z+\b0, \a0
    STD  Z+\b1, \a1
    STD  Z+\b2, \a2
    STD  Z+\b3, \a3
.endm

// Store 32-bit word via Z-pointer to RAM using post-increment addressing mode
.macro STZINCR a0:req, a1:req, a2:req, a3:req
    ST   Z+, \a0
    ST   Z+, \a1
    ST   Z+, \a2
    ST   Z+, \a3
.endm


///////////////////////////////////////////////////////////////////////////////
////// MACROS FOR RIGHT-ROTATION OF A 32-BIT WORD FOLLOWED BY ADD OR XOR //////
///////////////////////////////////////////////////////////////////////////////

// A = A + (B >>> 31)
.macro RR31ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the left
    ADD  t0, t0 
    ADC  t1, t1
    ADC  t2, t2
    ADC  t3, t3
    ADC  t0, ZERO
    // Add word T to word A
    ADD  \a0, t0
    ADC  \a1, t1
    ADC  \a2, t2
    ADC  \a3, t3
.endm

// A = A XOR (B >>> 31)
.macro RR31XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the left
    ADD  t0, t0 
    ADC  t1, t1
    ADC  t2, t2
    ADC  t3, t3
    ADC  t0, ZERO
    // XOR word T to word A
    EOR  \a0, t0
    EOR  \a1, t1
    EOR  \a2, t2
    EOR  \a3, t3
.endm

// A = A + (B >>> 24)
.macro RR24ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Add word B with implicit 24-bit right-rotation to word A
    ADD  \a0, \b3
    ADC  \a1, \b0
    ADC  \a2, \b1
    ADC  \a3, \b2
.endm

// A = A XOR (B >>> 24)
.macro RR24XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // XOR word B with implicit 24-bit right-rotation to word A
    EOR  \a0, \b3
    EOR  \a1, \b0
    EOR  \a2, \b1
    EOR  \a3, \b2
.endm

// A = A + (B >>> 17)
.macro RR17ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the right
    BST  t0, 0
    ROR  t3
    ROR  t2
    ROR  t1
    ROR  t0
    BLD  t3, 7
    // Add word T with implicit 16-bit right-rotation to word A
    ADD  \a0, t2
    ADC  \a1, t3
    ADC  \a2, t0
    ADC  \a3, t1
.endm

// A = A XOR (B >>> 17)
.macro RR17XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the right
    BST  t0, 0
    ROR  t3
    ROR  t2
    ROR  t1
    ROR  t0
    BLD  t3, 7
    // XOR word T with implicit 16-bit right-rotation to word A
    EOR  \a0, t2
    EOR  \a1, t3
    EOR  \a2, t0
    EOR  \a3, t1
.endm

// A = A + (B >>> 16)
.macro RR16ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Add word B with implicit 16-bit right-rotation to word A
    ADD  \a0, \b2
    ADC  \a1, \b3
    ADC  \a2, \b0
    ADC  \a3, \b1
.endm

// A = A XOR (B >>> 16)
.macro RR16XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // XOR word B with implicit 16-bit right-rotation to word A
    EOR  \a0, \b2
    EOR  \a1, \b3
    EOR  \a2, \b0
    EOR  \a3, \b1
.endm

// A = A + (B >>> 15)
.macro RR15ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the left
    ADD  t0, t0 
    ADC  t1, t1
    ADC  t2, t2
    ADC  t3, t3
    ADC  t0, ZERO
    // Add word T with implicit 16-bit right-rotation to word A
    ADD  \a0, t2
    ADC  \a1, t3
    ADC  \a2, t0
    ADC  \a3, t1
.endm

// A = A XOR (B >>> 15)
.macro RR15XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move word B to temporary word T
    MOVW t0, \b0
    MOVW t2, \b2
    // Rotate word T one bit to the left
    ADD  t0, t0 
    ADC  t1, t1
    ADC  t2, t2
    ADC  t3, t3
    ADC  t0, ZERO
    // XOR word T with implicit 16-bit right-rotation to word A
    EOR  \a0, t2
    EOR  \a1, t3
    EOR  \a2, t0
    EOR  \a3, t1
.endm

// A = A + (B >>> 8)
.macro RR08ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Add word B with implicit 8-bit right-rotation to word A
    ADD  \a0, \b1
    ADC  \a1, \b2
    ADC  \a2, \b3
    ADC  \a3, \b0
.endm

// A = A XOR (B >>> 8)
.macro RR08XOR a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // XOR word B with implicit 8-bit right-rotation to word A
    EOR  \a0, \b1
    EOR  \a1, \b2
    EOR  \a2, \b3
    EOR  \a3, \b0
.endm

// A = A + (B >> 16)
.macro RS16ADD a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Add word B with implicit 16-bit right-shift to word A
    ADD  \a0, \b2
    ADC  \a1, \b3
    ADC  \a2, ZERO
    ADC  \a3, ZERO
.endm


///////////////////////////////////////////////////////////////////////////////
//////////////////// PROLOGUE: PUSH CALLEE-SAVED REGISTERS ////////////////////
///////////////////////////////////////////////////////////////////////////////

// Push callee-saved registers on the stack
.macro PROLOGUE
    PUSH R0
    PUSH R2
    PUSH R3
    PUSH R4
    PUSH R5
    PUSH R6
    PUSH R7
    PUSH R8
    PUSH R9
    PUSH R10
    PUSH R11
    PUSH R12
    PUSH R13
    PUSH R14
    PUSH R15
    PUSH R16
    PUSH R17
    // initialize pointers and loop-counters
    MOVW XL, R24
    MOV  NB, R22
    MOV  NS, R20
    ADD  NB, NB
    ADD  NB, NB
    CLR  ZERO
.endm


///////////////////////////////////////////////////////////////////////////////
///////////////////// EPILOGUE: POP CALLEE-SAVED REGISTERS ////////////////////
///////////////////////////////////////////////////////////////////////////////

// Pop callee-saved registers from the stack
.macro EPILOGUE
    POP  R17
    POP  R16
    POP  R15
    POP  R14
    POP  R13
    POP  R12
    POP  R11
    POP  R10
    POP  R9
    POP  R8
    POP  R7
    POP  R6
    POP  R5
    POP  R4
    POP  R3
    POP  R2
    POP  R0
    CLR  R1
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////////// ADDITION OF STEP COUNTER TO STATE //////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro ADD_STEP_CNT
    LDI     ZL, lo8(RCON)
    LDI     ZH, hi8(RCON)
    MOV     t0, SCNT
    ANDI    t0, 7
    ADD     t0, t0
    ADD     t0, t0
    ADD     ZL, t0
    ADC     ZH, ZERO
    LDZPCMI WR0
    ADIW    XL, 4
    LDXINCR WR1
    XORWORD WR1, WR0
    STXDECR WR1
    SBIW    ZL, 4
    SUB     ZL, t0
    SBC     ZH, ZERO
    ADIW    XL, 8
    LD      t0, X
    EOR     t0, SCNT
    ST      X, t0
    SBIW    XL, 12
.endm


///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// ARXBOX LAYER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro ARXBOX_LAYER
    MOV     BCNT, NB       ; set branch-counter to NB
.LARXLOOP1:
    LDXINCR WR0            ; load state-word X
    LDXINCR WR1            ; load state-word Y
    LDZPCMI WR2            ; load round constant C
    RR31ADD WR0, WR1       ; X = X + (Y >>> 31)
    RR24XOR WR1, WR0       ; Y = Y XOR (X >>> 24)
    XORWORD WR0, WR2       ; X = X XOR C
    RR17ADD WR0, WR1       ; X = X + (Y >>> 17)
    RR17XOR WR1, WR0       ; Y = Y XOR (X >>> 17)
    XORWORD WR0, WR2       ; X = X XOR C
    ADDWORD WR0, WR1       ; X = X + (Y >>> 0)
    RR31XOR WR1, WR0       ; Y = Y XOR (X >>> 31)
    XORWORD WR0, WR2       ; X = X XOR C
    RR24ADD WR0, WR1       ; X = X + (Y >>> 24)
    RR16XOR WR1, WR0       ; Y = Y XOR (X >>> 16)
    XORWORD WR0, WR2       ; X = X XOR C
    SBIW    XL,  8         ; decrement X-pointer by 8
    STXINCR WR0,           ; store state-word X
    STXINCR WR1,           ; store state-word Y
    SUBI    BCNT, 4        ; decrement branch-counter by 4
    CPSE    BCNT, ZERO     ; test whether branch-counter is 0
    RJMP    .LARXLOOP1     ; if not then jump back to start
    SUB     XL,  NB        ; set X-pointer to address of state[nb]
    SBC     XH,  ZERO      ; propagate carry
    SUB     XL,  NB        ; set X-pointer to address of state[0]
    SBC     XH,  ZERO      ; propagate carry
.endm


///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// LINEAR LAYER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro LINEAR_LAYER
    PUSH    NS             ; push NS to get one more register
    PUSH    SCNT           ; push SCNT to get one more register
    MOVW    ZL, XL         ; set Z-pointer to address of state[0]
    LDXINCR WR0            ; WR0 = X[0] (WR0 contains tmpx)
    MOVWORD WR1, WR0       ; WR1 = X[0] (WR1 contains x0)
    LDXINCR WR2            ; WR2 = Y[0] (WR2 contains tmpy)
    MOVWORD WR3, WR2       ; WR3 = Y[0] (WR3 contains y0)
    MOV     BCNT, NB       ; set branch-counter to NB
    SUBI    BCNT, 8        ; first iteration of loop below is peeled off
.LLINLOOP1:
    LDXINCR WR4            ; load state-word X[i]
    XORWORD WR0, WR4       ; xor X[i] to tmpx
    LDXINCR WR4            ; load state-word Y[i]
    XORWORD WR2, WR4       ; xor Y[i] to tmpy
    SUBI    BCNT, 8        ; decrement branch-counter
    BRNE    .LLINLOOP1     ; jump back to start if branch-counter is not 0
    ELLWORD WR0, WR0       ; perform ELL operation on tmpx
    ELLWORD WR2, WR2       ; perform ELL operation on tmpy
    ADIW    XL, 8          ; X-pointer contains now address of state[j+nb]
    MOV     BCNT, NB       ; set branch-counter to NB
    SUBI    BCNT, 8        ; last iteration of loop below is peeled off
.LLINLOOP2:
    LDXINCR WR4            ; WR4 = state[j+nb]
    XORWORD WR4, WR2       ; WR4 = state[j+nb] ^ tmpy
    LDZDISP WR5, OF2       ; WR5 = state[j]
    XORWORD WR4, WR5       ; WR4 = state[j+nb] ^ tmpy ^ state[j]
    STXDECR WR5            ; state[j+nb] = WR5
    STZINCR WR4            ; state[j-2] = WR4
    ADIW    XL, 4          ; increment X-pointer manually
    LDXINCR WR4            ; WR4 = state[j+nb+1]
    XORWORD WR4, WR0       ; WR4 = state[j+nb+1] ^ tmpx
    LDZDISP WR5, OF2       ; WR5 = state[j+1]
    XORWORD WR4, WR5       ; WR4 = state[j+nb+1] ^ tmpx ^ state[j+1]
    STXDECR WR5            ; state[j+nb+1] = WR5
    STZINCR WR4            ; state[j-1] = WR4
    ADIW    XL, 4          ; increment X-pointer manually
    SUBI    BCNT, 8        ; decrement branch-counter
    BRNE    .LLINLOOP2     ; jump back to start if branch-counter is not 0
    MOVW    XL, ZL         ; X-pointer contains address of state[nb-1]
    ADIW    XL, 8          ; X-pointer contains address of state[nb]
    LDXINCR WR4            ; WR4 = state[nb]
    XORWORD WR4, WR2       ; WR4 = state[nb] ^ tmpy
    XORWORD WR4, WR1       ; WR4 = state[j+nb] ^ tmpy ^ x0
    STXDECR WR1            ; state[nb] = x0
    STZINCR WR4            ; state[nb-2] = WR4
    ADIW    XL, 4          ; increment X-pointer manually
    LDXINCR WR4            ; WR4 = state[nb+1]
    XORWORD WR4, WR0       ; WR4 = state[nb+1] ^ tmpx
    XORWORD WR4, WR3       ; WR4 = state[j+nb+1] ^ tmpx ^ y0
    STXDECR WR3            ; state[nb+1] = y0
    STZINCR WR4            ; state[nb-1] = WR4
    SBIW    XL, 4          ; decrement X-pointer manually
    CLR     ZERO           ; ZERO register was "misused" above
    SUB     XL, NB         ; restore original address of X-pointer
    SBC     XH, ZERO       ; restore original address of X-pointer
    POP     SCNT           ; restore original content of SCNT
    POP     NS             ; restore original content of NS
.endm


///////////////////////////////////////////////////////////////////////////////
///////////////////////////// SPARKLE PERMUTATION /////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle_avr(uint32_t *state, int brans, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32-array containing 2*brans state words
// brans: number of branches (must be either 4, 6, or 8)
// steps: number of steps
//
// Return value:
// -------------
// None

.global sparkle_avr
.type sparkle_avr, @function
.func sparkle_avr
sparkle_avr:
    PROLOGUE               ; push callee-saved registers
    CLR SCNT               ; clear step-counter
.LMAINLOOP:
    ADD_STEP_CNT           ; macro to add step counter to state
    ARXBOX_LAYER           ; macro for the arxbox layer
    LINEAR_LAYER           ; macro for the linear layer
    INC SCNT               ; increment step-counter
    CPSE SCNT, NS          ; test whether step-counter equals ns
    RJMP .LMAINLOOP        ; if not then jump back to start of loop
    EPILOGUE               ; pop callee-saved registers
    RET
.endfunc

.size sparkle_avr, .-sparkle_avr


///////////////////////////////////////////////////////////////////////////////
///////////////////////// ROUND CONSTANTS FOR SPARKLE /////////////////////////
///////////////////////////////////////////////////////////////////////////////


.section .progmem.data
.balign 4

// .global RCON
.type RCON, @object
.size RCON, 32
RCON:
.long 0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738
.long 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D


.end
