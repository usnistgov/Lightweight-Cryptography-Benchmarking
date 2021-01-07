///////////////////////////////////////////////////////////////////////////////
// ascon_avr.S: AVR Assembler implementation of the ASCON permutation.       //
// Version 1.0.0 (2020-09-19), see <http://www.cryptolux.org/> for updates.  //
// Author: Johann Groszschaedl, (DCS and SnT, University of Luxembourg).     //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 20220 University of Luxembourg <http://www.uni.lu/>.        //
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


// Register pairs for 16-bit slice-registers
#define SR0 R0,R1
#define SR1 R4,R5
#define SR2 R8,R9
#define SR3 R12,R13
#define SR4 R16,R17

// Register pairs for 16-bit temp-registers
#define TR0 R2,R3
#define TR1 R6,R7
#define TR2 R10,R11
#define TR3 R14,R15
#define TR4 R18,R19

// Other temporary registers
#define t0 R24
#define t1 R25
#define t2 R26
#define t3 R27

// Other register names
#define ZERO R20
#define RCON R21
#define RCTR R22
#define SCTR R23

// Register octets for 64-bit word-registers
#define WRA R0,R1,R2,R3,R4,R5,R6,R7
#define WRB R8,R9,R10,R11,R12,R13,R14,R15
#define WRC R16,R17,R18,R19,R24,R25,R26,R27

// Offset values
#define OF0  0,1,2,3,4,5,6,7
#define OF8  8,9,10,11,12,13,14,15
#define OF16 16,17,18,19,20,21,22,23
#define OF24 24,25,26,27,28,29,30,31
#define OF32 32,33,34,35,36,37,38,39


// Program flash data section (in code memory space)
.section .text


///////////////////////////////////////////////////////////////////////////////
/////// MACROS FOR 16-BIT ARITHMETIC/LOGICAL OPERATIONS AND LOADS/STORES //////
///////////////////////////////////////////////////////////////////////////////

// Bitwise AND of two 16-bit words: A = A & B
.macro AND16 a0:req, a1:req, b0:req, b1:req
    AND  \a0, \b0
    AND  \a1, \b1
.endm

// Bitwise XOR of two 16-bit words: A = A ^ B
.macro XOR16 a0:req, a1:req, b0:req, b1:req
    EOR  \a0, \b0
    EOR  \a1, \b1
.endm

// One's complement of a 16-bit word: A = ~A
.macro COM16 a0:req, a1:req
    COM  \a0
    COM  \a1
.endm

// One's complement of a 16-bit word ANDed with a 16-bit word: A = ~B & C
.macro CAN16 a0:req, a1:req, b0:req, b1:req, c0:req, c1:req
    MOVW \a0, \b0
    COM  \a0
    COM  \a1
    AND  \a0, \c0
    AND  \a1, \c1
.endm

// Load 16-bit word via Z-pointer from RAM using displacement addressing
.macro LDZ16_DIS a0:req, a1:req, b0:req, b1:req
    LDD  \a0, Z+\b0
    LDD  \a1, Z+\b1
.endm

// Store 16-bit word via Z-pointer to RAM using displacement addressing
.macro STZ16_DIS a0:req, a1:req, b0:req, b1:req
    STD  Z+\b0, \a0
    STD  Z+\b1, \a1
.endm


///////////////////////////////////////////////////////////////////////////////
/////// MACROS FOR 64-BIT ARITHMETIC/LOGICAL OPERATIONS AND LOADS/STORES //////
///////////////////////////////////////////////////////////////////////////////

// Move a 64-bit word from register B to register A: A = B
.macro MOV64 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
             b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    MOVW \a0, \b0
    MOVW \a2, \b2
    MOVW \a4, \b4
    MOVW \a6, \b6
.endm

// Rotate a 64-bit word 1 bit to the left: A = (A << 1)
.macro ROL64 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req
    LSL  \a0
    ROL  \a1
    ROL  \a2
    ROL  \a3
    ROL  \a4
    ROL  \a5
    ROL  \a6
    ROL  \a7
    ADC  \a0, ZERO
.endm

// Rotate a 64-bit word 1-bit to the right: A = (A >> 1)
.macro ROR64 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req
    BST  \a0, 0
    ROR  \a7
    ROR  \a6
    ROR  \a5
    ROR  \a4
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    BLD  \a7, 7
.endm

// Bitwise XOR of two 64-bit words: A = A ^ B
.macro XOR64 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
             b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    EOR  \a0, \b0
    EOR  \a1, \b1
    EOR  \a2, \b2
    EOR  \a3, \b3
    EOR  \a4, \b4
    EOR  \a5, \b5
    EOR  \a6, \b6
    EOR  \a7, \b7
.endm

// XOR of two 64-bit words with implicit 8-bit right-shift: A = A ^ (B >> 8)
.macro XOR64_R08 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    EOR  \a0, \b1
    EOR  \a1, \b2
    EOR  \a2, \b3
    EOR  \a3, \b4
    EOR  \a4, \b5
    EOR  \a5, \b6
    EOR  \a6, \b7
    EOR  \a7, \b0
.endm

// XOR of two 64-bit words with implicit 16-bit right-shift: A = A ^ (B >> 16)
.macro XOR64_R16 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    EOR  \a0, \b2
    EOR  \a1, \b3
    EOR  \a2, \b4
    EOR  \a3, \b5
    EOR  \a4, \b6
    EOR  \a5, \b7
    EOR  \a6, \b0
    EOR  \a7, \b1
.endm

// XOR of two 64-bit words with implicit 24-bit right-shift: A = A ^ (B >> 24)
.macro XOR64_R24 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    EOR  \a0, \b3
    EOR  \a1, \b4
    EOR  \a2, \b5
    EOR  \a3, \b6
    EOR  \a4, \b7
    EOR  \a5, \b0
    EOR  \a6, \b1
    EOR  \a7, \b2
.endm

// XOR of two 64-bit words with implicit 24-bit left-shift: A = A ^ (B << 24)
.macro XOR64_L24 a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    EOR  \a0, \b5
    EOR  \a1, \b6
    EOR  \a2, \b7
    EOR  \a3, \b0
    EOR  \a4, \b1
    EOR  \a5, \b2
    EOR  \a6, \b3
    EOR  \a7, \b4
.endm

// Load 64-bit word via Z-pointer from RAM using displacement addressing
.macro LDZ64_DIS a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    LDD  \a0, Z+\b0
    LDD  \a1, Z+\b1
    LDD  \a2, Z+\b2
    LDD  \a3, Z+\b3
    LDD  \a4, Z+\b4
    LDD  \a5, Z+\b5
    LDD  \a6, Z+\b6
    LDD  \a7, Z+\b7
.endm

// Load 64-bit word via Z-pointer from RAM using displacement addressing
.macro STZ64_DIS a0:req, a1:req, a2:req, a3:req, a4:req, a5:req, a6:req, a7:req, \
                 b0:req, b1:req, b2:req, b3:req, b4:req, b5:req, b6:req, b7:req
    STD  Z+\b0, \a0
    STD  Z+\b1, \a1
    STD  Z+\b2, \a2
    STD  Z+\b3, \a3
    STD  Z+\b4, \a4
    STD  Z+\b5, \a5
    STD  Z+\b6, \a6
    STD  Z+\b7, \a7
.endm


///////////////////////////////////////////////////////////////////////////////
////////// PROLOGUE AND EPILOGUE: PUSH AND POP CALLEE-SAVED REGISTERS /////////
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
    MOVW ZL, R24
    MOV  RCTR, R22
    CLR  ZERO
    // initialize round constant RCON
    LDI  t0, 12
    SUB  t0, RCTR
    LDI  RCON, 15
    SUB  RCON, t0
    SWAP RCON
    OR   RCON, t0
.endm

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
///////////////////// MACRO FOR ADDITION OF ROUND CONSTANT ////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro ADD_RCON
    LDD  t0, Z+16
    EOR  t0, RCON
    SUBI RCON, 15
    STD  Z+16, t0
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// MACROS FOR NONLINEAR SUBSTITUTION LAYER ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Load a 16-bit slice from each 64-bit word of the state
.macro LOAD_SLICE
    LDZ16_DIS SR0, 0,1
    LDZ16_DIS SR1, 8,9
    LDZ16_DIS SR2, 16,17
    LDZ16_DIS SR3, 24,25
    LDZ16_DIS SR4, 32,33
.endm

// Perform the Ascon Sbox operation on five 16-bit slices
.macro SBOX_SLICE
    XOR16     SR0, SR4          // X0 = X0 ^ X4
    XOR16     SR2, SR1          // X2 = X2 ^ X1
    XOR16     SR4, SR3          // X4 = X4 ^ X3
    CAN16     TR0, SR1, SR2     // T0 = ~X1 & X2
    CAN16     TR1, SR2, SR3     // T1 = ~X2 & X3
    CAN16     TR2, SR3, SR4     // T2 = ~X3 & X4
    CAN16     TR3, SR4, SR0     // T3 = ~X4 & X0
    CAN16     TR4, SR0, SR1     // T4 = ~X0 & X1
    XOR16     SR0, TR0          // X0 = X0 ^ T0
    XOR16     SR1, TR1          // X1 = X1 ^ T1
    XOR16     SR2, TR2          // X2 = X2 ^ T2
    XOR16     SR3, TR3          // X3 = X3 ^ T3
    XOR16     SR4, TR4          // X4 = X4 ^ T4
    XOR16     SR1, SR0          // X1 = X1 ^ X0
    XOR16     SR3, SR2          // X3 = X3 ^ X2
    XOR16     SR0, SR4          // X0 = X0 ^ X4
    COM16     SR2               // X2 = ~X2
.endm

// Store a 16-bit slice from each 64-bit word of the state
.macro STORE_SLICE
    STZ16_DIS SR0, 0,1
    STZ16_DIS SR1, 8,9
    STZ16_DIS SR2, 16,17
    STZ16_DIS SR3, 24,25
    STZ16_DIS SR4, 32,33
.endm

// Nonlinear substitution layer
.macro SBOX_LAYER
    LDI  SCTR, 4
.LOOP_SLICE:
    LOAD_SLICE
    SBOX_SLICE
    STORE_SLICE
    ADIW ZL, 2
    DEC  SCTR
    CPSE SCTR, ZERO        ; test whether round-counter is 0
    RJMP .LOOP_SLICE       ; if not then jump back to start of loop
    SBIW ZL, 8
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////////// MACROS FOR LINEAR DIFFUSION LAYER //////////////////////
///////////////////////////////////////////////////////////////////////////////

// Load 64-bit word X0 of state from RAM
.macro LOAD_WORD0
    LDZ64_DIS WRA, OF0
.endm

// Linear diffusion operation for word X0: X0 = X0 ^ (X0 >> 19) ^ (X0 >> 28)
.macro LDIF_WORD0
    MOV64     WRB, WRA
    ROR64     WRB
    ROR64     WRB
    ROR64     WRB
    XOR64_R16 WRA, WRB
    ROR64     WRB
    XOR64_R24 WRA, WRB
.endm

// Store 64-bit word X0 of state to RAM
.macro STORE_WORD0
    STZ64_DIS WRA, OF0
.endm

// Load 64-bit word X1 of state from RAM
.macro LOAD_WORD1
    LDZ64_DIS WRA, OF8
.endm

// Linear diffusion operation for word X1: X1 = X1 ^ (X1 >> 61) ^ (X1 >> 39)
.macro LDIF_WORD1
    MOV64     WRB, WRA
    ROL64     WRB
    XOR64_L24 WRA, WRB
    ROL64     WRB
    ROL64     WRB
    XOR64     WRA, WRB
.endm

// Store 64-bit word X1 of state to RAM
.macro STORE_WORD1
    STZ64_DIS WRA, OF8
.endm

// Load 64-bit word X2 of state from RAM
.macro LOAD_WORD2
    LDZ64_DIS WRA, OF16
.endm

// Linear diffusion operation for word X2: X2 = X2 ^ (X2 >> 1) ^ (X2 >> 6)
.macro LDIF_WORD2
    MOV64     WRB, WRA
    MOV64     WRC, WRA
    ROR64     WRB
    XOR64     WRA, WRB
    ROL64     WRC
    ROL64     WRC
    XOR64_R08 WRA, WRC
.endm

// Store 64-bit word X2 of state to RAM
.macro STORE_WORD2
    STZ64_DIS WRA, OF16
.endm

// Load 64-bit word X3 of state from RAM
.macro LOAD_WORD3
    LDZ64_DIS WRA, OF24
.endm

// Linear diffusion operation for word X3: X3 = X3 ^ (X3 >> 10) ^ (X3 >> 17)
.macro LDIF_WORD3
    MOV64     WRB, WRA
    ROR64     WRB
    XOR64_R16 WRA, WRB
    ROR64     WRB
    XOR64_R08 WRA, WRB
.endm

// Store 64-bit word X3 of state to RAM
.macro STORE_WORD3
    STZ64_DIS WRA, OF24
.endm

// Load 64-bit word X4 of state from RAM
.macro LOAD_WORD4
    LDZ64_DIS WRA, OF32
.endm

// Linear diffusion operation for word X4: X4 = X4 ^ (X4 >> 7) ^ (X4 >> 41)
.macro LDIF_WORD4
    MOV64     WRB, WRA
    MOV64     WRC, WRA
    ROL64     WRB
    XOR64_R08 WRA, WRB
    ROR64     WRC
    XOR64_L24 WRA, WRC
.endm

// Store 64-bit word X4 of state to RAM
.macro STORE_WORD4
    STZ64_DIS WRA, OF32
.endm

// Linear diffusion layer
.macro LIN_LAYER
    LOAD_WORD0
    LDIF_WORD0
    STORE_WORD0
    LOAD_WORD1
    LDIF_WORD1
    STORE_WORD1
    LOAD_WORD2
    LDIF_WORD2
    STORE_WORD2
    LOAD_WORD3
    LDIF_WORD3
    STORE_WORD3
    LOAD_WORD4
    LDIF_WORD4
    STORE_WORD4
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////////////////// ASCON PERMUTATION //////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void ascon_perm_avr(state *s, int r)
//
// Parameters:
// -----------
// s: pointer to a struct containing five 64-bit state words
// r: number of rounds
//
// Return value:
// -------------
// None

.global ascon_perm_avr
.type ascon_perm_avr, @function
.func ascon_perm_avr
ascon_perm_avr:
    PROLOGUE                    // push callee-saved registers
.LOOP_MAIN:                     // start of main loop
    ADD_RCON                    // add round constant to X2
    SBOX_LAYER                  // macro for the sbox layer
    LIN_LAYER                   // macro for the linear layer
    DEC RCTR                    // decrement round-counter
    CPSE RCTR, ZERO             // test whether round-counter is 0
    RJMP .LOOP_MAIN             // if not then jump back to start of loop
    EPILOGUE                    // pop callee-saved registers
    RET
.endfunc


.size ascon_perm_avr, .-ascon_perm_avr


.end
