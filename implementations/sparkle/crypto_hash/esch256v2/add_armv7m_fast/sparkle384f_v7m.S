///////////////////////////////////////////////////////////////////////////////
// sparkle384f_v7m.S: Speed-optimized ARMv7-M implementation of SPARKLE384.  //
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


.syntax unified
.thumb
.arch armv7-m
.eabi_attribute Tag_ABI_align_preserved, 1


.section .text
.balign 4


.global sparkle384_arm


///////////////////////////////////////////////////////////////////////////////
//////////////////////// REGISTER NAMES AND CONSTANTS /////////////////////////
///////////////////////////////////////////////////////////////////////////////

// register sptr holds the start address of array 'state'
sptr .req r0
// register step holds the number of steps (parameter 'steps')
step .req r1
// registers c0w to c7w hold round constants from array 'rcon'
c0w .req r0
c1w .req r1
c2w .req r1
c3w .req r1
c4w .req r1
c5w .req r1
c6w .req r1
c7w .req r1
// registers tmpx, tmpy hold temporary values
tmpx .req r1
tmpy .req r1
// registers x0w to y5w hold 12 words from array 'state'
x0w .req r2
y0w .req r3
x1w .req r4
y1w .req r5
x2w .req r6
y2w .req r7
x3w .req r8
y3w .req r9
x4w .req r10
y4w .req r11
x5w .req r12
y5w .req lr

// Round constants
.equ .Lrc0, 0xB7E15162
.equ .Lrc1, 0xBF715880
.equ .Lrc2, 0x38B4DA56
.equ .Lrc3, 0x324E7738
.equ .Lrc4, 0xBB1185EB
.equ .Lrc5, 0x4F7C7B57
.equ .Lrc6, 0xCFBFA1C8
.equ .Lrc7, 0xC2B3293D


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// MACROS FOR SPARKLE384 ////////////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro PROLOGUE_384
    push    {r4-r12,lr}
    ldmia   sptr, {x0w-x5w,y5w}
    push.w  {sptr,step}
.endm

.macro EPILOGUE_384
    pop.w   {sptr}
    stmia.w sptr!, {x3w-x5w,y5w}
    stmia.w sptr!, {x2w,y2w}
    stmia.w sptr!, {x0w-y1w}
    pop     {r4-r12,pc}
.endm

.macro RET_SLIM_384
    pop     {sptr,step}
    cmp     step, #7
    bgt.w   .Lbig_384
    stmia.w sptr!, {x4w-x5w,y5w}
    stmia.w sptr!, {x3w,y3w}
    stmia.w sptr!, {x0w-y2w}
    pop     {r4-r12,pc}
.Lbig_384:
    push.w  {sptr}
.endm

.macro ARX_BOX xi:req, yi:req, ci:req
    add     \xi, \xi, \yi, ror #31
    eor     \yi, \yi, \xi, ror #24
    eor     \xi, \xi, \ci
    add     \xi, \xi, \yi, ror #17
    eor     \yi, \yi, \xi, ror #17
    eors    \xi, \xi, \ci
    adds    \xi, \xi, \yi
    eor     \yi, \yi, \xi, ror #31
    eor     \xi, \xi, \ci
    add     \xi, \xi, \yi, ror #24
    eor     \yi, \yi, \xi, ror #16
    eor     \xi, \xi, \ci
.endm

.macro MOV32 ri:req, ci:req
    movw    \ri, #:lower16:\ci
    movt    \ri, #:upper16:\ci
.endm

.macro LL_TMPX xi:req, xj:req, xk:req
    eor     tmpx, \xi, \xj
    eor     tmpx, tmpx, \xk
    eor     tmpx, tmpx, tmpx, lsl #16
.endm
    
.macro LL_TMPY yi:req, yj:req, yk:req
    eor     tmpy, \yi, \yj
    eor     tmpy, tmpy, \yk
    eor     tmpy, tmpy, tmpy, lsl #16
.endm
    
.macro LL_ADDX xi:req, xj:req
    eor     \xi, \xi, tmpy, ror #16
    eor     \xi, \xi, \xj
.endm
    
.macro LL_ADDY yi:req, yj:req
    eor     \yi, \yi, tmpx, ror #16
    eor     \yi, \yi, \yj
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 0 OF SPARKLE384 (USING ROUND-CONSTANT RC0) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_00_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC0
    MOV32   c0w, .Lrc0
    eor     \y0, \y0, c0w
    // ARXBOX Layer
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 1 OF SPARKLE384 (USING ROUND-CONSTANT RC1) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_01_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC1
    eor     \y1, \y1, #1
    MOV32   c1w, .Lrc1
    eor     \y0, \y0, c1w
    // ARXBOX Layer
    ARX_BOX \x1, \y1, c1w
    ARX_BOX \x0, \y0, c0w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 2 OF SPARKLE384 (USING ROUND-CONSTANT RC2) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_02_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC2
    eor     \y1, \y1, #2
    MOV32   c2w, .Lrc2
    eor     \y0, \y0, c2w
    // ARXBOX Layer
    ARX_BOX \x2, \y2, c2w
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 3 OF SPARKLE384 (USING ROUND-CONSTANT RC3) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_03_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC3
    eor     \y1, \y1, #3
    MOV32   c3w, .Lrc3
    eor     \y0, \y0, c3w
    // ARXBOX Layer
    ARX_BOX \x3, \y3, c3w
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 4 OF SPARKLE384 (USING ROUND-CONSTANT RC4) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_04_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC4
    eor     \y1, \y1, #4
    MOV32   c4w, .Lrc4
    eor     \y0, \y0, c4w
    // ARXBOX Layer
    ARX_BOX \x4, \y4, c4w
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 5 OF SPARKLE384 (USING ROUND-CONSTANT RC5) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_05_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC5
    eor     \y1, \y1, #5
    MOV32   c5w, .Lrc5
    eor     \y0, \y0, c5w
    // ARXBOX Layer
    ARX_BOX \x5, \y5, c5w
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 6 OF SPARKLE384 (USING ROUND-CONSTANT RC6) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_06_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC6
    eor     \y1, \y1, #6
    MOV32   c6w, .Lrc6
    eor     \y0, \y0, c6w
    // ARXBOX Layer
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 7 OF SPARKLE384 (USING ROUND-CONSTANT RC7) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_07_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC7
    eor     \y1, \y1, #7
    MOV32   c7w, .Lrc7
    eor     \y0, \y0, c7w
    // ARXBOX Layer
    MOV32   c0w, .Lrc0    
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 8 OF SPARKLE384 (USING ROUND-CONSTANT RC0) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_08_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC0
    eor     \y1, \y1, #8
    eor     \y0, \y0, c0w
    // ARXBOX Layer
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 9 OF SPARKLE384 (USING ROUND-CONSTANT RC1) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_09_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC1
    eor     \y1, \y1, #9
    MOV32   c1w, .Lrc1
    eor     \y0, \y0, c1w
    // ARXBOX Layer
    ARX_BOX \x1, \y1, c1w
    ARX_BOX \x0, \y0, c0w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 10 OF SPARKLE384 (USING ROUND-CONSTANT RC2) ///
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_10_384 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req
    // Addition RC2
    eor     \y1, \y1, #10
    MOV32   c2w, .Lrc2
    eor     \y0, \y0, c2w
    // ARXBOX Layer
    ARX_BOX \x2, \y2, c2w
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer
    LL_TMPX \x0, \x1, \x2
    LL_ADDY \y3, \y0
    LL_ADDY \y4, \y1
    LL_ADDY \y5, \y2
    LL_TMPY \y0, \y1, \y2
    LL_ADDX \x3, \x0
    LL_ADDX \x4, \x1
    LL_ADDX \x5, \x2
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// SPARKLE384 PERMUTATION (FULLY UNROLLED) ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle384_arm(uint32_t *state, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32_t-array containing the 12 state words
// steps: number of steps (must be either 7 or 11)
//
// Return value:
// -------------
// None

.type sparkle384_arm, %function
.func sparkle384_arm
sparkle384_arm:
    PROLOGUE_384
    PERM_STEP_00_384 x0w, y0w, x1w, y1w, x2w, y2w, x3w, y3w, x4w, y4w, x5w, y5w
    PERM_STEP_01_384 x4w, y4w, x5w, y5w, x3w, y3w, x0w, y0w, x1w, y1w, x2w, y2w
    PERM_STEP_02_384 x1w, y1w, x2w, y2w, x0w, y0w, x4w, y4w, x5w, y5w, x3w, y3w
    PERM_STEP_03_384 x5w, y5w, x3w, y3w, x4w, y4w, x1w, y1w, x2w, y2w, x0w, y0w
    PERM_STEP_04_384 x2w, y2w, x0w, y0w, x1w, y1w, x5w, y5w, x3w, y3w, x4w, y4w
    PERM_STEP_05_384 x3w, y3w, x4w, y4w, x5w, y5w, x2w, y2w, x0w, y0w, x1w, y1w
    PERM_STEP_06_384 x0w, y0w, x1w, y1w, x2w, y2w, x3w, y3w, x4w, y4w, x5w, y5w
    RET_SLIM_384 // return when the number of steps is slim
    PERM_STEP_07_384 x4w, y4w, x5w, y5w, x3w, y3w, x0w, y0w, x1w, y1w, x2w, y2w
    PERM_STEP_08_384 x1w, y1w, x2w, y2w, x0w, y0w, x4w, y4w, x5w, y5w, x3w, y3w
    PERM_STEP_09_384 x5w, y5w, x3w, y3w, x4w, y4w, x1w, y1w, x2w, y2w, x0w, y0w
    PERM_STEP_10_384 x2w, y2w, x0w, y0w, x1w, y1w, x5w, y5w, x3w, y3w, x4w, y4w
    EPILOGUE_384
.endfunc


.size sparkle384_arm, .-sparkle384_arm


.end
