///////////////////////////////////////////////////////////////////////////////
// sparkle512f_v7m.S: Speed-optimized ARMv7-M implementation of SPARKLE512.  //
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


.global sparkle512_arm


///////////////////////////////////////////////////////////////////////////////
//////////////////////// REGISTER NAMES AND CONSTANTS /////////////////////////
///////////////////////////////////////////////////////////////////////////////

// register sptr holds the start address of array 'state'
sptr .req r0
// register step holds the number of steps (parameter 'steps')
step .req r1
// registers c0w to c7w hold round constants from array 'rcon'
c0w .req r1
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
//////////////////////////// MACROS FOR SPARKLE512 ////////////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro PROLOGUE_512
    push    {r4-r12,lr}
    ldmia   sptr!, {r2-r12,lr}
    push.w  {step}
.endm

.macro EPILOGUE_512
    stmdb.w sptr!, {r6,r7,r12,lr}
    stmdb.w sptr!, {r2,r3,r8,r9,r10,r11}
    stmdb.w sptr!, {r4,r5}
    pop     {r4-r12,pc}
.endm

.macro RET_SLIM_512
    pop     {step}
    cmp     step, #8
    bgt.w   .Lbig_512
    stmdb.w sptr!, {r4,r5}
    stmdb.w sptr!, {r2,r3,r8,r9}
    stmdb.w sptr!, {r10,r11}
    stmdb.w sptr!, {r6,r7,r12,lr}
    pop     {r4-r12,pc}
.Lbig_512:
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

.macro LL_TMPX xi:req, xj:req, xk:req, xl:req
    eor     tmpx, \xi, \xj
    eor     tmpx, tmpx, \xk
    eor     tmpx, tmpx, \xl
    eor     tmpx, tmpx, tmpx, lsl #16
.endm
    
.macro LL_TMPY yi:req, yj:req, yk:req, yl:req
    eor     tmpy, \yi, \yj
    eor     tmpy, tmpy, \yk
    eor     tmpy, tmpy, \yl
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
//// MACRO FOR PERMUTATION-STEP 0 OF SPARKLE512 (USING ROUND-CONSTANT RC0) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_00_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC0
    MOV32   c0w, .Lrc0
    eor     \y0, \y0, c0w
    // ARXBOX Layer part 1
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
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x0,\y0,\x1,\y1}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x6,\y6,\x7,\y7}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 1 OF SPARKLE512 (USING ROUND-CONSTANT RC1) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_01_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC1
    eor     \y1, \y1, #1
    MOV32   c1w, .Lrc1
    eor     \y0, \y0, c1w
    // ARXBOX Layer part 1
    ARX_BOX \x1, \y1, c1w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia   sptr, {\x2,\y2,\x3,\y3}
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x4,\y4,\x5,\y5}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 2 OF SPARKLE512 (USING ROUND-CONSTANT RC2) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_02_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC2
    eor     \y1, \y1, #2
    MOV32   c2w, .Lrc2
    eor     \y0, \y0, c2w
    // ARXBOX Layer part 1
    ARX_BOX \x2, \y2, c2w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x1,\y1,\x0,\y0}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x6,\y6,\x7,\y7}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 3 OF SPARKLE512 (USING ROUND-CONSTANT RC3) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_03_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC3
    eor     \y1, \y1, #3
    MOV32   c3w, .Lrc3
    eor     \y0, \y0, c3w
    // ARXBOX Layer part 1
    ARX_BOX \x3, \y3, c3w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia   sptr, {\x2,\y2,\x3,\y3}
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x5,\y5,\x4,\y4}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 4 OF SPARKLE512 (USING ROUND-CONSTANT RC4) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_04_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC4
    eor     \y1, \y1, #4
    MOV32   c4w, .Lrc4
    eor     \y0, \y0, c4w
    // ARXBOX Layer part 1
    ARX_BOX \x4, \y4, c4w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x1,\y1,\x0,\y0}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x6,\y6,\x7,\y7}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 5 OF SPARKLE512 (USING ROUND-CONSTANT RC5) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_05_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC5
    eor     \y1, \y1, #5
    MOV32   c5w, .Lrc5
    eor     \y0, \y0, c5w
    // ARXBOX Layer part 1
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia   sptr, {\x3,\y3,\x2,\y2}
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x5,\y5,\x4,\y4}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 6 OF SPARKLE512 (USING ROUND-CONSTANT RC6) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_06_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC6
    eor     \y1, \y1, #6
    MOV32   c6w, .Lrc6
    eor     \y0, \y0, c6w
    // ARXBOX Layer part 1
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
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x0,\y0,\x1,\y1}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x7,\y7,\x6,\y6}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 7 OF SPARKLE512 (USING ROUND-CONSTANT RC7) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_07_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC7
    eor     \y1, \y1, #7
    MOV32   c7w, .Lrc7
    eor     \y0, \y0, c7w
    // ARXBOX Layer part 1
    ARX_BOX \x7, \y7, c7w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia   sptr, {\x2,\y2,\x3,\y3}
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x4,\y4,\x5,\y5}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 8 OF SPARKLE512 (USING ROUND-CONSTANT RC0) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_08_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC0
    eor     \y1, \y1, #8
    MOV32   c0w, .Lrc0
    eor     \y0, \y0, c0w
    // ARXBOX Layer part 1
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
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x0,\y0,\x1,\y1}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x6,\y6,\x7,\y7}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 9 OF SPARKLE512 (USING ROUND-CONSTANT RC1) ////
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_09_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC1
    eor     \y1, \y1, #9
    MOV32   c1w, .Lrc1
    eor     \y0, \y0, c1w
    // ARXBOX Layer part 1
    ARX_BOX \x1, \y1, c1w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia   sptr, {\x3,\y3,\x2,\y2}
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x4,\y4,\x5,\y5}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 10 OF SPARKLE512 (USING ROUND-CONSTANT RC2) ///
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_10_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC2
    eor     \y1, \y1, #10
    MOV32   c2w, .Lrc2
    eor     \y0, \y0, c2w
    // ARXBOX Layer part 1
    ARX_BOX \x2, \y2, c2w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c3w, .Lrc3
    ARX_BOX \x3, \y3, c3w
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    push.w  {tmpy}
    stmdb   sptr, {\x1,\y1,\x0,\y0}
    // ARXBOX Layer part 2
    ldmia   sptr, {\x7,\y7,\x6,\y6}
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    pop.w   {tmpx}
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
.endm


///////////////////////////////////////////////////////////////////////////////
//// MACRO FOR PERMUTATION-STEP 11 OF SPARKLE512 (USING ROUND-CONSTANT RC3) ///
///////////////////////////////////////////////////////////////////////////////

.macro PERM_STEP_11_512 x0:req, y0:req, x1:req, y1:req, x2:req, y2:req, \
                        x3:req, y3:req, x4:req, y4:req, x5:req, y5:req, \
                        x6:req, y6:req, x7:req, y7:req
    // Addition RC3
    eor     \y1, \y1, #11
    MOV32   c3w, .Lrc3
    eor     \y0, \y0, c3w
    // ARXBOX Layer part 1
    ARX_BOX \x3, \y3, c3w
    MOV32   c0w, .Lrc0
    ARX_BOX \x0, \y0, c0w
    MOV32   c1w, .Lrc1
    ARX_BOX \x1, \y1, c1w
    MOV32   c2w, .Lrc2
    ARX_BOX \x2, \y2, c2w
    MOV32   c6w, .Lrc6
    ARX_BOX \x6, \y6, c6w
    MOV32   c7w, .Lrc7
    ARX_BOX \x7, \y7, c7w
    // Linear Layer part 1
    LL_TMPX \x0, \x1, \x2, \x3
    LL_ADDY \y6, \y2
    LL_ADDY \y7, \y3
    push.w  {tmpx}
    LL_TMPY \y0, \y1, \y2, \y3
    LL_ADDX \x6, \x2
    LL_ADDX \x7, \x3
    push.w  {tmpy}
    stmia.w sptr!, {\x2,\y2}
    stmia.w sptr!, {\x3,\y3}
    sub     sptr, sptr, #16
    // ARXBOX Layer part 2
    ldmdb   sptr, {\x5,\y5,\x4,\y4}
    MOV32   c4w, .Lrc4
    ARX_BOX \x4, \y4, c4w
    MOV32   c5w, .Lrc5
    ARX_BOX \x5, \y5, c5w
    // Linear Layer part 2
    pop.w   {tmpy}
    LL_ADDX \x4, \x0
    LL_ADDX \x5, \x1
    pop.w   {tmpx}
    LL_ADDY \y4, \y0
    LL_ADDY \y5, \y1
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// SPARKLE512 PERMUTATION (FULLY UNROLLED) ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle512_arm(uint32_t *state, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32_t-array containing the 16 state words
// steps: number of steps (must be either 8 or 12)
//
// Return value:
// -------------
// None

.type sparkle512_arm, %function
.func sparkle512_arm
sparkle512_arm:
    PROLOGUE_512
    // step 0: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM.
    // these branches share the following physical registers: r2, r3, r4, r5.
    PERM_STEP_00_512  r2,  r3,  r4,  r5,  r6,  r7,  r8,  r9, \
                     r10, r11, r12,  lr,  r2,  r3,  r4,  r5
    // step 1: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM.
    // these branches share the following physical registers: r4, r5, r10, r11.
    PERM_STEP_01_512 r12,  lr,  r2,  r3,  r4,  r5, r10, r11, \
                      r4,  r5, r10, r11,  r6,  r7,  r8,  r9
    // step 2: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM.
    // these branches share the following physical registers: r6, r7, r10, r11.
    PERM_STEP_02_512 r10, r11,  r6,  r7,  r8,  r9,  r4,  r5, \
                     r12,  lr,  r2,  r3,  r6,  r7, r10, r11
    // step 3: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM.
    // these branches share the following physical registers: r10, r11, r12, lr
    PERM_STEP_03_512  r2,  r3,  r6,  r7, r10, r11, r12,  lr, \
                     r12,  lr, r10, r11,  r8,  r9,  r4,  r5
    // step 4: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM.
    // these branches share the following physical registers: r8, r9, r10, r11.
    PERM_STEP_04_512 r10, r11,  r8,  r9,  r4,  r5, r12,  lr, \
                      r2,  r3,  r6,  r7,  r8,  r9, r10, r11
    // step 5: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM.
    // these branches share the following physical registers: r2, r3, r10, r11.
    PERM_STEP_05_512  r6,  r7,  r8,  r9, r10, r11,  r2,  r3, \
                     r10, r11,  r2,  r3,  r4,  r5, r12,  lr
    // step 6: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM.
    // these branches share the following physical registers: r2, r3, r4, r5.
    PERM_STEP_06_512  r2,  r3,  r4,  r5, r12,  lr, r10, r11, \
                      r6,  r7,  r8,  r9,  r4,  r5,  r2,  r3
    // step 7: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM.
    // these branches share the following physical registers: r2, r3, r6, r7.
    PERM_STEP_07_512  r8,  r9,  r4,  r5,  r2,  r3,  r6,  r7, \
                      r2,  r3,  r6,  r7, r12,  lr, r10, r11    
    RET_SLIM_512 // return when the number of steps is slim
    // step 8: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM.
    // these branches share the following physical registers: r6, r7 , r12, lr.
    PERM_STEP_08_512  r6,  r7, r12,  lr, r10, r11,  r2,  r3, \
                      r8,  r9,  r4,  r5,  r6,  r7, r12,  lr
    // step 9: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM.
    // these branches share the following physical registers: r8, r9, r12, lr.
    PERM_STEP_09_512  r4,  r5,  r6,  r7, r12,  lr,  r8,  r9, \
                      r8,  r9, r12,  lr, r10, r11,  r2,  r3
    // step 10: branches (Z6,Z7) are loaded from RAM and (Z0,Z1) written to RAM
    // these branches share the following physical registers: r10, r11, r12, lr
    PERM_STEP_10_512 r12,  lr, r10, r11,  r2,  r3,  r8,  r9, \
                      r4,  r5,  r6,  r7, r12,  lr, r10, r11
    // step 11: branches (Z4,Z5) are loaded from RAM and (Z2,Z3) written to RAM
    // these branches share the following physical registers: r4, r5, r10, r11.
    PERM_STEP_11_512  r6,  r7, r12,  lr, r10, r11,  r4,  r5, \
                     r10, r11,  r4,  r5,  r2,  r3,  r8,  r9
    EPILOGUE_512
.endfunc


.size sparkle512_arm, .-sparkle512_arm


.end
