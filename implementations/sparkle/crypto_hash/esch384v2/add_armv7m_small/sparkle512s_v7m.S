///////////////////////////////////////////////////////////////////////////////
// sparkle512s_v7m.asm: Size-optimized ARMv7-M implementation of SPARKLE512. //
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
// it will be useful, but WITHOUT ANY WARRANTY/ without even the implied     //
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
sptr .req r12
// register cptr holds the start address of array 'rcon'
cptr .req lr
// register cnt holds the step counter (for loop termination)
cnt .req r0
// register step holds the number of steps (parameter 'steps')
step .req r1
// registers c0w to c7w hold round constants from array 'rcon'
c0w .req r2
c1w .req r3
c2w .req r2
c3w .req r3
c4w .req r0
c5w .req r1
c6w .req r0
c7w .req r1
// registers tmpx, tmpy hold temporary values
tmpx .req r0
tmpy .req r1
// registers x0w to y7w hold 16 words from array 'state'
x0w .req r4
y0w .req r5
x1w .req r6
y1w .req r7
x2w .req r8
y2w .req r9
x3w .req r10
y3w .req r11
x4w .req r2
y4w .req r3
x5w .req r4
y5w .req r5
x6w .req r6
y6w .req r7
x7w .req r8
y7w .req r9


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// MACROS FOR SPARKLE512 ////////////////////////////
///////////////////////////////////////////////////////////////////////////////

.macro PROLOGUE_512
    push    {r4-r12,lr}
    ldr.w   cptr, =RCON
    ldmia   r0!, {x0w-y3w}
    mov     sptr, r0
.endm

.macro EPILOGUE_512
    stmdb   sptr!, {x0w-y3w}
    pop     {r4-r12,pc}
.endm

.macro ADD_STEP_CNT_512
    eor     y1w, y1w, cnt
    and     c0w, cnt, #7
    ldr     c0w, [cptr, c0w, lsl #2]
    eor     y0w, y0w, c0w
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

.macro ARXBOX_LAYER_512
    // ARX-box computations for the four left-side branches (i.e. x[0]-y[3]).
    // Only two round constants can be loaded at a time (no register space!).
    ldmia   cptr!, {c0w,c1w}
    ARX_BOX x0w, y0w, c0w
    ARX_BOX x1w, y1w, c1w
    ldmia   cptr!, {c2w,c3w}
    ARX_BOX x2w, y2w, c2w
    ARX_BOX x3w, y3w, c3w
    // tmpx and tmpy are computed in two steps; the first is a quadruple XOR,
    // i.e. tmpx = x[0] ^ x[1] ^ x[2] ^ x[3], tmpy = y[0] ^ y[1] ^ y[2] ^ y[3],
    // along with a 16-bit left-shift. The second step is a 16-bit rotation
    // that is carried out as part of the linear layer below.
    LL_TMPX x0w, x1w, x2w, x3w
    LL_TMPY y0w, y1w, y2w, y3w
    push.w  {tmpx,tmpy}
    // ARX-box computations for the first two right-side branches (i.e. the
    // branches x[4]-y[5]) together with a part of the Feistel round (namely
    // the XOR of the two right-side branches with two left branches). After
    // each ARX-box computation, one of the left branches is written to memory
    // since it is not needed anymore.
    ldmia   cptr!, {c4w,c5w}    
    ldmia   sptr, {x4w,y4w}
    ARX_BOX x4w, y4w, c4w
    eor     x4w, x4w, x0w
    eor     y4w, y4w, y0w
    stmia   sptr!, {x0w,y0w}
    ldmia   sptr, {x5w,y5w}    
    ARX_BOX x5w, y5w, c5w
    eor     x5w, x5w, x1w
    eor     y5w, y5w, y1w
    stmia   sptr!, {x1w,y1w}
    // ARX-box computations for the second two right-side branches (i.e. the 
    // branches x[6]-y[7]) together with a part of the Feistel round (namely
    // the XOR of the two right-side branches with two left branches). After
    // each ARX-box computation, one of the left branches is written to memory
    // since it is not needed anymore.
    ldmia   cptr!, {c6w,c7w}
    ldmia   sptr, {x6w,y6w}
    ARX_BOX x6w, y6w, c6w
    eor     x6w, x6w, x2w
    eor     y6w, y6w, y2w
    stmia   sptr!, {x2w,y2w}
    ldmia   sptr, {x7w,y7w}
    ARX_BOX x7w, y7w, c7w
    eor     x7w, x7w, x3w
    eor     y7w, y7w, y3w
    stmia   sptr!, {x3w,y3w}
    // Initialize pointer to state-array and rcon-array for next step
    sub     sptr, sptr, #32
    sub     cptr, cptr, #32
    pop.w   {tmpx,tmpy}
.endm

.macro LINEAR_LAYER_512
    // Most parts of the linear layer (e.g. computation of tmpx/tmpy, first
    // part of Feistel round, and branch permutation) were already carried out
    // in the ARXBOX layer. The remaining part is the 1-branch left-rotation of
    // the (now) right-side branches and the XOR with tmpx and tmpy (which are
    // not yet fully computed since a 16-bit rotations is still lacking).
    eor      y3w, y4w, tmpx, ror #16
    eor      x3w, x4w, tmpy, ror #16
    eor      y2w, y7w, tmpx, ror #16
    eor      x2w, x7w, tmpy, ror #16
    eor      y1w, y6w, tmpx, ror #16
    eor      x1w, x6w, tmpy, ror #16
    eor      y0w, y5w, tmpx, ror #16
    eor      x0w, x5w, tmpy, ror #16
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////// SPARKLE512 PERMUTATION (BRANCH-UNROLLED) ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle512_arm(uint32_t *state, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32_t-array containing the 12 state words
// steps: number of steps (this implementation requires steps to be even!)
//
// Return value:
// -------------
// None

.type sparkle512_arm, %function
.func sparkle512_arm
sparkle512_arm:
    PROLOGUE_512            // push callee-saved registers and load state
    movs cnt, #0            // initialize step-counter
.Lloop_512:                 // start of loop
    push.w {cnt,step}       // push step-counter and 'steps' to free registers
    ADD_STEP_CNT_512        // macro to add step-counter to state
    ARXBOX_LAYER_512        // macro for the ARXBOX layer
    LINEAR_LAYER_512        // macro for the linear layer
    pop {cnt,step}          // restore step-counter and 'steps' from stack
    adds cnt, #1            // increment step-counter
    teq cnt, step           // test whether step-counter equals 'steps'
    bne .Lloop_512          // if not then branch to start of loop
    EPILOGUE_512            // store state and pop callee-saved registers
.endfunc


.size sparkle512_arm, .-sparkle512_arm


///////////////////////////////////////////////////////////////////////////////
/////////////////////////// SPARKLE ROUND CONSTANTS ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

// This implementation places the round constants in the .data segment, which
// means they are loaded from RAM during the computation of the ARX-boxes. It
// would also be possible to place them in the .rodata segment (by replacing
// the ".section .data" directive below by ".section .rodata") so that they are
// loaded from flash, which reduces the RAM consumption by 32 bytes, but may
// increase the execution time on devices with a high number of flash wait
// states.

.section .data
.balign 4


.type RCON, %object
.size RCON, 32
RCON:
.word 0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738
.word 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D


.end
