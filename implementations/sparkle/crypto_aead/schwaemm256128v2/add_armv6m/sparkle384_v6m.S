///////////////////////////////////////////////////////////////////////////////
// sparkle384_v6m.S: ARMv6-M implementation of the SPARKLE384 permutation.   //
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
.arch armv6-m
.eabi_attribute Tag_ABI_align_preserved, 1


.section .text
.balign 4


.global sparkle384_arm


///////////////////////////////////////////////////////////////////////////////
//////////////////////// REGISTER NAMES AND CONSTANTS /////////////////////////
///////////////////////////////////////////////////////////////////////////////
    
// register sptr holds the start address of array 'state'
sptr .req r0
// register cptr holds the start address of array 'rcon'
cptr .req r1
// register imm holds an immediate value
imm .req r1
// register cnt holds the step counter (for loop termination)
cnt .req r6
// register step holds the number of steps (parameter 'steps')
step .req r7
// registers xlw and ylw hold x-word and y-word of a left-side branch
xlw .req r2
ylw .req r3
// registers xrw and yrw hold x-word and y-word of a right-side branch
xrw .req r4
yrw .req r5
// register clw and crw hold round-constant for left and right branch
clw .req r6
crw .req r7
// registers tmpx and tmpy hold temporary values
tmpx .req r6
tmpy .req r7
// registers tw0 to tw5 are high registers (used as temporary storage)
tw0 .req r8
tw1 .req r9
tw2 .req r10
tw3 .req r11
tw4 .req r12
tw5 .req lr


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// MACROS FOR SPARKLE384 ////////////////////////////
/////////////////////////////////////////////////////////////////////////////// 

.macro PROLOGUE_384
    // push callee-saved registers
    push    {r4-r7,lr}
    mov     r3, r8
    mov     r4, r9
    mov     r5, r10
    mov     r6, r11
    mov     r7, r12
    push    {r3-r7}
    // load the left-side branches
    ldm     sptr!, {xlw-crw}
    mov     tw2, xrw
    mov     tw3, yrw
    mov     tw4, clw
    mov     tw5, crw
    // initialize 'steps' register
    movs    step, r1
.endm

.macro EPILOGUE_384
    // store the left-side branches
    subs    sptr, #24
    stm     sptr!, {xlw-ylw}
    mov     xlw, tw2
    mov     ylw, tw3
    mov     xrw, tw4
    mov     yrw, tw5
    stm     sptr!, {xlw-yrw}
    // pop callee-saved registers
    pop     {r3-r7}
    mov     r8, r3
    mov     r9, r4
    mov     r10, r5
    mov     r11, r6
    mov     r12, r7
    pop     {r4-r7,pc}
.endm

.macro ADD_STEP_CNT_384
    // add cnt to y1 (in temp register tw3)
    mov     imm, tw3
    eors    imm, cnt
    mov     tw3, imm
    // add round-constant RCON[cnt&7] to y0
    ldr     cptr, =RCON
    movs    step, #7
    ands    step, cnt
    lsls    step, #2
    ldr     step, [cptr, step]
    eors    ylw, step
.endm

.macro ARX_BOX_PAIR
    // y = y >>> 31; x = x + y
    movs    imm, #31
    rors    ylw, imm
    adds    xlw, ylw
    rors    yrw, imm
    adds    xrw, yrw
    // y = y >>> 09; y = y ^ x
    movs    imm, #9
    rors    ylw, imm
    eors    ylw, xlw
    rors    yrw, imm
    eors    yrw, xrw
    // x = x ^ rcon
    eors    xlw, clw
    eors    xrw, crw
    // y = y >>> 09; x = x + y
    rors    ylw, imm
    adds    xlw, ylw
    rors    yrw, imm
    adds    xrw, yrw
    // y = y >>> 30; y = y ^ x
    movs    imm, #30
    rors    ylw, imm
    eors    ylw, xlw
    rors    yrw, imm
    eors    yrw, xrw
    // x = x ^ rcon
    eors    xlw, clw
    eors    xrw, crw
    // y = y >>> 17; x = x + y
    movs    imm, #17
    rors    ylw, imm
    adds    xlw, ylw
    rors    yrw, imm
    adds    xrw, yrw
    // y = y >>> 01; y = y ^ x
    movs    imm, #1
    rors    ylw, imm
    eors    ylw, xlw
    rors    yrw, imm
    eors    yrw, xrw
    // x = x ^ rcon
    eors    xlw, clw
    eors    xrw, crw
    // y = y >>> 17; x = x + y
    movs    imm, #23
    rors    ylw, imm
    adds    xlw, ylw
    rors    yrw, imm
    adds    xrw, yrw
    // y = y >>> 01; y = y ^ x
    movs    imm, #24
    rors    ylw, imm
    eors    ylw, xlw
    rors    yrw, imm
    eors    yrw, xrw
    // x = x ^ rcon
    eors    xlw, clw
    eors    xrw, crw
    // y = y >>> 16
    movs    imm, #16
    rors    ylw, imm
    rors    yrw, imm
.endm

.macro LD_BRANS_0_3
    // branch 0 (i.e. x0, y0) already in registers xlw, ylw
    // load branch 3 (i.e. x3, y3) to registers xrw, yrw
    ldm     sptr!, {xrw-yrw}
    // load round-constants clw = RCON[0] and crw = RCON[3]
    ldr     clw, [cptr, #0]
    ldr     crw, [cptr, #12]
.endm

.macro LD_BRANS_1_4
    // branch 1 (i.e. x1, y1) already in registers xlw, ylw
    // load branch 4 (i.e. x4, y4) to registers xrw, yrw
    ldm     sptr!, {xrw-yrw}
    // load round-constants clw = RCON[1] and crw = RCON[4]
    ldr     cptr, =RCON
    ldr     clw, [cptr, #4]
    ldr     crw, [cptr, #16]
.endm

.macro LD_BRANS_2_5
    // branch 2 (i.e. x2, y2) already in registers xlw, ylw
    // load branch 5 (i.e. x5, y5) to registers xrw, yrw
    ldm     sptr!, {xrw-yrw}
    // load round-constants clw = RCON[2] and crw = RCON[5]
    ldr     cptr, =RCON
    ldr     clw, [cptr, #8]
    ldr     crw, [cptr, #20]
.endm

.macro ST_BRANS_0_3
    // tmpx = x0, tmpy = y0 
    mov     tw0, xlw
    mov     tw1, ylw
    // left branch is XORed to right branch
    eors    xrw, xlw
    eors    yrw, ylw
    // store left branch in the state-array
    subs    sptr, #8
    stm     sptr!, {xlw-ylw}
    // load left branch of next pair of ARX-boxes
    mov     xlw, tw2
    mov     ylw, tw3
    // move right branch to temp regs tw2 and tw3
    mov     tw2, xrw
    mov     tw3, yrw
.endm

.macro ST_BRANS_1_4
    // compute tmpx = tmpx ^ x1, tmpy = tmpy ^ y1
    mov     tmpx, tw0
    mov     tmpy, tw1
    eors    tmpx, xlw
    eors    tmpy, ylw
    mov     tw0, tmpx
    mov     tw1, tmpy
    // left branch is XORed to right branch
    eors    xrw, xlw
    eors    yrw, ylw
    // store left branch in the state-array
    subs    sptr, #8
    stm     sptr!, {xlw-ylw}
    // load left branch of next pair of ARX-boxes
    mov     xlw, tw4
    mov     ylw, tw5
    // move right branch to temp regs tw4 and tw5
    mov     tw4, xrw
    mov     tw5, yrw
.endm

.macro ST_BRANS_2_5
    // compute tmpx = tmpx ^ x2, tmpy = tmpy ^ y2
    mov     tmpx, tw0
    mov     tmpy, tw1
    eors    tmpx, xlw
    eors    tmpy, ylw
    // left branch is XORed to right branch
    eors    xrw, xlw
    eors    yrw, ylw
    // store left branch in the state-array
    subs    sptr, #8
    stm     sptr!, {xlw-ylw}
    // state-pointer contains address of x3
    subs    sptr, #24
.endm

.macro ARXBOX_LAYER_384
    // compute branch 0 (x0, y0) and branch 3 (x3, y3)
    LD_BRANS_0_3
    ARX_BOX_PAIR
    ST_BRANS_0_3
    // compute branch 1 (x1, y1) and branch 4 (x4, y4)
    LD_BRANS_1_4
    ARX_BOX_PAIR
    ST_BRANS_1_4
    // compute branch 2 (x2, y2) and branch 5 (x5, y5)
    LD_BRANS_2_5
    ARX_BOX_PAIR
    ST_BRANS_2_5
    // branch 3 (i.e. x3, y3) is in temp regs tw2, tw3
    // branch 4 (i.e. x4, y4) is in temp regs tw4, tw5
    // branch 5 (i.e. x5, y5) is in regs xrw, yrw
.endm

.macro LINEAR_LAYER_384
    // compute tmpx = ELL(tmpx), tmpy = ELL(tmpy)
    mov     xlw, tmpx
    mov     ylw, tmpy
    lsls    xlw, #16
    lsls    ylw, #16
    eors    tmpx, xlw
    eors    tmpy, ylw
    movs    imm, #16
    rors    tmpx, imm
    rors    tmpy, imm
    // compute x4 = x4 ^ tmpy and y4 = y4 ^ tmpx
    // branch 4 becomes branch 0 in next iteration
    mov     xlw, tw4
    eors    xlw, tmpy
    mov     ylw, tw5
    eors    ylw, tmpx
    // compute x3 = x3 ^ tmpy and y3 = y3 ^ tmpx
    // branch 3 becomes branch 2 in next iteration    
    mov     imm, tw2
    eors    imm, tmpy
    mov     tw4, imm
    mov     imm, tw3
    eors    imm, tmpx
    mov     tw5, imm
    // compute x5 = x5 ^ tmpy and y5 = y5 ^ tmpx
    // branch 5 becomes branch 1 in next iteration
    eors    xrw, tmpy
    mov     tw2, xrw
    eors    yrw, tmpx
    mov     tw3, yrw
.endm


///////////////////////////////////////////////////////////////////////////////
////////////////// SPARKLE384 PERMUTATION (BRANCH-UNROLLED) ///////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sparkle384_arm(uint32_t *state, int steps)
//
// Parameters:
// -----------
// state: pointer to an uint32_t-array containing the 12 state words
// steps: number of steps
//
// Return value:
// -------------
// None

.type sparkle384_arm, %function
.func sparkle384_arm
sparkle384_arm:
    PROLOGUE_384            // push callee-saved registers and load state
    movs    cnt, #0         // initialize step-counter
.Lloop_384:                 // start of loop
    push    {cnt,step}      // push step-counter and 'steps' to free registers
    ADD_STEP_CNT_384        // macro to add step-counter to state
    ARXBOX_LAYER_384        // macro for the ARXBOX layer
    LINEAR_LAYER_384        // macro for the linear layer
    pop     {cnt,step}      // restore step-counter and 'steps' from stack
    adds    cnt, #1         // increment step-counter
    cmp     cnt, step       // test whether step-counter equals 'steps'
    beq     .Llend_384      // if yes then branch to end of loop
    b       .Lloop_384      // if not then branch to start of loop
.Llend_384:                 // end of loop
    EPILOGUE_384            // store state and pop callee-saved registers
.endfunc


.size sparkle384_arm, .-sparkle384_arm


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
