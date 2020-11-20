/****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTn-128 block cipher.
* This implementation focuses on speed, at the cost of a large code size.
* See "Fixslicing: A New GIFT Representation" paper available at 
* https:// for more details.
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
* @date     March 2020
****************************************************************************/

.syntax unified
.thumb
/*****************************************************************************
* Fully unrolled implementation of the GIFT-128 key schedule according to the
* fixsliced representation.
*****************************************************************************/
@ void gift128_keyschedule(const u8* key, u32* rkey)
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r2-r12, r14}
    ldm     r0, {r4-r7}             //load key words
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    str.w   r6, [r1, #8]
    str.w   r4, [r1, #12]
    str.w   r7, [r1]
    str.w   r5, [r1, #4]
    // keyschedule using classical representation for the first 20 rounds
    movw    r12, #0x3fff
    lsl     r12, r12, #16           //r12<- 0x3fff0000
    movw    r10, #0x000f            //r10<- 0x0000000f
    movw    r9, #0x0fff             //r9 <- 0x00000fff
    // 1st classical key update
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    str.w   r5, [r1, #16]
    str.w   r7, [r1, #20]
    // 2nd classical key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    str.w   r4, [r1, #24]
    str.w   r6, [r1, #28]
    // 3rd classical key update
    and     r2, r10, r5, lsr #12
    and     r3, r5, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r5, lsr #2
    orr     r2, r2, r3
    and     r5, r5, #0x00030000
    orr     r5, r2, r5, lsl #14
    str.w   r7, [r1, #32]
    str.w   r5, [r1, #36]
    // 4th classical key update
    and     r2, r10, r4, lsr #12
    and     r3, r4, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r4, lsr #2
    orr     r2, r2, r3
    and     r4, r4, #0x00030000
    orr     r4, r2, r4, lsl #14
    str.w   r6, [r1, #40]
    str.w   r4, [r1, #44]
    // 5th classical key update
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    str.w   r5, [r1, #48]
    str.w   r7, [r1, #52]
    // 6th classical key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    str.w   r4, [r1, #56]
    str.w   r6, [r1, #60]
    // 7th classical key update
    and     r2, r10, r5, lsr #12
    and     r3, r5, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r5, lsr #2
    orr     r2, r2, r3
    and     r5, r5, #0x00030000
    orr     r5, r2, r5, lsl #14
    str.w   r7, [r1, #64]
    str.w   r5, [r1, #68]
    // 8th classical key update
    and     r2, r10, r4, lsr #12
    and     r3, r4, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r4, lsr #2
    orr     r2, r2, r3
    and     r4, r4, #0x00030000
    orr     r4, r2, r4, lsl #14
    str.w   r6, [r1, #72]
    str.w   r4, [r1, #76]
    // rearrange the rkeys to their respective new representations
    // REARRANGE_RKEY_0
    movw    r3, #0x0055
    movt    r3, #0x0055             //r3 <- 0x00550055
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            //r11<- 0x000f000f
    ldrd    r6, r4, [r1]
    eor     r12, r6, r6, lsr #9
    and     r12, r12, r3
    eor     r6, r12
    eor     r6, r6, r12, lsl #9     //SWAPMOVE(r6, r6, 0x00550055, 9);
    eor     r12, r4, r4, lsr #9
    and     r12, r12, r3
    eor     r4, r12
    eor     r4, r4, r12, lsl #9     //SWAPMOVE(r4, r4, 0x00550055, 9);
    eor     r12, r6, r6, lsr #18
    and     r12, r12, r10
    eor     r6, r12
    eor     r6, r6, r12, lsl #18    //SWAPMOVE(r6, r6, 0x3333, 18);
    eor     r12, r4, r4, lsr #18
    and     r12, r12, r10
    eor     r4, r12
    eor     r4, r4, r12, lsl #18    //SWAPMOVE(r4, r4, 0x3333, 18);
    eor     r12, r6, r6, lsr #12
    and     r12, r12, r11
    eor     r6, r12
    eor     r6, r6, r12, lsl #12    //SWAPMOVE(r6, r6, 0x000f000f, 12);
    eor     r12, r4, r4, lsr #12
    and     r12, r12, r11
    eor     r4, r12
    eor     r4, r4, r12, lsl #12    //SWAPMOVE(r4, r4, 0x000f000f, 12);
    eor     r12, r6, r6, lsr #24
    and     r12, r12, #0xff
    eor     r6, r12
    eor     r6, r6, r12, lsl #24    //SWAPMOVE(r6, r6, 0x000000ff, 24);
    eor     r12, r4, r4, lsr #24
    and     r12, r12, #0xff
    eor     r4, r12
    eor     r4, r4, r12, lsl #24    //SWAPMOVE(r4, r4, 0x000000ff, 24);
    strd    r6, r4, [r1]
    ldrd    r6, r4, [r1, #40]
    eor     r12, r6, r6, lsr #9
    and     r12, r12, r3
    eor     r6, r12
    eor     r6, r6, r12, lsl #9     //SWAPMOVE(r6, r6, 0x00550055, 9);
    eor     r12, r4, r4, lsr #9
    and     r12, r12, r3
    eor     r4, r12
    eor     r4, r4, r12, lsl #9     //SWAPMOVE(r4, r4, 0x00550055, 9);
    eor     r12, r6, r6, lsr #18
    and     r12, r12, r10
    eor     r6, r12
    eor     r6, r6, r12, lsl #18    //SWAPMOVE(r6, r6, 0x3333, 18);
    eor     r12, r4, r4, lsr #18
    and     r12, r12, r10
    eor     r4, r12
    eor     r4, r4, r12, lsl #18    //SWAPMOVE(r4, r4, 0x3333, 18);
    eor     r12, r6, r6, lsr #12
    and     r12, r12, r11
    eor     r6, r12
    eor     r6, r6, r12, lsl #12    //SWAPMOVE(r6, r6, 0x000f000f, 12);
    eor     r12, r4, r4, lsr #12
    and     r12, r12, r11
    eor     r4, r12
    eor     r4, r4, r12, lsl #12    //SWAPMOVE(r4, r4, 0x000f000f, 12);
    eor     r12, r6, r6, lsr #24
    and     r12, r12, #0xff
    eor     r6, r12
    eor     r6, r6, r12, lsl #24    //SWAPMOVE(r6, r6, 0x000000ff, 24);
    eor     r12, r4, r4, lsr #24
    and     r12, r12, #0xff
    eor     r4, r12
    eor     r4, r4, r12, lsl #24    //SWAPMOVE(r4, r4, 0x000000ff, 24);
    str.w   r6, [r1, #40]
    str.w   r4, [r1, #44]
    // REARRANGE_RKEY_1
    movw    r3, #0x1111
    movt    r3, #0x1111
    movw    r10, #0x0303
    movt    r10, #0x0303
    ldrd    r5, r7, [r1, #8]
    eor     r8, r7, r7, lsr #3
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #3      //SWAPMOVE(r7, r7, 0x11111111, 3);
    eor     r8, r5, r5, lsr #3
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #3      //SWAPMOVE(r5, r5, 0x11111111, 3);
    eor     r8, r7, r7, lsr #6
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #6      //SWAPMOVE(r7, r7, 0x03030303, 6);
    eor     r8, r5, r5, lsr #6
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #6      //SWAPMOVE(r5, r5, 0x03030303, 6);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    ldr.w   r12, [r1, #48]
    ldr.w   r14, [r1, #52]
    str.w   r5, [r1, #8]
    str.w   r7, [r1, #12]
    eor     r8, r14, r14, lsr #3
    and     r8, r8, r3
    eor     r14, r8
    eor     r14, r14, r8, lsl #3    //SWAPMOVE(r7, r7, 0x11111111, 3);
    eor     r8, r12, r12, lsr #3
    and     r8, r8, r3
    eor     r12, r8
    eor     r12, r12, r8, lsl #3    //SWAPMOVE(r5, r5, 0x11111111, 3);
    eor     r8, r14, r14, lsr #6
    and     r8, r8, r10
    eor     r14, r8
    eor     r14, r14, r8, lsl #6    //SWAPMOVE(r7, r7, 0x03030303, 6);
    eor     r8, r12, r12, lsr #6
    and     r8, r8, r10
    eor     r12, r8
    eor     r12, r12, r8, lsl #6    //SWAPMOVE(r5, r5, 0x03030303, 6);
    eor     r8, r14, r14, lsr #12
    and     r8, r8, r11
    eor     r14, r8
    eor     r14, r14, r8, lsl #12   //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r12, r12, lsr #12
    and     r8, r8, r11
    eor     r12, r8
    eor     r12, r12, r8, lsl #12   //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r14, r14, lsr #24
    and     r8, r8, #0xff
    eor     r14, r8
    eor     r14, r14, r8, lsl #24   //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r12, r12, lsr #24
    and     r8, r8, #0xff
    eor     r12, r8
    eor     r12, r12, r8, lsl #24   //SWAPMOVE(r5, r5, 0x000000ff, 24);
    str.w   r12, [r1, #48]
    str.w   r14, [r1, #52]
    // REARRANGE_RKEY_2
    movw    r3, #0xaaaa
    movw    r10, #0x3333
    movw    r11, #0xf0f0
    ldrd    r5, r7, [r1, #16]
    eor     r8, r7, r7, lsr #15
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #15     //SWAPMOVE(r7, r7, 0x0000aaaa, 15);
    eor     r8, r5, r5, lsr #15
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #15     //SWAPMOVE(r5, r5, 0x0000aaaa, 15);
    eor     r8, r7, r7, lsr #18
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #18     //SWAPMOVE(r7, r7, 0x00003333, 18);
    eor     r8, r5, r5, lsr #18
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #18     //SWAPMOVE(r5, r5, 0x00003333, 18);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x00000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    strd    r5, r7, [r1, #16]
    ldrd    r5, r7, [r1, #56]
    eor     r8, r7, r7, lsr #15
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #15     //SWAPMOVE(r7, r7, 0x0000aaaa, 15);
    eor     r8, r5, r5, lsr #15
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #15     //SWAPMOVE(r5, r5, 0x0000aaaa, 15);
    eor     r8, r7, r7, lsr #18
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #18     //SWAPMOVE(r7, r7, 0x00003333, 18);
    eor     r8, r5, r5, lsr #18
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #18     //SWAPMOVE(r5, r5, 0x00003333, 18);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    str.w   r5, [r1, #56]
    str.w   r7, [r1, #60]
    // REARRANGE_RKEY_3
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             //r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            //r10<- 0x00cc00cc
    ldrd    r5, r7, [r1, #24]
    eor     r8, r7, r7, lsr #3
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #3      //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3);
    eor     r8, r5, r5, lsr #3
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #3      //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3);
    eor     r8, r7, r7, lsr #6
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #6      //SWAPMOVE(r7, r7, 0x00cc00cc, 6);
    eor     r8, r5, r5, lsr #6
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #6      //SWAPMOVE(r5, r5, 0x00cc00cc, 6);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    strd    r5, r7, [r1, #24]
    ldrd    r5, r7, [r1, #64]
    eor     r8, r7, r7, lsr #3
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #3      //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3);
    eor     r8, r5, r5, lsr #3
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #3      //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3);
    eor     r8, r7, r7, lsr #6
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #6      //SWAPMOVE(r7, r7, 0x00cc00cc, 6);
    eor     r8, r5, r5, lsr #6
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #6      //SWAPMOVE(r5, r5, 0x00cc00cc, 6);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x0000ff00, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x0000ff00, 24);
    str.w   r5, [r1, #64]
    str.w   r7, [r1, #68]
    //keyschedule according to the new representations
    // KEY_DOULBE/TRIPLE_UPDATE_0
    movw    r10, #0x3333
    eor     r12, r10, r10, lsl #16
    mvn     r11, r12
    movw    r9, #0x4444
    movt    r9, #0x5555
    movw    r8, #0x1100
    movt    r8, #0x5555
    ldrd    r4, r5, [r1]
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    str.w   r5, [r1, #80]
    str.w   r4, [r1, #84]
    and     r2, r12, r5, ror #24
    and     r5, r5, r11
    orr     r5, r2, r5, ror #16     //KEY_TRIPLE_UPDATE_1(r5)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r8
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x55551100, 1)
    eor     r2, r4, r4, lsr #16
    and     r2, r2, r10
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #16     //SWAPMOVE(r4, r4, 0x00003333, 16)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r9
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x555544444, 1)
    str.w   r4, [r1, #160]
    str.w   r5, [r1, #164]
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    strd    r5, r4, [r1, #240]
    ldrd    r4, r5, [r1, #40]
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    str.w   r5, [r1, #120]
    str.w   r4, [r1, #124]
    and     r2, r12, r5, ror #24
    and     r5, r5, r11
    orr     r5, r2, r5, ror #16     //KEY_TRIPLE_UPDATE_1(r5)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r8
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x55551100, 1)
    eor     r2, r4, r4, lsr #16
    and     r2, r2, r10
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #16     //SWAPMOVE(r4, r4, 0x00003333, 16)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r9
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x555544444, 1)
    str.w   r4, [r1, #200]
    str.w   r5, [r1, #204]
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    str.w   r5, [r1, #280]
    str.w   r4, [r1, #284]
    // KEY_DOULBE/TRIPLE_UPDATE_2
    // masks
    movw    r12, #0x0f00
    movt    r12, #0x0f00
    movw    r11, #0x0003
    movt    r11, #0x0003
    movw    r10, #0x003f
    movt    r10, #0x003f
    lsl     r9, r11, #8             //r9 <- 0x03000300
    and     r8, r10, r10, lsr #3    //r8 <- 0x00070007
    orr     r7, r8, r8, lsl #2      //r7 <- 0x001f001f
    ldrd    r4, r5, [r1, #8]
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl #2      //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r5, [r1, #88]
    str.w   r4, [r1, #92]
    and     r2, r9, r5, lsr #6
    and     r3, r5, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #5
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r12, r4, lsr #4
    and     r3, r4, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r4, lsr #6
    orr     r2, r2, r3
    and     r4, r4, r10
    orr     r4, r2, r4, lsl #2      //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r4, [r1, #168]
    str.w   r5, [r1, #172]
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl#2       //KEY_DOUBLE_UPDATE_2(r5)
    strd    r5, r4, [r1, #248]
    ldrd    r4, r5, [r1, #48]
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl #2      //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r5, [r1, #128]
    str.w   r4, [r1, #132]
    and     r2, r9, r5, lsr #6
    and     r3, r5, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #5
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r12, r4, lsr #4
    and     r3, r4, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r4, lsr #6
    orr     r2, r2, r3
    and     r4, r4, r10
    orr     r4, r2, r4, lsl #2      //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r4, [r1, #208]
    str.w   r5, [r1, #212]
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl#2       //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r5, [r1, #288]
    str.w   r4, [r1, #292]
    // KEY_DOULBE/TRIPLE_UPDATE_2
    // masks
    movw    r12, #0x5555
    movt    r12, #0x5555
    mvn     r11, r12
    ldrd    r4, r5, [r1, #16]
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r5, [r1, #96]
    str.w   r4, [r1, #100]
    and     r2, r12, r5, ror #24
    and     r5, r11, r5, ror #20
    orr     r5, r5, r2              //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r11, r4, ror #24
    and     r4, r12, r4, ror #16
    orr     r4, r4, r2              //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r4, [r1, #176]
    str.w   r5, [r1, #180]
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    strd    r5, r4, [r1, #256]
    ldrd    r4, r5, [r1, #56]
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r5, [r1, #136]
    str.w   r4, [r1, #140]
    and     r2, r12, r5, ror #24
    and     r5, r11, r5, ror #20
    orr     r5, r5, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r4, ror #24
    and     r4, r12, r4, ror #16
    orr     r4, r4, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #216]
    str.w   r5, [r1, #220]
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r5, [r1, #296]
    str.w   r4, [r1, #300]
    // KEY_DOULBE/TRIPLE_UPDATE_3
    // masks
    orr     r12, r8, r8, lsl #8     //r12<- 0x07070707
    movw    r11, #0xc0c0
    movw    r10, #0x3030
    and     r9, r12, r12, lsr #1    //r9 <- 0x03030303
    lsl     r8, r12, #4
    eor     r7, r8, r9, lsl #5
    movw    r6, #0xf0f0
    ldrd    r4, r5, [r1, #24]
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #104]
    str.w   r4, [r1, #108]
    and     r2, r10, r5, lsr #18
    and     r3, r5, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r5, lsr #14
    orr     r2, r2, r3
    and     r3, r5, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7, lsr #16
    orr     r5, r2, r5, lsl #19     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r9, r4, lsr #2
    and     r3, r9, r4
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r4, [r1, #184]
    str.w   r5, [r1, #188]
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    strd    r5, r4, [r1, #264]
    ldrd    r4, r5, [r1, #64]
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #144]
    str.w   r4, [r1, #148]
    and     r2, r10, r5, lsr #18
    and     r3, r5, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r5, lsr #14
    orr     r2, r2, r3
    and     r3, r5, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7, lsr #16
    orr     r5, r2, r5, lsl #19     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r9, r4, lsr #2
    and     r3, r9, r4
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r4, [r1, #224]
    str.w   r5, [r1, #228]
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #304]
    str.w   r4, [r1, #308]
    // KEY_DOULBE/TRIPLE_UPDATE_4
    // masks
    movw    r12, #0x0fff
    lsl     r10, r12, #16
    movw    r8, #0x00ff
    movw    r7, #0x03ff
    lsl     r7, r7, #16
    ldrd    r4, r5, [r1, #32]
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #112]
    str.w   r4, [r1, #116]
    and     r2, r7, r5, lsr #6
    and     r3, r5, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r5, lsr #4
    orr     r2, r2, r3
    and     r5, r5, #0x000f
    orr     r5, r2, r5, lsl #12     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r10, r4, lsr #4
    and     r3, r4, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r4, lsr #8
    orr     r2, r2, r3
    and     r4, r4, r8
    orr     r4, r2, r4, lsl #8      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r4, [r1, #192]
    str.w   r5, [r1, #196]
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    strd    r5, r4, [r1, #272]
    ldrd    r4, r5, [r1, #72]
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #152]
    str.w   r4, [r1, #156]
    and     r2, r7, r5, lsr #6
    and     r3, r5, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r5, lsr #4
    orr     r2, r2, r3
    and     r5, r5, #0x000f
    orr     r5, r2, r5, lsl #12     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r10, r4, lsr #4
    and     r3, r4, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r4, lsr #8
    orr     r2, r2, r3
    and     r4, r4, r8
    orr     r4, r2, r4, lsl #8      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r4, [r1, #232]
    str.w   r5, [r1, #236]
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r5, [r1, #312]
    str.w   r4, [r1, #316]
    pop     {r2-r12,r14}
    bx      lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push {r2-r12,r14}
    // load plaintext blocks
    ldm     r2, {r9-r12}
    // endianness
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    // masks for HALF/BYTE/NIBBLE rotations
    movw    r2, #0x1111
    movt    r2, #0x1111 //for NIBBLE_ROR
    movw    r3, #0x000f
    movt    r3, #0x000f //for HALF_ROR
    mvn     r4, r2, lsl #3 //0x7777777 for NIBBLE_ROR
    // ------------------ 1st QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x0008
    movt    r5, 0x1000 //load rconst
    ldrd    r6, r7, [r1] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    and     r8, r4, r12, lsr #1
    and     r12, r12, r2
    orr     r12, r8, r12, lsl #3 //NIBBLE_ROR(r12, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 2nd round
    movw    r5, 0x8000
    movt    r5, 0x8001 //load rconst
    ldrd    r6, r7, [r1, #8] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r9, lsr #4
    and     r9, r9, r3
    orr     r9, r8, r9, lsl #12 //HALF_ROR(r9, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x5400 //load rconst
    ldrd    r6, r7, [r1, #16] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1 //SWAPMOVE(r12, r12, 0x55550000, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x00005555, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 4th round
    movw    r5, 0x0181
    movt    r5, 0x0101 //load rconst
    ldrd    r6, r7, [r1, #24] //load rkey
    and     r8, r11, r12, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #16
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r9, lsr #6
    and     r9, r14, r9
    orr     r9, r8, r9, lsl #2 //BYTE_ROR(r9, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 5th round
    movw    r5, 0x001f
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #32] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst

    // ------------------ 2nd QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x8880
    movt    r5, 0x1088 //load rconst
    ldrd    r6, r7, [r1, #40] //load rkey
    and     r8, r11, r12, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #24
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    and     r8, r4, r9, lsr #1
    and     r9, r9, r2
    orr     r9, r8, r9, lsl #3 //NIBBLE_ROR(r9, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 2nd round
    movw    r5, 0xe000
    movt    r5, 0x6001 //load rconst
    ldrd    r6, r7, [r1, #48] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r12, lsr #4
    and     r12, r12, r3
    orr     r12, r8, r12, lsl #12 //HALF_ROR(r12, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x5150 //load rconst
    ldrd    r6, r7, [r1, #56] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r9, r9, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r9, r9, r8
    eor     r9, r9, r8, lsl #1 //SWAPMOVE(r9, r9, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 4th round
    movw    r5, 0x0180
    movt    r5, 0x0303 //load rconst
    ldrd    r6, r7, [r1, #64] //load rkey
    and     r8, r11, r9, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #16
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r12, lsr #6
    and     r12, r14, r12
    orr     r12, r8, r12, lsl #2 //BYTE_ROR(r12, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 5th round
    movw    r5, 0x002f
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #72] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst

    // ------------------ 3rd QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x8880
    movt    r5, 0x1008 //load rconst
    ldrd    r6, r7, [r1, #80] //load rkey
    and     r8, r11, r9, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #24
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    and     r8, r4, r12, lsr #1
    and     r12, r12, r2
    orr     r12, r8, r12, lsl #3 //NIBBLE_ROR(r12, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 2nd round
    movw    r5, 0x6000
    movt    r5, 0x6001 //load rconst
    ldrd    r6, r7, [r1, #88] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r9, lsr #4
    and     r9, r9, r3
    orr     r9, r8, r9, lsl #12 //HALF_ROR(r9, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x4150 //load rconst
    ldrd    r6, r7, [r1, #96] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1 //SWAPMOVE(r12, r12, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 4th round
    movw    r5, 0x0080
    movt    r5, 0x0303 //load rconst
    ldrd    r6, r7, [r1, #104] //load rkey
    and     r8, r11, r12, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #16
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r9, lsr #6
    and     r9, r14, r9
    orr     r9, r8, r9, lsl #2 //BYTE_ROR(r9, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 5th round
    movw    r5, 0x0027
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #112] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst

    // ------------------ 4th QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x8880
    movt    r5, 0x1000 //load rconst
    ldrd    r6, r7, [r1, #120] //load rkey
    and     r8, r11, r12, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #24
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    and     r8, r4, r9, lsr #1
    and     r9, r9, r2
    orr     r9, r8, r9, lsl #3 //NIBBLE_ROR(r9, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 2nd round
    movw    r5, 0xe000
    movt    r5, 0x4001 //load rconst
    ldrd    r6, r7, [r1, #128] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r12, lsr #4
    and     r12, r12, r3
    orr     r12, r8, r12, lsl #12 //HALF_ROR(r12, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x1150 //load rconst
    ldrd    r6, r7, [r1, #136] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r9, r9, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r9, r9, r8
    eor     r9, r9, r8, lsl #1 //SWAPMOVE(r9, r9, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 4th round
    movw    r5, 0x0180
    movt    r5, 0x0302 //load rconst
    ldrd    r6, r7, [r1, #144] //load rkey
    and     r8, r11, r9, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #16
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r12, lsr #6
    and     r12, r14, r12
    orr     r12, r8, r12, lsl #2 //BYTE_ROR(r12, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 5th round
    movw    r5, 0x002b
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #152] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst

    // ------------------ 5th QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x0880
    movt    r5, 0x1008 //load rconst
    ldrd    r6, r7, [r1, #160] //load rkey
    and     r8, r11, r9, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #24
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    and     r8, r4, r12, lsr #1
    and     r12, r12, r2
    orr     r12, r8, r12, lsl #3 //NIBBLE_ROR(r12, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 2nd round
    movw    r5, 0x4000
    movt    r5, 0x6001 //load rconst
    ldrd    r6, r7, [r1, #168] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r9, lsr #4
    and     r9, r9, r3
    orr     r9, r8, r9, lsl #12 //HALF_ROR(r9, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x0140 //load rconst
    ldrd    r6, r7, [r1, #176] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1 //SWAPMOVE(r12, r12, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 4th round
    movw    r5, 0x0080
    movt    r5, 0x0202 //load rconst
    ldrd    r6, r7, [r1, #184] //load rkey
    and     r8, r11, r12, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #16
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r9, lsr #6
    and     r9, r14, r9
    orr     r9, r8, r9, lsl #2 //BYTE_ROR(r9, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 5th round
    movw    r5, 0x0021
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #192] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst

    // ------------------ 6th QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x0080
    movt    r5, 0x1000 //load rconst
    ldrd    r6, r7, [r1, #200] //load rkey
    and     r8, r11, r12, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #24
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    and     r8, r4, r9, lsr #1
    and     r9, r9, r2
    orr     r9, r8, r9, lsl #3 //NIBBLE_ROR(r9, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 2nd round
    movw    r5, 0xc000
    movt    r5, 0x0001 //load rconst
    ldrd    r6, r7, [r1, #208] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r12, lsr #4
    and     r12, r12, r3
    orr     r12, r8, r12, lsl #12 //HALF_ROR(r12, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x5100 //load rconst
    ldrd    r6, r7, [r1, #216] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r9, r9, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r9, r9, r8
    eor     r9, r9, r8, lsl #1 //SWAPMOVE(r9, r9, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 4th round
    movw    r5, 0x0180
    movt    r5, 0x0301 //load rconst
    ldrd    r6, r7, [r1, #224] //load rkey
    and     r8, r11, r9, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #16
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r12, lsr #6
    and     r12, r14, r12
    orr     r12, r8, r12, lsl #2 //BYTE_ROR(r12, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 5th round
    movw    r5, 0x002e
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #232] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst


    // ------------------ 7th QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x8800
    movt    r5, 0x1008 //load rconst
    ldrd    r6, r7, [r1, #240] //load rkey
    and     r8, r11, r9, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #24
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    and     r8, r4, r12, lsr #1
    and     r12, r12, r2
    orr     r12, r8, r12, lsl #3 //NIBBLE_ROR(r12, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 2nd round
    movw    r5, 0x2000
    movt    r5, 0x6001 //load rconst
    ldrd    r6, r7, [r1, #248] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r9, lsr #4
    and     r9, r9, r3
    orr     r9, r8, r9, lsl #12 //HALF_ROR(r9, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x4050 //load rconst
    ldrd    r6, r7, [r1, #256] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1 //SWAPMOVE(r12, r12, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 4th round
    movw    r5, 0x0080
    movt    r5, 0x0103 //load rconst
    ldrd    r6, r7, [r1, #264] //load rkey
    and     r8, r11, r12, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #16
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r9, lsr #6
    and     r9, r14, r9
    orr     r9, r8, r9, lsl #2 //BYTE_ROR(r9, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 5th round
    movw    r5, 0x0006
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #272] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst

    // ------------------ 8th QUINTUPLE ROUND ------------------
    // 1st round
    movw    r5, 0x8808
    movt    r5, 0x1000 //load rconst
    ldrd    r6, r7, [r1, #280] //load rkey
    and     r8, r11, r12, ror #24 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r8, r12, ror #24
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    and     r8, r4, r9, lsr #1
    and     r9, r9, r2
    orr     r9, r8, r9, lsl #3 //NIBBLE_ROR(r9, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1 //NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1 //0x33333333 for NIBBLE_ROR
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2 //NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 2nd round
    movw    r5, 0xa000
    movt    r5, 0xc001 //load rconst
    ldrd    r6, r7, [r1, #288] //load rkey
    and     r8, r9, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    mvn     r14, r3, lsl #12 //0x0fff0fff for HALF_ROR
    and     r8, r14, r12, lsr #4
    and     r12, r12, r3
    orr     r12, r8, r12, lsl #12 //HALF_ROR(r12, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4 //HALF_ROR(r11, 12)
    rev16   r10, r10 //HALF_ROR(r10, 8)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 3rd round
    movw    r5, 0x0002
    movt    r5, 0x1450 //load rconst
    ldrd    r6, r7, [r1, #296] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9
    orr     r14, r2, r2, lsl #2 //0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1 //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r9, r9, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r9, r9, r8
    eor     r9, r9, r8, lsl #1 //SWAPMOVE(r9, r9, 0x00005555, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1 //SWAPMOVE(r11, r11, 0x55550000, 1)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r7, r11, ror #16 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // 4th round
    movw    r5, 0x0181
    movt    r5, 0x0102 //load rconst
    ldrd    r6, r7, [r1, #304] //load rkey
    and     r8, r11, r9, ror #16 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r8, r9, ror #16
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12
    eor     r14, r3, r3, lsl #8 //0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4 //BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2 //0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8 //BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r12, lsr #6
    and     r12, r14, r12
    orr     r12, r8, r12, lsl #2 //BYTE_ROR(r12, 6)
    eor     r10, r10, r6 //add 1st keyword
    eor     r11, r11, r7 //add 2nd keyword
    eor     r9, r9, r5 //add     rconst
    // 5th round
    movw    r5, 0x001a
    movt    r5, 0x8000 //load rconst
    ldrd    r6, r7, [r1, #312] //load rkey
    and     r8, r12, r11 //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r9
    eor     r12, r12, r8
    orr     r8, r12, r10
    eor     r11, r11, r8
    eor     r9, r9, r11
    eor     r10, r10, r9
    and     r8, r12, r10
    eor     r11, r11, r8
    mvn     r9, r9, ror #24
    eor     r10, r6, r10, ror #16 //add 1st keyword
    eor     r11, r7, r11, ror #8 //add 2nd keyword
    eor     r12, r12, r5 //add     rconst
    // endianness
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    stm     r0, {r9-r12}
    pop     {r2-r12,r14}
    bx      lr
