/****************************************************************************
* Compact ARM assembly implementation of the GIFT-128 block cipher. This
* implementation focuses on code size rather than speed.
* See "Fixslicing: A New GIFT Representation" paper available at 
* https:// for more details.
****************************************************************************/

.syntax unified
.thumb

/*****************************************************************************
* Round constants look-up table according to the fixsliced representation.
*****************************************************************************/
.align 2
.type rconst,%object
rconst:
.word 0x10000008, 0x80018000, 0x54000002, 0x01010181
.word 0x8000001f, 0x10888880, 0x6001e000, 0x51500002
.word 0x03030180, 0x8000002f, 0x10088880, 0x60016000
.word 0x41500002, 0x03030080, 0x80000027, 0x10008880
.word 0x4001e000, 0x11500002, 0x03020180, 0x8000002b
.word 0x10080880, 0x60014000, 0x01400002, 0x02020080
.word 0x80000021, 0x10000080, 0x0001c000, 0x51000002
.word 0x03010180, 0x8000002e, 0x10088800, 0x60012000
.word 0x40500002, 0x01030080, 0x80000006, 0x10008808
.word 0xc001a000, 0x14500002, 0x01020181, 0x8000001a

.align 2
key_update:
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    strd    r5, r7, [r1], #8        //store rkeys after 1st key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    strd    r4, r6, [r1], #8        //store rkeys after 2nd key update
    and     r2, r10, r5, lsr #12
    and     r3, r5, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r5, lsr #2
    orr     r2, r2, r3
    and     r5, r5, #0x00030000
    orr     r5, r2, r5, lsl #14
    strd    r7, r5, [r1], #8        //store rkeys after 3rd key update
    and     r2, r10, r4, lsr #12
    and     r3, r4, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r4, lsr #2
    orr     r2, r2, r3
    and     r4, r4, #0x00030000
    orr     r4, r2, r4, lsl #14
    strd    r6, r4, [r1], #8        //store rkeys after 4th key update
    bx      lr

.align 2
rearrange_rkey_0:
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
    bx      lr

.align 2
rearrange_rkey_1:
    ldrd    r5, r7, [r1]
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
    strd    r5, r7, [r1]
    bx      lr

.align 2
rearrange_rkey_2:
    ldrd    r5, r7, [r1]
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
    strd    r5, r7, [r1]
    bx      lr

.align 2
rearrange_rkey_3:
    ldrd    r5, r7, [r1]
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
    strd    r5, r7, [r1]
    bx      lr

/*****************************************************************************
* Code size optimized implementation of the GIFTb-128 key schedule.
* Compute the key schedule in the normal representation and then rearrange all
* the round keys in their respective fixsliced representations.
*****************************************************************************/
.align 2
@ void gift128_keyschedule(const u8* key, u32* rkey)
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r1-r12, r14}
    ldm     r0, {r4-r7}             //load key words
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    strd    r7, r5, [r1], #8        //the first rkeys are not updated
    strd    r6, r4, [r1], #8        //the first rkeys are not updated
    // keyschedule using classical representation for the first 20 rounds
    movw    r12, #0x3fff
    lsl     r12, r12, #16           //r12<- 0x3fff0000
    movw    r10, #0x000f            //r10<- 0x0000000f
    movw    r9, #0x0fff             //r9 <- 0x00000fff
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    bl      key_update
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    strd    r5, r7, [r1], #8        //penultimate key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    strd    r4, r6, [r1], #8        //ultimate key update
    sub.w   r1, r1, #320
    // rearrange the rkeys to their respective new representations
    movw    r3, #0x0055
    movt    r3, #0x0055             //r3 <- 0x00550055
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            //r11<- 0x000f000f
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    sub.w   r1, r1, #272
    movw    r3, #0x1111
    movt    r3, #0x1111             //r3 <- 0x11111111
    movw    r10, #0x0303
    movt    r10, #0x0303            //r10<- 0x03030303
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    sub.w   r1, r1, #272
    movw    r3, #0xaaaa             //r3 <- 0x0000aaaa
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0xf0f0            //r11<- 0x0000f0f0
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    sub.w   r1, r1, #272
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             //r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            //r10<- 0x00cc00cc
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    pop     {r1-r12, r14}
    bx      lr

.align 2
quintuple_round:
    str.w   r14, [sp]
    ldr.w   r5, [r0], #4
    ldr.w   r6, [r1], #4            //load rkey
    ldr.w   r7, [r1], #4            //load rkey
    and     r8, r11, r9             //sbox layer
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
    and     r8, r4, r12, lsr #1     //permutation layer
    and     r12, r12, r2
    orr     r12, r8, r12, lsl #3    //r12<- NIBBLE_ROR(r12, 1)
    and     r8, r4, r11
    and     r11, r2, r11, lsr #3
    orr     r11, r11, r8, lsl #1    //r11<- NIBBLE_ROR(r11, 3)
    orr     r14, r2, r2, lsl #1     //r14 <- 0x33333333
    and     r8, r14, r10, lsr #2
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #2    //r10<- NIBBLE_ROR(r10, 2)
    eor     r10, r10, r6            //add 1st keyword
    eor     r11, r11, r7            //add 2nd keyword
    eor     r9, r9, r5              //add rconst
    ldr.w   r5, [r0], #4
    ldr.w   r6, [r1], #4            //load rkey
    ldr.w   r7, [r1], #4            //load rkey
    and     r8, r12, r11            //sbox layer
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
    mvn     r14, r3, lsl #12        //r0 <- 0x0fff0fff
    and     r8, r14, r9, lsr #4
    and     r9, r9, r3
    orr     r9, r8, r9, lsl #12     //r9 <- HALF_ROR(r9, 4)
    and     r8, r3, r11, lsr #12
    and     r11, r11, r14
    orr     r11, r8, r11, lsl #4    //r11<- HALF_ROR(r11, 12)
    rev16   r10, r10                //r10<- HALF_ROR(r10, 8)
    eor     r10, r10, r6            //add 1st keyword
    eor     r11, r11, r7            //add 2nd keyword
    eor     r12, r12, r5            //add rconst
    ldr.w   r5, [r0], #4
    ldr.w   r6, [r1], #4            //load rkey
    ldr.w   r7, [r1], #4            //load rkey
    and     r8, r9, r11             //sbox layer
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
    orr     r14, r2, r2, lsl #2     //r14 <- 0x55555555 for SWAPMOVE
    eor     r8, r10, r10, lsr #1
    and     r8, r8, r14
    eor     r10, r10, r8
    eor     r10, r10, r8, lsl #1    //SWAPMOVE(r10, r10, 0x55555555, 1)
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r14, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1    //SWAPMOVE(r12, r12, 0x55550000, 1)
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r14, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1    //SWAPMOVE(r11, r11, 0x00005555, 1)
    eor     r10, r10, r6            //add 1st keyword
    eor     r11, r7, r11, ror #16   //add 2nd keyword
    eor     r9, r9, r5              //add rconst
    ldr.w   r5, [r0], #4
    ldr.w   r6, [r1], #4            //load rkey
    ldr.w   r7, [r1], #4            //load rkey
    and     r8, r11, r12, ror #16   //sbox layer
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
    eor     r14, r3, r3, lsl #8     //r14 <- 0x0f0f0f0f for BYTE_ROR
    and     r8, r14, r10, lsr #4
    and     r10, r10, r14
    orr     r10, r8, r10, lsl #4    //r10<- BYTE_ROR(r10, 4)
    orr     r14, r14, r14, lsl #2   //r14 <- 0x3f3f3f3f for BYTE_ROR
    mvn     r8, r14                 //r8 <- 0xc0c0c0c0 for BYTE_ROR
    and     r8, r8, r11, lsl #6
    and     r11, r14, r11, lsr #2
    orr     r11, r11, r8            //r11<- BYTE_ROR(r11, 2)
    mvn     r8, r14, lsr #6
    and     r8, r8, r9, lsr #6
    and     r9, r14, r9
    orr     r9, r8, r9, lsl #2      //r9 <- BYTE_ROR(r9, 6)
    eor     r10, r10, r6            //add 1st keyword
    eor     r11, r11, r7            //add 2nd keyword
    eor     r12, r12, r5            //add rconst
    ldr.w   r5, [r0], #4
    ldr.w   r6, [r1], #4            //load rkey
    ldr.w   r7, [r1], #4            //load rkey
    ldr.w   lr, [sp]                //restore link register
    and     r8, r9, r11             //sbox layer
    eor     r10, r10, r8
    and     r8, r10, r12
    eor     r9, r9, r8
    orr     r8, r9, r10
    eor     r11, r11, r8
    eor     r12, r12, r11
    eor     r10, r10, r12
    and     r8, r9, r10
    eor     r11, r11, r8
    mvn     r12, r12, ror #24
    eor     r10, r6, r10, ror #16   //add 1st keyword
    eor     r11, r7, r11, ror #8    //add 2nd keyword
    eor     r9, r9, r5              //add rconst
    eor     r9, r9, r12             //swap r9 with r12
    eor     r12, r12, r9            //swap r9 with r12
    eor     r9, r9, r12             //swap r9 with r12
    bx      lr

/*****************************************************************************
* Code size optimized implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
.align 2
@ void giftb128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push    {r0,r2-r12,r14}
    sub.w   sp, #4              //to store 'lr' when calling 'quintuple_round'
    ldm     r2, {r9-r12}        // load plaintext words
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    movw    r2, #0x1111
    movt    r2, #0x1111         //r2 <- 0x11111111 (for NIBBLE_ROR)
    movw    r3, #0x000f
    movt    r3, #0x000f         //r3 <- 0x000f000f (for HALF_ROR)
    mvn     r4, r2, lsl #3      //r4 <- 0x7777777 (for NIBBLE_ROR)
    adr     r0, rconst          //r0 <- 'rconst' address
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    ldr.w   r0, [sp ,#4]        //restore 'ctext' address
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    stm     r0, {r9-r12}
    add.w   sp, #4
    pop     {r0,r2-r12,r14}
    bx      lr
    