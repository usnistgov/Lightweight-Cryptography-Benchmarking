/****************************************************************************
* Balanced ARM assembly implementation of the GIFT-128 block cipher. This
* implementation provides efficiency with limited impact on the code size.
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
classical_key_update:
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    str.w   r7, [r1, #4]            //1st classical key update
    str.w   r5, [r1], #8            //1st classical key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    str.w   r6, [r1, #4]            //2nd classical key update
    str.w   r4, [r1], #8            //2nd classical key update
    and     r2, r10, r5, lsr #12
    and     r3, r5, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r5, lsr #2
    orr     r2, r2, r3
    and     r5, r5, #0x00030000
    orr     r5, r2, r5, lsl #14
    str.w   r5, [r1, #4]            //3rd classical key update
    str.w   r7, [r1], #8            //3rd classical key update
    and     r2, r10, r4, lsr #12
    and     r3, r4, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r4, lsr #2
    orr     r2, r2, r3
    and     r4, r4, #0x00030000
    orr     r4, r2, r4, lsl #14
    str.w   r4, [r1, #4]            //4th classical key update
    str.w   r6, [r1], #8            //4th classical key update
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
    str.w   r6, [r1]
    str.w   r4, [r1, #4]
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
    str.w   r5, [r1]
    str.w   r7, [r1, #4]
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
    str.w   r5, [r1]
    str.w   r7, [r1, #4]
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
    str.w   r5, [r1]
    str.w   r7, [r1, #4]
    bx      lr

.align 2
key_update_0:
    ldrd    r4, r5, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
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
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

.align 2
key_update_1:
    ldrd    r4, r5, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
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
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

.align 2
key_update_2:
    ldrd    r4, r5, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r12, r5, ror #24
    and     r5, r11, r5, ror #20
    orr     r5, r5, r2              //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r11, r4, ror #24
    and     r4, r12, r4, ror #16
    orr     r4, r4, r2              //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

.align 2
key_update_3:
    ldrd    r4, r5, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
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
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

.align 2
key_update_4:
    ldrd    r4, r5, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
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
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
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
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

/*****************************************************************************
* Balanced implementation of the GIFT-128 key schedule according to the 
* fixsliced representation.
*****************************************************************************/
.align 2
@ void gift128_keyschedule(const u8* key, u32* rkey) {
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r1-r12, r14}
    ldm     r0, {r4-r7}             //load key words
    rev     r4, r4                  //endianness (could be skipped with another representation)
    rev     r5, r5                  //endianness (could be skipped with another representation)
    rev     r6, r6                  //endianness (could be skipped with another representation)
    rev     r7, r7                  //endianness (could be skipped with another representation)
    str.w   r5, [r1, #4]
    str.w   r7, [r1], #8            //the first rkeys are not updated  
    str.w   r4, [r1, #4]
    str.w   r6, [r1], #8            //the first rkeys are not updated
    movw    r12, #0x3fff
    lsl     r12, r12, #16           //r12<- 0x3fff0000
    movw    r10, #0x000f            //r10<- 0x0000000f
    movw    r9, #0x0fff             //r9 <- 0x00000fff
    bl      classical_key_update    //keyschedule using classical representation (10 rounds)
    bl      classical_key_update    //keyschedule using classical representation (20 rounds)
    sub.w   r1, r1, #80
    movw    r3, #0x0055
    movt    r3, #0x0055             //r3 <- 0x00550055
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            //r11<- 0x000f000f
    bl      rearrange_rkey_0        //fixslice the rkeys
    add.w   r1, r1, #40
    bl      rearrange_rkey_0        //fixslice the rkeys
    sub.w   r1, r1, #32
    movw    r3, #0x1111
    movt    r3, #0x1111             //r3 <- 0x11111111
    movw    r10, #0x0303
    movt    r10, #0x0303            //r10<- 0x03030303
    bl      rearrange_rkey_1        //fixslice the rkeys
    add.w   r1, r1, #40
    bl      rearrange_rkey_1        //fixslice the rkeys
    sub.w   r1, r1, #32
    movw    r3, #0xaaaa             //r3 <- 0x0000aaaa
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0xf0f0            //r11<- 0x0000f0f0
    bl      rearrange_rkey_2        //fixslice the rkeys
    add.w   r1, r1, #40
    bl      rearrange_rkey_2        //fixslice the rkeys
    sub.w   r1, r1, #32
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             //r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            //r10<- 0x00cc00cc
    bl      rearrange_rkey_3        //fixslice the rkeys
    add.w   r1, r1, #40
    bl      rearrange_rkey_3        //fixslice the rkeys
    sub.w   r1, r1, #64
    movw    r10, #0x3333            //r10<- 0x00003333
    eor     r12, r10, r10, lsl #16  //r12<- 0w33333333 
    mvn     r11, r12                //r11<- 0xcccccccc
    movw    r9, #0x4444
    movt    r9, #0x5555             //r9 <- 0x55554444
    movw    r8, #0x1100
    movt    r8, #0x5555             //r8 <- 0x55551100
    bl      key_update_0            //keyschedule according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_0            //keyschedule according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x0f00
    movt    r12, #0x0f00            //r12<- 0x0f000f00
    movw    r11, #0x0003
    movt    r11, #0x0003            //r11<- 0x00030003
    movw    r10, #0x003f
    movt    r10, #0x003f            //r10<- 0x003f003f
    lsl     r9, r11, #8             //r9 <- 0x03000300
    and     r8, r10, r10, lsr #3    //r8 <- 0x00070007
    orr     r7, r8, r8, lsl #2      //r7 <- 0x001f001f
    bl      key_update_1            //keyschedule according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_1            //keyschedule according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x5555
    movt    r12, #0x5555            //r12<- 0x55555555
    mvn     r11, r12                //r11<- 0xaaaaaaaa
    bl      key_update_2            //keyschedule according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_2            //keyschedule according to fixslicing
    sub.w   r1, r1, #352
    orr     r12, r8, r8, lsl #8     //r12<- 0x07070707
    movw    r11, #0xc0c0            //r11<- 0x0000c0c0
    movw    r10, #0x3030            //r10<- 0x00003030
    and     r9, r12, r12, lsr #1    //r9 <- 0x03030303
    lsl     r8, r12, #4             //r8 <- 0x70707070
    eor     r7, r8, r9, lsl #5      //r7 <- 0x10101010
    movw    r6, #0xf0f0             //r6 <- 0x0000f0f0
    bl      key_update_3            //keyschedule according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_3            //keyschedule according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x0fff
    lsl     r10, r12, #16
    movw    r8, #0x00ff             //r8 <- 0x000000ff
    movw    r7, #0x03ff             //r7 <- 0x000003ff
    lsl     r7, r7, #16
    bl      key_update_4            //keyschedule according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_4            //keyschedule according to fixslicing
    pop     {r1-r12,r14}
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
* Balanced ARM assembly implementation of the GIFTb-128 block cipher.
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
    