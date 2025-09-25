    .section .data
plaintext:
    .byte 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
key128:
    .byte 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f

SBox:
    .byte 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
    .byte 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
    .byte 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
    .byte 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
    .byte 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
    .byte 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
    .byte 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
    .byte 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
    .byte 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
    .byte 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
    .byte 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
    .byte 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
    .byte 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
    .byte 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
    .byte 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
    .byte 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16

    .section .bss
    .balign 16
state:  .skip 16
tmp16:  .skip 16

    .section .text
    .global _start

// ----------------- helper: print_state -----------------
// write(1, state, 16)
print_state:
    mov   x0, #1
    ldr   x1, =state
    mov   x2, #16
    mov   x8, #64
    svc   #0
    ret

// ----------------- AddRoundKey -----------------
add_round_key:
    mov   x2, #16
1:  ldrb  w3, [x0]
    ldrb  w4, [x1]
    eor   w3, w3, w4
    strb  w3, [x0]
    add   x0, x0, #1
    add   x1, x1, #1
    subs  x2, x2, #1
    b.ne  1b
    // limpiar temporales
    mov   w2, wzr
    mov   w3, wzr
    mov   w4, wzr
    ret

// ----------------- SubBytes -----------------
sub_bytes:
    mov   x2, #16
2:  ldrb  w3, [x0]
    add   x4, x1, x3, uxtw    // SBox[x3]
    ldrb  w5, [x4]
    strb  w5, [x0]
    add   x0, x0, #1
    subs  x2, x2, #1
    b.ne  2b
    // limpiar temporales
    mov   w2, wzr
    mov   w3, wzr
    mov   w4, wzr
    mov   w5, wzr
    ret

// ----------------- ShiftRows (x0=&state, x1=&tmp16) -----------------
shift_rows:
    // copia 15..0 (evita leer [#16])
    mov   x2, #15
3:  ldrb  w3, [x0, x2]
    strb  w3, [x1, x2]
    subs  x2, x2, #1
    b.pl  3b

    // fila 0
    ldrb w3,[x1,#0];  strb w3,[x0,#0]
    ldrb w3,[x1,#4];  strb w3,[x0,#4]
    ldrb w3,[x1,#8];  strb w3,[x0,#8]
    ldrb w3,[x1,#12]; strb w3,[x0,#12]
    // fila 1
    ldrb w3,[x1,#5];  strb w3,[x0,#1]
    ldrb w3,[x1,#9];  strb w3,[x0,#5]
    ldrb w3,[x1,#13]; strb w3,[x0,#9]
    ldrb w3,[x1,#1];  strb w3,[x0,#13]
    // fila 2
    ldrb w3,[x1,#10]; strb w3,[x0,#2]
    ldrb w3,[x1,#14]; strb w3,[x0,#6]
    ldrb w3,[x1,#2];  strb w3,[x0,#10]
    ldrb w3,[x1,#6];  strb w3,[x0,#14]
    // fila 3
    ldrb w3,[x1,#15]; strb w3,[x0,#3]
    ldrb w3,[x1,#3];  strb w3,[x0,#7]
    ldrb w3,[x1,#7];  strb w3,[x0,#11]
    ldrb w3,[x1,#11]; strb w3,[x0,#15]

    // limpiar temporales
    mov   w2, wzr
    mov   w3, wzr
    ret

// ----------------- xtime: w0 -> 2*w0 (GF 2^8) -----------------
xtime:
    lsl   w1, w0, #1
    uxtb  w1, w1
    tst   w0, #0x80
    b.eq  9f
    mov   w2, #0x1b
    eor   w1, w1, w2
9:  mov   w0, w1
    // limpiar temporales
    mov   w1, wzr
    mov   w2, wzr
    ret

// ----------------- mul3: w0 -> 3*w0 = (2*w0)^w0 -----------------
mul3:
    mov   w10, w0
    bl    xtime
    eor   w0, w0, w10
    // limpiar temporales
    mov   w10, wzr
    ret

// ----------------- MixColumns (unrolled, seguro) -----------------
// x0 = &state (16 bytes)
mix_columns:
    mov   w5, #0x80
    mov   w6, #0x1B

    // ===== columna 0 =====
    ldrb  w16, [x0,#0];  ldrb  w17, [x0,#1];  ldrb  w18, [x0,#2];  ldrb  w19, [x0,#3]
    eor   w7, w16, w17;  eor w7, w7, w18;  eor w7, w7, w19
    eor   w9, w16, w17;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 0f; eor w12,w12,w6
0:  eor   w10,w16,w7;   eor w10,w10,w12            // s0
    eor   w9, w17, w18;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 1f; eor w12,w12,w6
1:  eor   w11,w17,w7;   eor w11,w11,w12            // s1
    eor   w9, w18, w19;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 2f; eor w12,w12,w6
2:  eor   w13,w18,w7;   eor w13,w13,w12            // s2
    eor   w9, w19, w16;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 3f; eor w12,w12,w6
3:  eor   w14,w19,w7;   eor w14,w14,w12            // s3
    strb  w10,[x0,#0];   strb w11,[x0,#1];         strb w13,[x0,#2]; strb w14,[x0,#3]

    // ===== columna 1 =====
    ldrb  w16, [x0,#4];  ldrb  w17, [x0,#5];  ldrb  w18, [x0,#6];  ldrb  w19, [x0,#7]
    eor   w7, w16, w17;  eor w7, w7, w18;  eor w7, w7, w19
    eor   w9, w16, w17;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 4f; eor w12,w12,w6
4:  eor   w10,w16,w7;   eor w10,w10,w12
    eor   w9, w17, w18;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 5f; eor w12,w12,w6
5:  eor   w11,w17,w7;   eor w11,w11,w12
    eor   w9, w18, w19;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 6f; eor w12,w12,w6
6:  eor   w13,w18,w7;   eor w13,w13,w12
    eor   w9, w19, w16;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 7f; eor w12,w12,w6
7:  eor   w14,w19,w7;   eor w14,w14,w12
    strb  w10,[x0,#4];   strb w11,[x0,#5];         strb w13,[x0,#6]; strb w14,[x0,#7]

    // ===== columna 2 =====
    ldrb  w16, [x0,#8];  ldrb  w17, [x0,#9];  ldrb  w18, [x0,#10]; ldrb w19,[x0,#11]
    eor   w7, w16, w17;  eor w7, w7, w18;         eor w7, w7, w19
    eor   w9, w16, w17;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 8f; eor w12,w12,w6
8:  eor   w10,w16,w7;   eor w10,w10,w12
    eor   w9, w17, w18;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 9f; eor w12,w12,w6
9:  eor   w11,w17,w7;   eor w11,w11,w12
    eor   w9, w18, w19;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 10f; eor w12,w12,w6
10: eor   w13,w18,w7;   eor w13,w13,w12
    eor   w9, w19, w16;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 11f; eor w12,w12,w6
11: eor   w14,w19,w7;   eor w14,w14,w12
    strb  w10,[x0,#8];   strb w11,[x0,#9];         strb w13,[x0,#10]; strb w14,[x0,#11]

    // ===== columna 3 =====
    ldrb  w16,[x0,#12];  ldrb w17,[x0,#13]; ldrb w18,[x0,#14]; ldrb w19,[x0,#15]
    eor   w7, w16, w17;  eor w7, w7, w18;         eor w7, w7, w19
    eor   w9, w16, w17;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 12f; eor w12,w12,w6
12: eor   w10,w16,w7;   eor w10,w10,w12
    eor   w9, w17, w18;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 13f; eor w12,w12,w6
13: eor   w11,w17,w7;   eor w11,w11,w12
    eor   w9, w18, w19;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 14f; eor w12,w12,w6
14: eor   w13,w18,w7;   eor w13,w13,w12
    eor   w9, w19, w16;  lsl w12,w9,#1; uxtb w12,w12; tst w9,w5; b.eq 15f; eor w12,w12,w6
15: eor   w14,w19,w7;   eor w14,w14,w12
    strb  w10,[x0,#12];  strb w11,[x0,#13];        strb w13,[x0,#14]; strb w14,[x0,#15]

    // limpiar temporales usados aquí
    mov   w5, wzr; mov w6, wzr; mov w7, wzr; mov w9, wzr
    mov   w10,wzr; mov w11,wzr; mov w12,wzr; mov w13,wzr; mov w14,wzr
    mov   w16,wzr; mov w17,wzr; mov w18,wzr; mov w19,wzr
    ret

// ----------------- Main -----------------
_start:
    // state = plaintext
    ldr   x0, =plaintext
    ldr   x1, =state
    mov   x2, #16
0:
    ldrb  w3, [x0], #1
    strb  w3, [x1], #1
    subs  x2, x2, #1
    b.ne  0b

    // AddRoundKey
    ldr   x0, =state
    ldr   x1, =key128
    bl    add_round_key
    bl    print_state      // << imprime

    // SubBytes
    ldr   x0, =state
    ldr   x1, =SBox
    bl    sub_bytes
    bl    print_state      // << imprime

    // ShiftRows
    ldr   x0, =state
    ldr   x1, =tmp16
    bl    shift_rows
    bl    print_state      // << imprime

    // MixColumns
    ldr   x0, =state
    bl    mix_columns
    bl    print_state      // << imprime

    // exit(0)
    mov   x0, #0
    mov   x8, #93
    svc   #0
