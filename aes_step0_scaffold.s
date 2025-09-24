    .global _start

    .section .data
plaintext:
    .byte 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
key128:
    .byte 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f

    .section .bss
    .balign 16
state:  .skip 16

    .section .text
_start:
    // state = plaintext
    adr   x0, plaintext
    adr   x1, state
    mov   x2, #16
0:
    ldrb  w3, [x0], #1
    strb  w3, [x1], #1
    subs  x2, x2, #1
    b.ne  0b

    // write(1, state, 16)
    mov   x0, #1
    adr   x1, state
    mov   x2, #16
    mov   x8, #64      // sys_write
    svc   #0

    // exit(0)
    mov   x0, #0
    mov   x8, #93
    svc   #0
