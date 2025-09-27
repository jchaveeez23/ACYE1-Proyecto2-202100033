// ===============================
// main.s  (AES-128 completo: KeyExpansion + 10 rondas con trazas)
// ===============================

// IMPORTAR ARCHIVO CONSTANTS.S (Sbox, Rcon)
.include "constants.s"

// ===== CADENAS DE TEXTO =====
.section .data
    msg_txt: .asciz "Ingrese el texto a cifrar (maximo 16 caracteres): "
        lenMsgTxt = . - msg_txt

    msg_key: .asciz "Ingrese la clave (32 caracteres hex): "
        lenMsgKey = . - msg_key

    key_err_msg: .asciz "Error: Valor de clave incorrecto\n"
        lenKeyErr = . - key_err_msg

    newline: .asciz "\n"
    
    debug_state: .asciz "Matriz de Estado:\n"
        lenDebugState = . - debug_state
    
    debug_key: .asciz "Matriz de Clave:\n"
        lenDebugKey = . - debug_key

    debug_ark: .asciz "Resultado AddRoundKey:\n"
        lenDebugARK = . - debug_ark

    debug_sub: .asciz "Resultado SubBytes:\n"
        lenDebugSub = . - debug_sub

    debug_shift: .asciz "Resultado ShiftRows:\n"
        lenDebugShift = . - debug_shift

    debug_mix: .asciz "Resultado MixColumns:\n"
        lenDebugMix = . - debug_mix

    debug_roundkey: .asciz "Subclave de la Ronda:\n"
        lenDebugRK = . - debug_roundkey

    debug_round_in: .asciz "Estado de entrada de la ronda:\n"
        lenDebugRoundIn = . - debug_round_in

    debug_final: .asciz "Cifrado final (tras Ronda 10):\n"
        lenDebugFinal = . - debug_final

// ===== RESERVACION DE MEMORIA =====
.section .bss
    .global matState
    matState:       .space 16, 0

    .global key
    key:            .space 16, 0

    // buffers de trabajo
    .global state_cur
    state_cur:      .space 16, 0
    .global state_sub
    state_sub:      .space 16, 0
    .global state_shift
    state_shift:    .space 16, 0
    .global state_mix
    state_mix:      .space 16, 0

    // Key schedule: 44 palabras (176B)
    .global roundWords
    roundWords:     .space 176, 0

    // Subclave en formato matriz (16B col-major)
    .global roundKeyMat
    roundKeyMat:    .space 16, 0

    buffer:         .space 256, 0
    temp_buffer:    .space 64, 0

// ===== MACROS =====
.macro print fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64
    svc #0
.endm

.macro read fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63
    svc #0
.endm

// ===== CODIGO FUENTE =====
.section .text

// ----------------------
// Copiar 16 bytes (x0=src, x1=dst)
// ----------------------
.type copy16, %function
.global copy16
copy16:
    ldr x2, [x0]
    ldr x3, [x0, #8]
    str x2, [x1]
    str x3, [x1, #8]
    ret

// ----------------------
// Imprimir "Ronda N" (w0=N)
// ----------------------
.type printRoundTitle, %function
.global printRoundTitle
printRoundTitle:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #32
    mov w2, #'R';  strb w2, [sp, #0]
    mov w2, #'o';  strb w2, [sp, #1]
    mov w2, #'n';  strb w2, [sp, #2]
    mov w2, #'d';  strb w2, [sp, #3]
    mov w2, #'a';  strb w2, [sp, #4]
    mov w2, #' ';  strb w2, [sp, #5]
    cmp w0, #10
    b.lt 1f
    mov w2, #'1';  strb w2, [sp, #6]
    mov w2, #'0';  strb w2, [sp, #7]
    mov w2, #10;   strb w2, [sp, #8]     // '\n'
    mov x2, #9
    b 2f
1:
    add w2, w0, #'0'; strb w2, [sp, #6]
    mov w2, #10;      strb w2, [sp, #7]
    mov x2, #8
2:
    mov x0, #1
    mov x1, sp
    mov x8, #64
    svc #0
    add sp, sp, #32
    ldp x29, x30, [sp], #16
    ret

// ----------------------
// AddRoundKey (x0=state, x1=key, x2=out)
// ----------------------
.type   addRoundKey, %function
.global addRoundKey
addRoundKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr x3, [x0]
    ldr x4, [x0, #8]
    ldr x5, [x1]
    ldr x6, [x1, #8]
    eor x7, x3, x5
    eor x8, x4, x6
    str x7, [x2]
    str x8, [x2, #8]
    ldp x29, x30, [sp], #16
    ret
    .size addRoundKey, (. - addRoundKey)

// ----------------------
// SubBytes (x0=in, x1=out)
// ----------------------
.type   subBytes, %function
.global subBytes
subBytes:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x20, x0
    mov x21, x1
    mov x22, #0
    ldr x23, =Sbox
1:
    cmp x22, #16
    b.ge 2f
    ldrb w24, [x20, x22]
    uxtb w24, w24
    ldrb w25, [x23, x24]     // índice en X (ok)
    strb w25, [x21, x22]
    add x22, x22, #1
    b 1b
2:
    ldp x29, x30, [sp], #16
    ret
    .size subBytes, (. - subBytes)

// ----------------------
// ShiftRows (row-major)  x0=in, x1=out
// ----------------------
.type   shiftRows, %function
.global shiftRows
shiftRows:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x20, x0
    mov x21, x1
    // Fila 0
    ldrb w0, [x20, #0];  ldrb w1, [x20, #1]
    ldrb w2, [x20, #2];  ldrb w3, [x20, #3]
    strb w0, [x21, #0];  strb w1, [x21, #1]
    strb w2, [x21, #2];  strb w3, [x21, #3]
    // Fila 1: 5,6,7,4
    ldrb w0, [x20, #4];  ldrb w1, [x20, #5]
    ldrb w2, [x20, #6];  ldrb w3, [x20, #7]
    strb w1, [x21, #4];  strb w2, [x21, #5]
    strb w3, [x21, #6];  strb w0, [x21, #7]
    // Fila 2: 10,11,8,9
    ldrb w0, [x20, #8];   ldrb w1, [x20, #9]
    ldrb w2, [x20, #10];  ldrb w3, [x20, #11]
    strb w2, [x21, #8];   strb w3, [x21, #9]
    strb w0, [x21, #10];  strb w1, [x21, #11]
    // Fila 3: 15,12,13,14
    ldrb w0, [x20, #12];  ldrb w1, [x20, #13]
    ldrb w2, [x20, #14];  ldrb w3, [x20, #15]
    strb w3, [x21, #12];  strb w0, [x21, #13]
    strb w1, [x21, #14];  strb w2, [x21, #15]
    ldp x29, x30, [sp], #16
    ret
    .size shiftRows, (. - shiftRows)

// ----------------------
// MixColumns (x0=in, x1=out)
// ----------------------
.type   mixColumns, %function
.global mixColumns
mixColumns:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x20, x0
    mov x21, x1
    mov x22, #0
    mov w27, #0x1B
mix_col_loop:
    cmp x22, #4
    b.ge mix_done
    mov x23, x22
    add x24, x23, #4
    add x25, x23, #8
    add x26, x23, #12
    ldrb w0, [x20, x23]
    ldrb w1, [x20, x24]
    ldrb w2, [x20, x25]
    ldrb w3, [x20, x26]
    // ×2 para a0..a3
    mov  w4, w0; and w9, w4, #0x80; lsl w4, w4, #1; and w4, w4, #0xFF; cbz w9, 1f; eor w4, w4, w27
1:  mov  w5, w1; and w9, w5, #0x80; lsl w5, w5, #1; and w5, w5, #0xFF; cbz w9, 2f; eor w5, w5, w27
2:  mov  w6, w2; and w9, w6, #0x80; lsl w6, w6, #1; and w6, w6, #0xFF; cbz w9, 3f; eor w6, w6, w27
3:  mov  w7, w3; and w9, w7, #0x80; lsl w7, w7, #1; and w7, w7, #0xFF; cbz w9, 4f; eor w7, w7, w27
4:
    // r0..r3
    eor  w8, w5, w1; eor w8, w8, w4; eor w8, w8, w2; eor w8, w8, w3; strb w8, [x21, x23]
    eor  w8, w6, w2; eor w8, w8, w5; eor w8, w8, w0; eor w8, w8, w3; strb w8, [x21, x24]
    eor  w8, w7, w3; eor w8, w8, w6; eor w8, w8, w0; eor w8, w8, w1; strb w8, [x21, x25]
    eor  w8, w4, w0; eor w8, w8, w1; eor w8, w8, w2; eor w8, w8, w7; strb w8, [x21, x26]
    add x22, x22, #1
    b mix_col_loop
mix_done:
    ldp x29, x30, [sp], #16
    ret
    .size mixColumns, (. - mixColumns)

// ----------------------
// KeyExpansion (AES-128)  x0=key(16B col-major), x1=roundWords(176B)
// ----------------------
.type   keyExpansion, %function
.global keyExpansion
keyExpansion:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    mov x19, x0
    mov x20, x1
    // W0..W3 desde columnas
    mov x2, #0
ke_init_cols:
    cmp x2, #4
    b.ge ke_init_done
    ldrb w3, [x19, x2]
    add x4, x2, #4;  ldrb w4, [x19, x4]
    add x5, x2, #8;  ldrb w5, [x19, x5]
    add x6, x2, #12; ldrb w6, [x19, x6]
    orr w7, wzr, w3
    orr w7, w7, w4, lsl #8
    orr w7, w7, w5, lsl #16
    orr w7, w7, w6, lsl #24
    add x8, x20, x2, lsl #2
    str w7, [x8]
    add x2, x2, #1
    b ke_init_cols
ke_init_done:
    // W4..W43
    add x9,  x20, #16
    mov x10, x20
    mov w11, #4
    mov w12, #0
    ldr x13, =Sbox
    ldr x14, =Rcon
ke_loop:
    cmp w11, #44
    b.ge ke_done
    ldr w4, [x9, #-4]         // temp = W[i-1]
    and w15, w11, #3
    cbnz w15, ke_no_core
    // core: RotWord + SubWord + Rcon
    ror w4, w4, #24
    uxtb w5, w4
    ldrb w5, [x13, w5, uxtw]
    lsr  w6, w4, #8;  uxtb w6, w6
    ldrb w6, [x13, w6, uxtw]
    lsr  w7, w4, #16; uxtb w7, w7
    ldrb w7, [x13, w7, uxtw]
    lsr  w8, w4, #24; uxtb w8, w8
    ldrb w8, [x13, w8, uxtw]
    orr  w4, wzr, w5
    orr  w4, w4, w6, lsl #8
    orr  w4, w4, w7, lsl #16
    orr  w4, w4, w8, lsl #24
    ldr  w17, [x14, w12, uxtw #2]
    eor  w4, w4, w17
    add  w12, w12, #1
ke_no_core:
    ldr w6, [x10]
    eor w6, w6, w4
    str w6, [x9]
    add x9, x9, #4
    add x10, x10, #4
    add w11, w11, #1
    b ke_loop
ke_done:
    ldp x29, x30, [sp], #32
    ret
    .size keyExpansion, (. - keyExpansion)

// ----------------------
// formatRoundKey: roundWords -> matriz col-major (x0=&roundWords, w1=round, x2=&out)
// ----------------------
.type   formatRoundKey, %function
.global formatRoundKey
formatRoundKey:
    add  x3, x0, w1, uxtw #4        // base = round*16
    mov  x4, #0
frk_col_loop:
    cmp  x4, #4
    b.ge frk_done
    add  x5, x3, x4, lsl #2
    ldr  w6, [x5]
    uxtb w7,  w6
    lsr  w8,  w6, #8;  uxtb w8,  w8
    lsr  w9,  w6, #16; uxtb w9,  w9
    lsr  w10, w6, #24; uxtb w10, w10
    strb w7,  [x2, x4]
    add  x11, x4, #4;  strb w8,  [x2, x11]
    add  x11, x4, #8;  strb w9,  [x2, x11]
    add  x11, x4, #12; strb w10, [x2, x11]
    add  x4, x4, #1
    b frk_col_loop
frk_done:
    ret
    .size formatRoundKey, (. - formatRoundKey)

// ----------------------
// printMatrix (x0=ptr, x1=msg, x2=len)  [impresión row-major]
// ----------------------
.type   printMatrix, %function
.global printMatrix
printMatrix:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    str x0, [sp, #16]
    str x1, [sp, #24]
    str x2, [sp, #32]
    mov x0, #1
    ldr x1, [sp, #24]
    ldr x2, [sp, #32]
    mov x8, #64
    svc #0
    mov x23, #0
pm_row_loop:
    cmp x23, #4
    b.ge pm_done
    mov x24, #0
pm_col_loop:
    cmp x24, #4
    b.ge pm_row_nl
    mov x25, #4
    mul x25, x23, x25
    add x25, x25, x24
    ldr x20, [sp, #16]
    ldrb w0, [x20, x25]
    bl print_hex_byte
    add x24, x24, #1
    b pm_col_loop
pm_row_nl:
    print 1, newline, 1
    add x23, x23, #1
    b pm_row_loop
pm_done:
    print 1, newline, 1
    ldp x29, x30, [sp], #48
    ret

// ----------------------
// print_hex_byte (W0 = byte a imprimir)
// ----------------------
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    and w1, w0, #0xF0; lsr w1, w1, #4
    and w2, w0, #0x0F
    cmp w1, #10; b.lt hd
    add w1, w1, #'A' - 10; b hdone
hd: add w1, w1, #'0'
hdone:
    cmp w2, #10; b.lt ld
    add w2, w2, #'A' - 10; b ldone
ld: add w2, w2, #'0'
ldone:
    sub sp, sp, #16
    strb w1, [sp]; strb w2, [sp, #1]
    mov w3, #' '; strb w3, [sp, #2]
    mov x0, #1; mov x1, sp; mov x2, #3; mov x8, #64; svc #0
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret

// ----------------------
// Ejecutar y mostrar 10 rondas completas
// ----------------------
.type   runAES10, %function
.global runAES10
runAES10:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Estado inicial -> state_cur
    ldr x0, =matState
    ldr x1, =state_cur
    bl  copy16

    // ===== Ronda 0: ARK con W0..W3 =====
    mov w0, #0
    bl  printRoundTitle

    ldr x0, =roundWords
    mov w1, #0
    ldr x2, =roundKeyMat
    bl  formatRoundKey

    // imprimir subclave ronda 0
    ldr x0, =roundKeyMat
    ldr x1, =debug_roundkey
    mov x2, lenDebugRK
    bl  printMatrix

    // AddRoundKey(state_cur, roundKeyMat) -> state_cur
    ldr x0, =state_cur
    ldr x1, =roundKeyMat
    ldr x2, =state_cur
    bl  addRoundKey

    ldr x0, =state_cur
    ldr x1, =debug_ark
    mov x2, lenDebugARK
    bl  printMatrix

    // ===== Rondas 1..9 =====
    mov w19, #1
r_loop:
    cmp w19, #10
    b.ge r_last

    // Título
    mov w0, w19
    bl  printRoundTitle

    // Entrada de ronda
    ldr x0, =state_cur
    ldr x1, =debug_round_in
    mov x2, lenDebugRoundIn
    bl  printMatrix

    // SubBytes
    ldr x0, =state_cur
    ldr x1, =state_sub
    bl  subBytes
    ldr x0, =state_sub
    ldr x1, =debug_sub
    mov x2, lenDebugSub
    bl  printMatrix

    // ShiftRows
    ldr x0, =state_sub
    ldr x1, =state_shift
    bl  shiftRows
    ldr x0, =state_shift
    ldr x1, =debug_shift
    mov x2, lenDebugShift
    bl  printMatrix

    // MixColumns
    ldr x0, =state_shift
    ldr x1, =state_mix
    bl  mixColumns
    ldr x0, =state_mix
    ldr x1, =debug_mix
    mov x2, lenDebugMix
    bl  printMatrix

    // Subclave de la ronda i
    ldr x0, =roundWords
    mov w1, w19
    ldr x2, =roundKeyMat
    bl  formatRoundKey
    ldr x0, =roundKeyMat
    ldr x1, =debug_roundkey
    mov x2, lenDebugRK
    bl  printMatrix

    // AddRoundKey -> state_cur
    ldr x0, =state_mix
    ldr x1, =roundKeyMat
    ldr x2, =state_cur
    bl  addRoundKey
    ldr x0, =state_cur
    ldr x1, =debug_ark
    mov x2, lenDebugARK
    bl  printMatrix

    add w19, w19, #1
    b r_loop

// ===== Ronda 10 (sin MixColumns) =====
r_last:
    // Título
    mov w0, #10
    bl  printRoundTitle

    // Entrada de ronda
    ldr x0, =state_cur
    ldr x1, =debug_round_in
    mov x2, lenDebugRoundIn
    bl  printMatrix

    // SubBytes
    ldr x0, =state_cur
    ldr x1, =state_sub
    bl  subBytes
    ldr x0, =state_sub
    ldr x1, =debug_sub
    mov x2, lenDebugSub
    bl  printMatrix

    // ShiftRows
    ldr x0, =state_sub
    ldr x1, =state_shift
    bl  shiftRows
    ldr x0, =state_shift
    ldr x1, =debug_shift
    mov x2, lenDebugShift
    bl  printMatrix

    // Subclave ronda 10
    ldr x0, =roundWords
    mov w1, #10
    ldr x2, =roundKeyMat
    bl  formatRoundKey
    ldr x0, =roundKeyMat
    ldr x1, =debug_roundkey
    mov x2, lenDebugRK
    bl  printMatrix

    // AddRoundKey final -> state_cur (ciphertext)
    ldr x0, =state_shift
    ldr x1, =roundKeyMat
    ldr x2, =state_cur
    bl  addRoundKey
    ldr x0, =state_cur
    ldr x1, =debug_ark
    mov x2, lenDebugARK
    bl  printMatrix

    // Cifrado final (extra)
    ldr x0, =state_cur
    ldr x1, =debug_final
    mov x2, lenDebugFinal
    bl  printMatrix

    ldp x29, x30, [sp], #16
    ret
    .size runAES10, (. - runAES10)


// ----------------------
// Lectura/parseo de texto y clave
// ----------------------
.type   readTextInput, %function
.global readTextInput
readTextInput:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    read 0, buffer, 256
    ldr x1, =buffer
    ldr x2, =matState
    mov x3, #0
rt_loop:
    cmp x3, #16
    b.ge rt_pad
    ldrb w4, [x1, x3]
    cmp w4, #10
    b.eq rt_pad
    cmp w4, #0
    b.eq rt_pad
    // column-major: (idx%4)*4 + (idx/4)
    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x9, x7
    add x10, x10, x8
    strb w4, [x2, x10]
    add x3, x3, #1
    b rt_loop
rt_pad:
    cmp x3, #16
    b.ge rt_done
    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x9, x7
    add x10, x10, x8
    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b rt_pad
rt_done:
    ldp x29, x30, [sp], #16
    ret

.type   convertHexKey, %function
.global convertHexKey
convertHexKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    read 0, buffer, 33
    ldr x1, =buffer
    ldr x2, =key
    mov x3, #0
    mov x11, #0
chk_loop:
    cmp x3, #16
    b.ge conv_done
skip_non_hex:
    ldrb w4, [x1, x11]
    cmp w4, #0
    b.eq conv_done
    cmp w4, #10
    b.eq conv_done
    bl is_hex_char
    cmp w0, #1
    b.eq do_pair
    add x11, x11, #1
    b skip_non_hex
do_pair:
    ldrb w4, [x1, x11]; add x11, x11, #1
    bl hex_char_to_nibble; lsl w5, w0, #4
    ldrb w4, [x1, x11]; add x11, x11, #1
    bl hex_char_to_nibble; orr w5, w5, w0
    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x9, x7
    add x10, x10, x8
    strb w5, [x2, x10]
    add x3, x3, #1
    b chk_loop
conv_done:
    ldp x29, x30, [sp], #16
    ret

// Aux HEX
is_hex_char:
    cmp w4, #'0'; b.lt not_hex
    cmp w4, #'9'; b.le is_hex
    orr w4, w4, #0x20
    cmp w4, #'a'; b.lt not_hex
    cmp w4, #'f'; b.le is_hex
not_hex: mov w0, #0; ret
is_hex:  mov w0, #1; ret

hex_char_to_nibble:
    cmp w4, #'0'; b.lt hex_error
    cmp w4, #'9'; b.le hex_digit
    orr w4, w4, #0x20
    cmp w4, #'a'; b.lt hex_error
    cmp w4, #'f'; b.gt hex_error
    sub w0, w4, #'a'; add w0, w0, #10; ret
hex_digit:
    sub w0, w4, #'0'; ret
hex_error:
    print 1, key_err_msg, lenKeyErr
    mov w0, #0; ret

// ----------------------
// _start
// ----------------------
.type   _start, %function
.global _start
_start:
    // Leer texto
    print 1, msg_txt, lenMsgTxt
    bl readTextInput
    // Mostrar estado inicial
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    // Leer clave
    print 1, msg_key, lenMsgKey
    bl convertHexKey
    // Mostrar clave base (como matriz de 16B)
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix

    // Expandir clave (genera W0..W43)
    ldr x0, =key
    ldr x1, =roundWords
    bl  keyExpansion

    // Ejecutar 10 rondas imprimiendo todos los pasos
    bl  runAES10

    // Salir
    mov x0, #0
    mov x8, #93
    svc #0
    .size _start, (. - _start)
