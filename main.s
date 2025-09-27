// ===============================
// main.s  (AES-128: AddRoundKey + SubBytes + ShiftRows + MixColumns)
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

// ===== RESERVACION DE MEMORIA =====
.section .bss
    .global matState
    matState:       .space 16, 0       // estado 16B

    .global key
    key:            .space 16, 0       // clave 16B

    .global criptograma
    criptograma:    .space 16, 0       // salida AddRoundKey

    .global state_sub
    state_sub:      .space 16, 0       // salida SubBytes

    .global state_shift
    state_shift:    .space 16, 0       // salida ShiftRows

    .global state_mix
    state_mix:      .space 16, 0       // salida MixColumns

    buffer:         .space 256, 0
    temp_buffer:    .space 64, 0

// ===== MACROS =====
.macro print fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64          // sys_write
    svc #0
.endm

.macro read fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63          // sys_read
    svc #0
.endm

// ===== CODIGO FUENTE =====
.section .text

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
    ldrb w25, [x23, x24]
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

    // Fila 0: 0,1,2,3 (igual)
    ldrb w0, [x20, #0];  ldrb w1, [x20, #1]
    ldrb w2, [x20, #2];  ldrb w3, [x20, #3]
    strb w0, [x21, #0];  strb w1, [x21, #1]
    strb w2, [x21, #2];  strb w3, [x21, #3]

    // Fila 1: 4,5,6,7 -> 5,6,7,4
    ldrb w0, [x20, #4];  ldrb w1, [x20, #5]
    ldrb w2, [x20, #6];  ldrb w3, [x20, #7]
    strb w1, [x21, #4];  strb w2, [x21, #5]
    strb w3, [x21, #6];  strb w0, [x21, #7]

    // Fila 2: 8,9,10,11 -> 10,11,8,9
    ldrb w0, [x20, #8];   ldrb w1, [x20, #9]
    ldrb w2, [x20, #10];  ldrb w3, [x20, #11]
    strb w2, [x21, #8];   strb w3, [x21, #9]
    strb w0, [x21, #10];  strb w1, [x21, #11]

    // Fila 3: 12,13,14,15 -> 15,12,13,14
    ldrb w0, [x20, #12];  ldrb w1, [x20, #13]
    ldrb w2, [x20, #14];  ldrb w3, [x20, #15]
    strb w3, [x21, #12];  strb w0, [x21, #13]
    strb w1, [x21, #14];  strb w2, [x21, #15]

    ldp x29, x30, [sp], #16
    ret
    .size shiftRows, (. - shiftRows)


// ----------------------
// MixColumns (x0=in, x1=out)  // por columnas: c, c+4, c+8, c+12
// ----------------------
.type   mixColumns, %function
.global mixColumns
mixColumns:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x20, x0        // in
    mov x21, x1        // out
    mov x22, #0        // col = 0..3
    mov w27, #0x1B     // polinomio de reducción

mix_col_loop:
    cmp x22, #4
    b.ge mix_done

    // offsets de la columna
    mov x23, x22          // c
    add x24, x23, #4      // c+4
    add x25, x23, #8      // c+8
    add x26, x23, #12     // c+12

    // a0..a3
    ldrb w0, [x20, x23]
    ldrb w1, [x20, x24]
    ldrb w2, [x20, x25]
    ldrb w3, [x20, x26]

    // xtime (×2) para a0..a3 -> w4..w7
    // w4 = m2(a0)
    mov  w4, w0
    and  w9, w4, #0x80
    lsl  w4, w4, #1
    and  w4, w4, #0xFF
    cbz  w9, 1f
    eor  w4, w4, w27
1:
    // w5 = m2(a1)
    mov  w5, w1
    and  w9, w5, #0x80
    lsl  w5, w5, #1
    and  w5, w5, #0xFF
    cbz  w9, 2f
    eor  w5, w5, w27
2:
    // w6 = m2(a2)
    mov  w6, w2
    and  w9, w6, #0x80
    lsl  w6, w6, #1
    and  w6, w6, #0xFF
    cbz  w9, 3f
    eor  w6, w6, w27
3:
    // w7 = m2(a3)
    mov  w7, w3
    and  w9, w7, #0x80
    lsl  w7, w7, #1
    and  w7, w7, #0xFF
    cbz  w9, 4f
    eor  w7, w7, w27
4:
    // r0 = 2*a0 ^ 3*a1 ^ a2 ^ a3
    eor  w8, w5, w1          // 3*a1
    eor  w8, w8, w4
    eor  w8, w8, w2
    eor  w8, w8, w3
    strb w8, [x21, x23]

    // r1 = a0 ^ 2*a1 ^ 3*a2 ^ a3
    eor  w8, w6, w2          // 3*a2
    eor  w8, w8, w5
    eor  w8, w8, w0
    eor  w8, w8, w3
    strb w8, [x21, x24]

    // r2 = a0 ^ a1 ^ 2*a2 ^ 3*a3
    eor  w8, w7, w3          // 3*a3
    eor  w8, w8, w6
    eor  w8, w8, w0
    eor  w8, w8, w1
    strb w8, [x21, x25]

    // r3 = 3*a0 ^ a1 ^ a2 ^ 2*a3
    eor  w8, w4, w0          // 3*a0
    eor  w8, w8, w1
    eor  w8, w8, w2
    eor  w8, w8, w7
    strb w8, [x21, x26]

    add x22, x22, #1
    b mix_col_loop

mix_done:
    ldp x29, x30, [sp], #16
    ret
    .size mixColumns, (. - mixColumns)

// ----------------------
// Leer texto (máx 16) → matState (column-major en memoria)
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
    
convert_text_loop:
    cmp x3, #16
    b.ge pad_remaining_bytes
    
    ldrb w4, [x1, x3]
    cmp w4, #10
    b.eq pad_remaining_bytes
    cmp w4, #0
    b.eq pad_remaining_bytes
    
    // column-major: offset = (idx%4)*4 + (idx/4)
    mov x7, #4
    udiv x8, x3, x7          // col
    msub x9, x8, x7, x3      // row
    mul x10, x9, x7
    add x10, x10, x8
    
    strb w4, [x2, x10]
    add x3, x3, #1
    b convert_text_loop
    
pad_remaining_bytes:
    cmp x3, #16
    b.ge convert_text_done

    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x9, x7
    add x10, x10, x8

    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b pad_remaining_bytes
    
convert_text_done:
    ldp x29, x30, [sp], #16
    ret
    .size readTextInput, (. - readTextInput)


// ----------------------
// Convertir clave hex → key (column-major)
// ----------------------
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
    
convert_hex_loop:
    cmp x3, #16
    b.ge convert_hex_done
    
skip_non_hex:
    ldrb w4, [x1, x11]
    cmp w4, #0
    b.eq convert_hex_done
    cmp w4, #10
    b.eq convert_hex_done
    
    bl is_hex_char
    cmp w0, #1
    b.eq process_hex_pair
    
    add x11, x11, #1
    b skip_non_hex
    
process_hex_pair:
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    lsl w5, w0, #4
    
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    orr w5, w5, w0
    
    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x9, x7
    add x10, x10, x8
    
    strb w5, [x2, x10]
    add x3, x3, #1
    b convert_hex_loop
    
convert_hex_done:
    ldp x29, x30, [sp], #16
    ret
    .size convertHexKey, (. - convertHexKey)


// ----------------------
// Auxiliares HEX
// ----------------------
is_hex_char:
    cmp w4, #'0'
    b.lt not_hex
    cmp w4, #'9'
    b.le is_hex
    orr w4, w4, #0x20
    cmp w4, #'a'
    b.lt not_hex
    cmp w4, #'f'
    b.le is_hex
not_hex:
    mov w0, #0
    ret
is_hex:
    mov w0, #1
    ret

hex_char_to_nibble:
    cmp w4, #'0'
    b.lt hex_error
    cmp w4, #'9'
    b.le hex_digit
    orr w4, w4, #0x20
    cmp w4, #'a'
    b.lt hex_error
    cmp w4, #'f'
    b.gt hex_error
    sub w0, w4, #'a'
    add w0, w0, #10
    ret
hex_digit:
    sub w0, w4, #'0'
    ret
hex_error:
    print 1, key_err_msg, lenKeyErr
    mov w0, #0
    ret


// ----------------------
// printMatrix (x0=ptr, x1=msg, x2=len)
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
row_loop:
    cmp x23, #4
    b.ge pm_done
    mov x24, #0
col_loop:
    cmp x24, #4
    b.ge row_nl
    mov x25, #4
    mul x25, x23, x25      // fila*4
    add x25, x25, x24      // + columna  -> row-major de impresión
    ldr x20, [sp, #16]
    ldrb w0, [x20, x25]
    bl print_hex_byte
    add x24, x24, #1
    b col_loop
row_nl:
    print 1, newline, 1
    add x23, x23, #1
    b row_loop
pm_done:
    print 1, newline, 1
    ldp x29, x30, [sp], #48
    ret
    .size printMatrix, (. - printMatrix)


// ----------------------
// print_hex_byte (W0 = byte a imprimir)
// ----------------------
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F
    cmp w1, #10
    b.lt hd
    add w1, w1, #'A' - 10
    b hdone
hd:
    add w1, w1, #'0'
hdone:
    cmp w2, #10
    b.lt ld
    add w2, w2, #'A' - 10
    b ldone
ld:
    add w2, w2, #'0'
ldone:
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov w3, #' '
    strb w3, [sp, #2]
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x8, #64
    svc #0
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret


// ----------------------
// encript: ARK -> SubBytes -> ShiftRows -> MixColumns
// ----------------------
.type   encript, %function
.global encript
encript:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // AddRoundKey → criptograma
    ldr x0, =matState
    ldr x1, =key
    ldr x2, =criptograma
    bl  addRoundKey

    // SubBytes(criptograma → state_sub)
    ldr x0, =criptograma
    ldr x1, =state_sub
    bl  subBytes

    // ShiftRows(state_sub → state_shift)
    ldr x0, =state_sub
    ldr x1, =state_shift
    bl  shiftRows

    // MixColumns(state_shift → state_mix)
    ldr x0, =state_shift
    ldr x1, =state_mix
    bl  mixColumns

    ldp x29, x30, [sp], #16
    ret
    .size encript, (. - encript)


// ----------------------
// _start
// ----------------------
.type   _start, %function
.global _start
_start:
    // Leer texto
    print 1, msg_txt, lenMsgTxt
    bl readTextInput

    // Mostrar estado
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    // Leer clave
    print 1, msg_key, lenMsgKey
    bl convertHexKey

    // Mostrar clave
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix

    // Ejecutar pipeline
    bl encript

    // Mostrar AddRoundKey
    ldr x0, =criptograma
    ldr x1, =debug_ark
    mov x2, lenDebugARK
    bl printMatrix

    // Mostrar SubBytes
    ldr x0, =state_sub
    ldr x1, =debug_sub
    mov x2, lenDebugSub
    bl printMatrix

    // Mostrar ShiftRows
    ldr x0, =state_shift
    ldr x1, =debug_shift
    mov x2, lenDebugShift
    bl printMatrix

    // Mostrar MixColumns
    ldr x0, =state_mix
    ldr x1, =debug_mix
    mov x2, lenDebugMix
    bl printMatrix
    
    // Salir
    mov x0, #0
    mov x8, #93
    svc #0
    .size _start, (. - _start)
