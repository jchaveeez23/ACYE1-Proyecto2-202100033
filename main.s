// IMPORTAR ARCHIVI CONSTANTS.S
.include "constants.s"

//CADENAS DE TEXTO
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

// ===== RESERVACION DE MEMORIA =====
.section .bss
    .global matState
    matState:       .space 16, 0         // Matriz de estado del texto en claro de 128 bits

    .global key
    key:            .space 16, 0         // Matriz de llave inicial de 128 bits

    .global criptograma
    criptograma:    .space 16, 0         // Buffer para almacenar el resultado de la encriptacion

    buffer:         .space 256, 0        // Buffer utilizado para almacenar la entrada del usuario
    temp_buffer:    .space 64, 0         // Buffer temporal

//  MACROS 
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

//  CODIGO FUENTE 
.section .text

// Función para leer cadena de texto y convertir a bytes ASCII
.type   readTextInput, %function
.global readTextInput
readTextInput:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Leer entrada del usuario
    read 0, buffer, 256
    
    // Convertir caracteres a bytes ASCII y almacenar en matriz
    ldr x1, =buffer           // Puntero al buffer de entrada
    ldr x2, =matState         // Puntero a matriz de estado
    mov x3, #0                // Contador de bytes procesados
    
convert_text_loop:
    cmp x3, #16
    b.ge pad_remaining_bytes
    
    ldrb w4, [x1, x3]         // Cargar carácter
    cmp w4, #10               // Verificar si es newline
    b.eq pad_remaining_bytes
    cmp w4, #0                // Verificar si es null terminator
    b.eq pad_remaining_bytes
    
    // Almacenar carácter como byte ASCII en column-major order
    // Calcular índice: (index % 4) + (index / 4) * 4
    mov x7, #4
    udiv x8, x3, x7           // columna = index / 4
    msub x9, x8, x7, x3       // fila = index % 4
    mul x10, x9, x7           // offset = fila * 4
    add x10, x10, x8          // offset final = fila * 4 + columna
    
    strb w4, [x2, x10]        // Almacenar byte ASCII
    add x3, x3, #1
    b convert_text_loop
    
pad_remaining_bytes:
    // Rellenar bytes restantes con ceros
    cmp x3, #16
    b.ge convert_text_done
    
    mov x7, #4
    udiv x8, x3, x7           // columna = index / 4
    msub x9, x8, x7, x3       // fila = index % 4
    mul x10, x9, x7           // offset = fila * 4
    add x10, x10, x8          // offset final
    
    mov w4, #0                // Padding con ceros
    strb w4, [x2, x10]
    add x3, x3, #1
    b pad_remaining_bytes
    
convert_text_done:
    ldp x29, x30, [sp], #16
    ret
    .size readTextInput, (. - readTextInput)

 // Función para convertir clave hexadecimal
.type   convertHexKey, %function
.global convertHexKey
convertHexKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Leer clave hexadecimal
    read 0, buffer, 33
    
    ldr x1, =buffer           // Puntero al buffer
    ldr x2, =key              // Puntero a matriz de clave
    mov x3, #0                // Contador de bytes
    mov x11, #0               // Índice del buffer
    
convert_hex_loop:
    cmp x3, #16
    b.ge convert_hex_done
    
// Saltar espacios y caracteres no válidos hasta encontrar hex
skip_non_hex:
    ldrb w4, [x1, x11]
    cmp w4, #0
    b.eq convert_hex_done
    cmp w4, #10               // newline
    b.eq convert_hex_done
    
    // Verificar si es carácter hex válido
    bl is_hex_char
    cmp w0, #1
    b.eq process_hex_pair
    
    add x11, x11, #1
    b skip_non_hex
    
process_hex_pair:
    // Procesar par de caracteres hex
    ldrb w4, [x1, x11]       // Primer nibble
    add x11, x11, #1
    bl hex_char_to_nibble
    lsl w5, w0, #4
    
    ldrb w4, [x1, x11]       // Segundo nibble
    add x11, x11, #1
    bl hex_char_to_nibble
    orr w5, w5, w0
    
    // Almacenar en column-major order
    mov x7, #4
    udiv x8, x3, x7           // columna = index / 4
    msub x9, x8, x7, x3       // fila = index % 4
    mul x10, x9, x7           // offset = fila * 4
    add x10, x10, x8          // offset final
    
    strb w5, [x2, x10]
    add x3, x3, #1
    b convert_hex_loop
    
convert_hex_done:
    ldp x29, x30, [sp], #16
    ret
    .size convertHexKey, (. - convertHexKey)

 // Función auxiliar: verificar si es carácter hex

is_hex_char:
    cmp w4, #'0'
    b.lt not_hex
    cmp w4, #'9'
    b.le is_hex
    
    orr w4, w4, #0x20         // Convertir a minúscula
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

 // Función auxiliar: convertir carácter hex a nibble
hex_char_to_nibble:
    cmp w4, #'0'
    b.lt hex_error
    cmp w4, #'9'
    b.le hex_digit
    
    orr w4, w4, #0x20         // Convertir a minúscula
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

 // Función para imprimir matriz en formato debug
.type   printMatrix, %function
.global printMatrix
printMatrix:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    
    // Guardar parámetros
    str x0, [sp, #16]         // matriz
    str x1, [sp, #24]         // mensaje
    str x2, [sp, #32]         // longitud mensaje
    
    // Imprimir mensaje
    mov x0, #1
    ldr x1, [sp, #24]
    ldr x2, [sp, #32]
    mov x8, #64
    svc #0
    
    // Imprimir matriz 4x4
    mov x23, #0               // contador de filas
    
print_row_loop:
    cmp x23, #4
    b.ge print_matrix_done
    
    mov x24, #0               // contador de columnas
    
print_col_loop:
    cmp x24, #4
    b.ge print_row_newline
    
    // Calcular índice column-major: fila*4 + columna
    mov x25, #4
    mul x25, x23, x25
    add x25, x25, x24
    
    // Cargar y mostrar byte
    ldr x20, [sp, #16]        // Recuperar puntero a matriz
    ldrb w0, [x20, x25]
    bl print_hex_byte
    
    add x24, x24, #1
    b print_col_loop
    
print_row_newline:
    print 1, newline, 1
    add x23, x23, #1
    b print_row_loop
    
print_matrix_done:
    print 1, newline, 1
    ldp x29, x30, [sp], #48
    ret
    .size printMatrix, (. - printMatrix)

 // Función para imprimir byte en hexadecimal
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    // Separar nibbles
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F
    
    // Convertir nibble alto
    cmp w1, #10
    b.lt high_digit
    add w1, w1, #'A' - 10
    b high_done
high_digit:
    add w1, w1, #'0'
high_done:
    
    // Convertir nibble bajo
    cmp w2, #10
    b.lt low_digit
    add w2, w2, #'A' - 10
    b low_done
low_digit:
    add w2, w2, #'0'
low_done:
    
    // Imprimir
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

 // Función de encriptación (placeholder)
.type   encript, %function
.global encript
encript:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // TODO: Implementar algoritmo AES
    ldr x0, =matState
    ldr x1, =criptograma
    mov x2, #16
copy_loop:
    cbz x2, copy_done
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    sub x2, x2, #1
    b copy_loop
copy_done:

    ldp x29, x30, [sp], #16
    ret
    .size encript, (. - encript)

 // Función principal
.type   _start, %function
.global _start
_start:
    // Leer texto como cadena
    print 1, msg_txt, lenMsgTxt
    bl readTextInput
    
    // Debug: mostrar matriz de estado
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // Leer clave en hexadecimal
    print 1, msg_key, lenMsgKey
    bl convertHexKey
    
    // Debug: mostrar matriz de clave
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix
    
    // Encriptar
    bl encript
    
    // Salir
    mov x0, #0
    mov x8, #93
    svc #0
    .size _start, (. - _start)