%include "definitions.mac"

section 	.data

; libc functions
extern  __errno_location    ;   int *__errno_location (void)
extern  free                ;   void free(void *ptr)
extern  malloc              ;   void *malloc(size_t size)
extern  memset              ;   void *memset(void *s, int c, size_t n)
extern  strlen              ;   size_t strlen(const char *s)
extern  printf              ;    int printf(const char *format, ...)
extern  sprintf             ;   sprintf(char *str, const char *format, ...)
extern  perror              ;   void perror (const char *message)

; openssl functions
extern  RAND_bytes          ;   int RAND_bytes(unsigned char *buf, int num);

; variable definitions

; The subsitution table for the one time pad
; Characters are represented by their position in the table.
; i.e. (space) = 0, ! = 1, " = 2, "0" = 16, "9" = 26, "A" = 31, "Z" = 56, "a" = 59, "p" = 74, "z" = 84
; Characters not found in the table are considered invalid and are not permitted in messages.
substitution_table      db  " !",0x22,"#$%&'()*+,-./0123456789:;=?@ABCDEFGHIJLKMNOPQRSTUVWXYZ\_abcdefghijlkmnopqrstuvwxyz"
substitution_table_size dq  $-substitution_table

nullbyte                db  0           ; for printNewline
string_format           db  "%s",10,0   ; for printNewline
number_format           db  "%02d",0    ; for formatting output digits in encryptMessageWithPad

msgFileOpenError        db  "Error opening file",0      ; openFile error message

section		.text


; *****************************************************************************
; Output a newline
;   Prints a newline character to the console
; Preconditions:
;   - None
; Postconditions:
;   - A newline is printed to the console
;   - Registers are *not* preserved!
;
global  printNewline
printNewline:
    mov     rdi, string_format
    mov     rsi, nullbyte
    xor     rax, rax
    call    printf
    ret

; *****************************************************************************
; Get the last error number from a libc function call
;   Gets the last error (if any) from a libc function call and places it in the
;   rax register
; Preconditions:
;   - None
; Postconditions:
;   - rax contains the last error number
;   - registers remain unchanged
;
global  geterrno
geterrno:
    call    __errno_location
    mov     rax, [rax]
    ret

; *****************************************************************************
; Set the error number in libc's errno variable
;   Stores the supplied error number in libc's "errno" variable (e.g. for use
;   with perror.
; Preconditions:
;   - rdi contains the error number to set (must be >= 0)
; Postconditions:
;   - rax contains the location of errno
;   - libc errno is set with the value from rdi
;   - registers remain unchanged
;
global  seterrno
seterrno:
    call    __errno_location
    mov     [rax], rdi
    ret


; *****************************************************************************
; Character to number (for message encryption)
;   Converts an ASCII character to its corresponding numeric value from the
;   substitution table.
; Preconditions:
;   - rdi contains the ASCII code of the character to convert
; Postconditions:
;   - rax contains the numeric code for the input character.
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If the character does not exist in the table, rax = 0
;
global characterToNumber
characterToNumber:

    push    rsi
    push    rcx
    push    rdx

    mov     rax, 0      ; code   = 0
    mov     rsi, 0      ; number = 0
    mov     rcx, [substitution_table_size]  ; counter = length of table
    dec     rcx                             ; - 1

characterToNumberLoop:
    ; iterate over the substitution table until the character is found
    lea     r10, [substitution_table+rcx]   ; c = table[offset]
    movzx   r11, byte [r10]
    cmp     r11, rdi                        ; compare table character to input
    jne     characterToNumberNext           ; if (c != character)
    mov     rax, rcx                        ; ret = i
    jmp     characterToNumberReturn         ; return
characterToNumberNext:
    loop    characterToNumberLoop

characterToNumberReturn:
    pop     rdx
    pop     rcx
    pop     rsi
    ret

; *****************************************************************************
; Number code to character
;   Converts a numeric code to its corresponding ASCII character in the
;   substitution table.
; Preconditions:
;   - rdi contains code to convert to a character
; Postconditions:
;   - rax contains the ASCII value for the numeric code
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If the code is outside of the range of the table, rax = 0
;
global numberToCharacter
numberToCharacter:

    mov     rax, 0                          ; ret = 0
    cmp     rdi, 0                          ; i = 0
    jl      numberToCharacterReturn         ; if i < 0: return
    cmp     rdi, [substitution_table_size]
    jae     numberToCharacterReturn         ; if i > strlen(table): return
    lea     r10, [substitution_table+rdi]   ; c = table[i]
    movzx   rax,  byte [r10]                 ; return c
numberToCharacterReturn:
    ret

; *****************************************************************************
; Convert a null-terminated numeric string to an unsigned 64-bit integer
;   Converts an ascii string to a 64-bit numeric integer. Stops reading when a
;   non-numeric character or null byte (\x00) is reached. Handles leading sign.
;
; Preconditions:
;   - rdi is a pointer to a null-terminated ascii string.
; Postconditions:
;   - rax contains the numeric value of the string
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If the string is non-numeric, 0 is returned.
;
global _strtol
_strtol:

    push    rcx
    push    rdi
    push    rsi

    mov     rsi, 1              ; sign multiplier
    xor     rax, rax            ; ret = 0

    ; check for leading +/- sign
    cmp     byte [rdi], '-'
    jne     ._strtolchksign     ; if num[0] == '-'
    mov     rsi, -1             ; multiplier = -1
    add     rdi, 1              ; advance pointer
._strtolchksign:
    cmp     byte [rdi], '+'
    jne     ._strtolnextdigit   ; if num[0] == '+'
    add     rdi, 1              ; advance pointer
._strtolnextdigit:
    movzx   rcx, byte [rdi]     ; get next digit of string
    inc     rdi                 ; increment pointer
    cmp     rcx, 0x30
    jb      ._strtoldone        ; if byte < '0' return
    cmp     rcx, 0x39
    ja      ._strtoldone        ; if byte > '9' return
    sub     rcx, 0x30           ; substract 0x30 to get numeric value
    imul    rax, 10             ; multiply current result by 10
    add     rax, rcx            ; add current digit
    jmp     ._strtolnextdigit   ; loop
._strtoldone:

    imul    rax, rsi            ; multiply result by sign

    pop     rsi
    pop     rdi
    pop     rcx

    ret

; *****************************************************************************
; Create a "page" of a one time pad
;   Allocates heap memory to hold a page of pad data and places a truly random
;   key (one time pad) in it. The random bytes are converted to characters from
;   the substitution table.
; Preconditions:
;   - rdi contains the number of characters (bytes) to fill the page with
; Postconditions:
;   - rax pointer to allocated memory containing the page data
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If memory could not be allocated, rax is a NULL pointer (0)
;
global createPadPage
createPadPage:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 40
    push    rbx
    ;   [rbp-32]  = size
    ;   [rbp-24] = *page
    ;   [rbp-16] = *bytes
    ;   [rbp- 8] = return

    mov     qword [rbp-8], 1     ; ret = 1
    mov     qword [rbp-32], rdi  ; size = bytes

    ; allocate memory for page
    mov     rax, qword [rbp-32]
    mov     rdi, rax
    call    malloc              ; page = malloc(size)
    mov     qword [rbp-24], rax ; store result
    cmp     qword [rbp-24], 0   ; if (page == NULL)
    jne     .cPP1
    mov     qword [rbp-8], 0    ; ret = 0
    jmp     createPadPageReturn ; return

.cPP1:
    ; allocate space for random bytes
    mov     rax, qword [rbp-32] ; size = bytes
    mov     rdi, rax
    call    malloc              ; bytes = malloc(size)
    mov     qword [rbp-16], rax
    cmp     qword [rbp-16], 0   ; if (bytes == NULL)
    jne     .cPP2
    mov     qword [rbp-8], 0    ; ret = 0
    jmp     createPadPageReturn ; return

.cPP2:
    ;   get random bytes
    mov     rdi, qword [rbp-16]     ; buf
    mov     rsi, qword [rbp-32]     ; count
    call    RAND_bytes              ; TODO: check for 0 or -1 and print error
    cmp     rax, 1                  ; if (ret == success)
    je      createPadPageToTable
    mov     qword [rbp-8], 0        ; ret = 0
    je      createPadPageReturn     ; return

createPadPageToTable:
    ; Convert a page of random bytes to values from the substitution table
    mov     rcx, 0                  ; i = 0
createPadPageToTableLoop:
    cmp     [rbp-32], ecx           ; if characters >= i: break
    jle     loopDone

    ; offset = random byte % strlen(table)
    mov     rdx, [rbp-16]                       ; bytes
    movzx   rax, byte [rdx+rcx]                 ; tmp = bytes[i]
    cqo                                         ; sign extend rax to rdx:rax
    div     qword [substitution_table_size]     ; for modulus
    mov     rax, rdx                            ; rdx = remainder

    ; page[i] = substitution_table[tmp % length(table)]
    mov     rdx, qword [rbp-24]     ; page
    add     rdx, rcx                ; page + offset
    mov     rax, [substitution_table+rax]   ; c = table[i]
    mov     byte [rdx], al                  ; page[offset] = c

    inc     rcx                             ; i += 1
    jmp     createPadPageToTableLoop
loopDone:

createPadPageReturn:
    cmp     qword [rbp-16], 0   ; if (bytes != 0)
    je      .cppRet2
    mov     rdi, qword [rbp-16]
    call    free                ; free(bytes)
.cppRet2:
    cmp     qword [rbp-8], 0    ; if (ret == 0)
    jne     .cppRet3
    mov     rax, qword [rbp-24]
    mov     rdi, rax
    call    free                ; free(page)
.cppRet3:

    cmp     qword [rbp-8], 0        ; ret == 0?
    je      .cppRet4                ; if ret == 0: return
    mov     rax, qword [rbp-24]     ; ret = page
    jmp     .cppRet5                ; return

.cppRet4:

    mov     rax, 0

.cppRet5:

    pop     rbx
    mov     rsp, rbp
    pop     rbp

    ret

; *****************************************************************************
; Encrypt a message with a one time pad
;   Encrypt a message using the Vernam cipher and a one time pad.
;
; Preconditions:
;   - rdi contains the address of a null terminated message to encrypt
;   - rsi contains the address to a page of data from the pad
;   - the length of the message *must not* exceed the length of the pad
; Postconditions:
;   - rax pointer to allocated memory containing the encrypted message
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If memory could not be allocated, rax is a NULL pointer (0)
;
global  encryptMessageWithPad
encryptMessageWithPad:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 36     ; allocate locals
    push    r13
    ;       [rbp-36] = i
    ;       [rbp-32] = length
    ;       [rbp-24] = pointer to message
    ;       [rbp-16] = pointer to pad
    ;       [rbp- 8] = pointer to ciphertext

    mov     [rbp-24], qword rdi        ; message
    mov     [rbp-16], qword rsi        ; pad

    ; get length of message
    mov     rax, qword [rbp-24]
    call    strlen
    mov     qword [rbp-32], rax

    ; allocate buffer for encrypted message
    ; ciphertext = malloc(length * 2 + 1)
    mov     rdi, qword [rbp-24]         ; length
    add     rdi, rdi                    ; * 2
    add     rdi, 1                      ; + 1
    mov     r13, rdi                    ; save length
    call    malloc
    cmp     rax, 0
    je      encryptMessageWithPadReturn
    mov     [rbp-8], rax

    ; memset(void *s, int c, size_t n)
    mov     rdi, [rbp-8]
    mov     rsi, 0
    mov     rdx, r13
    call    memset

    ; for int i = 0; i < length; ++i
    mov     dword [rbp-36], 0     ; for i = 0
    xor     r13, r13
.eMWPLoop1:
    mov     eax, dword [rbp-32]
    cmp     dword [rbp-36], eax
    jge      .eMWPLoopEnd

    ; r13 = characterToNumber(message[i])
    mov     rsi, [rbp-24]
    add     esi, dword [rbp-36]
    movzx   rdi, byte [rsi]
    call    characterToNumber
    mov     r13, rax

    ; rax = characterToNumber(page[i])
    mov     rsi, [rbp-16]
    add     esi, dword [rbp-36]
    movzx   rdi, byte [rsi]
    call    characterToNumber

    ; tmp = (r13 + rax % 100)
    add     rax, r13
    mov     rdx, 0
    mov     rcx, 100
    idiv    rcx
    mov     rax, rdx        ; rdx contains remainder (modulo)

    ; sprintf(ciphertext + (i * 2), "%02d", rdx)
    mov     eax, dword [rbp-36]     ; i
    add     eax, eax                ; *= 2
    mov     rcx, rax
    mov     rax, qword [rbp-8]      ; ciphertext
    lea     rdi, [rcx+rax]          ; ciphertext + (i * 2)
    mov     rsi, number_format
    mov     rax, 0
    call    sprintf

    add     dword [rbp-36], 1
    jmp     .eMWPLoop1
.eMWPLoopEnd:

    mov     rax, [rbp-8]

encryptMessageWithPadReturn:
    pop     r13
    mov     rsp, rbp
    pop     rbp
    ret


; *****************************************************************************
; Decrypt a message with a one time pad
;   Decrypts a message using the Vernam cipher and a one time pad.
;
; Preconditions:
;   - rdi contains the address of a null terminated ciphertext to decrypt
;   - rsi contains the address to a page of data from the pad
;   - the length of the message *must not* exceed the length of the pad
; Postconditions:
;   - rax pointer to allocated memory containing the decrypted message
;   - rbx, rcx, rdx, rsi, and rdi remain unchanged
;   - If memory could not be allocated, rax is a NULL pointer (0)
;
global  decryptMessageWithPad
decryptMessageWithPad:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 56     ; allocate locals

    ;   [rbp-56] = page
    ;   [rbp-48] = ciphertext
    ;   [rbp-40] = tmp
    ;   [rbp-32] = buf[8]
    ;   [rbp-24] = message_length
    ;   [rbp-16] = length
    ;   [rbp- 8] = decrypted

    mov     [rbp-48], rdi       ; ciphertext = $1
    mov     [rbp-56], rsi       ; page = $2

    ; TODO: assert(message_length % 2 == 0)

    ; message_length = strlen(ciphertext)
    mov     rdi, [rbp-48]
    call    strlen
    mov     [rbp-24], rax

    ; calculate length of decryption buffer
    ; length = (message_length / 2) + 1
    mov     rax, qword [rbp-24]     ; message length
    cqo                             ; sign extend for division
    mov     rcx, 2                  ; divisor
    idiv    rcx
    inc     rax                     ; add 1 to result for null byte
    mov     [rbp-16], rax           ; store length

    ; decrypted = malloc(length)
    mov     rdi, [rbp-16]
    call    malloc
    mov     [rbp-8], rax            ; decrypted buffer
    cmp     rax, 0                  ; if (decrypted == NULL) return ;
    je      .dMWPRet

    ; memset(decrypted, 0, length)
    mov     rdi, rax
    mov     rsi, 0
    mov     rdx, [rbp-16]
    call    memset

    ; for i = 0; i < message_length; i += 2
    mov     rcx, 0
.dMWPLoopNext:
    cmp     rcx, [rbp-24]       ; if i >= message length: return
    jae     .dMWPLoopDone

    ; buf[0] = ciphertext[i]
    mov     rax, [rbp-48]       ; ciphertext
    add     rax, rcx            ; ciphertext[i]
    movzx   rax, byte [rax]     ; get byte of ciphertext
    mov     byte [rbp-32], al   ; buf[0] = ciphertext[i]

    ; buf[1] = ciphertext[i + 1]
    mov     rax, [rbp-48]       ; ciphertext
    lea     rax, [rcx+rax+1]    ; ciphertext[i + 1]
    movzx   rax, byte [rax]     ; get byte of ciphertext
    mov     byte [rbp-31], al   ; buf[0] = ciphertext[i+1]

    ; buf[2] = \0
    mov     byte [rbp-30], 0    ; buf[2] = \0

    ; tmp = strtol(buf)
    lea     rdi, qword [rbp-32]
    call    _strtol
    mov     qword [rbp-40], rax

    ; tmp2 = characterToNumber(page[i/2])
    xor     rdx, rdx
    mov     rax, rcx            ; i
    mov     rdi, 2
    div     rdi                 ; i / 2
    mov     rdi, [rbp-56]       ; page
    add     rdi, rax            ; page[i/2]
    movzx   rdi, byte [rdi]
    call    characterToNumber

    ; tmp =- tmp2
    mov     rdi, [rbp-40]
    sub     rdi, rax
    cmp     rdi, 0
    jge     .dMWPNoAddition
    add     rdi, 100                ; if tmp2 < 0: tmp2 += 100
.dMWPNoAddition:
    call    numberToCharacter
    mov     qword [rbp-40], rax

    ; decrypted[i / 2] = characterToNumber(tmp)
    xor     rdx, rdx
    mov     rax, rcx
    mov     rdi, 2
    div     rdi
    mov     rdi, [rbp-8]
    add     rdi, rax
    mov     rax, [rbp-40]
    mov     [rdi], al

.dMWPLoopEnd:
    add     rcx, 2
    jmp     .dMWPLoopNext
.dMWPLoopDone:

    mov     rax, [rbp-8]

.dMWPRet:
    mov     rsp, rbp
    pop     rbp
    ret

; *****************************************************************************
; Open a file and check for errors
;   Opens a file and outputs an error message on failure
;
; Preconditions:
;   - rdi contains the address of a null terminated file name to open
;   - rsi contains status flags for SYS_open
; Postconditions:
;   - rax contains the result of the open syscall (< 0 is an error)
;   - on success, rax contains the file descriptor for the opened file
;   - on error, an error message is printed to the console
;
global openFile
openFile:

    ; attempt to open the file (rdi and rsi are passed in)
    mov     rax, SYS_open
    syscall
    push    rax                     ; store return value

    cmp     rax, 0                  ; compare return to 0
    jge     openFileReturn          ; if return >= 0: return

    ; get -errno (errno *= -1)
    cqo                             ; sign extend rax
    xor     rax, rdx
    sub     rax, rdx
    cdqe

    __seterrno  rax                 ; set errno in libc
    mov     rdi, msgFileOpenError   ; set message
    call    perror                  ; call perror

openFileReturn:
    pop     rax                     ; restore result of syscall
    ret
