
; *****************************************************************************
; Data Section
section 	.data

%macro  fflush    0
    push    rdi
    mov     rdi, [stdout]       ; FILE *fp = stdout
    call    fflush
    pop     rdi
%endmacro

extern  printEndl2

; libc function references
extern  stdout
extern  free
extern  malloc
extern  printf      ;   int printf(const char *format, ...)
extern  strcmp      ;   strcmp(const char *s1, const char *s2)
extern  fflush      ;   fflush(FILE *stream)

; cs12lib function references
extern  printRAX
extern  printRBX
extern  printRCX
extern  printRDX
extern  printReg
extern  printByteArray
extern  printEndl

; fp_lib function references
extern  characterToNumber
extern  numberToCharacter
extern  _strtol
extern  createPadPage
extern  encryptMessageWithPad
extern  decryptMessageWithPad

extern  RAND_bytes

; Constants

; Variable Definitions

testingMsg      db  "Testing %s...",0
testOkMsg       db  "ok",10,0
allTestsOkMsg   db  "all tests passed!",10,0
testFailMsg     db  "Test %d failed",10,0
mCharToNum      db  "characterToNumber",0
mNumToChar      db  "numberToCharacter",0
mOurStrtol      db  "our strtol function",0
mRandBytes      db  "RAND_bytes",10,0
mEncryptMsg     db  "encryptMessageWithPad",0
mDecryptMsg     db  "decryptMessageWithPad",0
mCreatePadPage  db  "createPadPage",0
mCreatePageED   db  "createPadPageEncryptAndDecrypt",0
mMallocFailed   db  "malloc failed",10,0
mEncryptingMsg  db  "encrypting",10,0
mDecryptingMsg  db  "decrypting",10,0
mResultMsg      db  "result=%s",10,0
mPageEqualsMsg  db  "Page=%s",10,0
mDecryptTestRes db  "Test #%d:",10," - Ciphertext=%s",10," - Result=%s",10," - Expect=%s",10,0
mPassMsg        db  "pass",0
mFailMsg        db  "fail",0

strtolT1        db  "32768",0
strtolTR1       dq  32768
strtolT2        db  "13159837203765439573",0
strtolTR2       dq  13159837203765439573
strtolT3        db  "-4295302729",0
strtolTR3       dq  -4295302729
strtolT4        db  "-49295302729",0
strtolTR4       dq  -49295302729
strtolT5        db  "+1337\x00",0
strtolTR5       dq  1337
strtolT6        db  "0042",0
strtolTR6       dq  42



testMsg1        db  "Alan Turing was an English mathematician, computer scientist, logician, cryptanalyst, philosopher, and theoretical biologist",0
testKey1        db  "hxU( 3FP)-7 TA\NEmIX\oqNiL&6eHvDynDMmu12T7 _x7Pc_zAS(e:+CCvmX8P56=\YTG1-qsqlDyDnPTACTQ7+Jk._,?BnX:",0x22,";IKL3;XWG#YbJ$4,4!V!opLq3@",0
testCT1         db  "97511080006915227685880031903444944339892938441144070693221646975431121032467690622361315397253921603126693089831100574966241594879518220909291336535843124206311533081162479777073987358503983530380286110441979317261366332701638912806825704639085297",0

testMsg2        db  "Le$",0x22,"i&78*5F_cnT,3HQa17KAmAgox6CYz!.+#:'ph,lqt+(Z?",0x22,"bYt0BR$Jm6g0jPCs)O9M:ON%kh1z_#?Iqd@)FLZU==jX!EES.- w2oIPf4;y UXGv9&@3H(TkM5",0
testKey2        db  "&,(n-4d9u7VS3z=neTuX@3wpH=jB(L,k#i'V=V4D6P3Tr o3t4'_$a6Z6ary 'F7?JL\7-p@7IuMP*",0x22,"A&// +$PVtJh,Pr6u9cna8qXjA-u6Lh-05DeIqk25Md'Cb",0
testCT2         db  "4775127480268549894488078056788482882613474223050959330590634525876821633178270888588825541181750722671382755404269947056523046962175002485600756744490963946034355490624113829334919440143023146010867224567241705943426849136775714364810037595112777681",0

testMsg3        db  "One-time pads are used for encoding and decoding messages. Such correspondence is resistant to disclosure. TOP SECRET//NOFORN",0
testKey3        db  "z9pL_K7_L'lE10A5OtDF0ge(,&bvG61Kcp lK&cSMXD1QZ6eL_yMF)h 1XlfOyB.nF3N7I2jbXj8pJ0",0x22,"G=LrN%!bsJUk6Vcn@3&LUG,79f-#DZLH=56R",0x22,"CIueY",0x22,"Ri",0
testCT3         db  "2997375436099421418128979416909708781313792763728582604309839004284665690178234905179590092394284129462013683163946869132444981433099520861692413216319635031669142817392172783836122970002561349796671024149199887813537902418763547083524854230891479611",0

; *****************************************************************************
; BSS Section
section		.bss

;
; Code Section
;
section		.text


global _testCharacterToNumber
_testCharacterToNumber:

    mov     r12, 1
    mov     rdi, testingMsg
    mov     rsi, mCharToNum
    xor     rax, rax
    call    printf

.tctn1:
    mov     rdi, 0x20           ; " "
    call    characterToNumber
    cmp     rax, 0
    je      .tctn2
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tctn2:
    inc     r12
    mov     rdi, 0x65           ; "e"
    call    characterToNumber
    cmp     rax, 63
    je      .tctn3
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tctn3:
    inc     r12
    mov     rdi, 0x30           ; "0"
    call    characterToNumber
    cmp     rax, 16
    je      .tctn4
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tctn4:
    inc     r12
    mov     rdi, 0x7c           ; "|" (invalid)
    call    characterToNumber
    cmp     rax, 0
    je      .tctn5
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tctn5:
.tctnret:

    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    ret

global _testNumberToCharacter
_testNumberToCharacter:

    mov     r12, 1
    mov     rdi, testingMsg
    mov     rsi, mNumToChar
    xor     rax, rax
    call    printf

.tntc1:
    mov     rdi, 0              ; " "
    call    numberToCharacter
    mov     r11, 0x20           ; " "
    cmp     rax, r11
    je      .tntc2
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tntc2:
    inc     r12
    mov     rdi, 59           ; "a"
    call    numberToCharacter
    mov     r11, 0x61             ; "a"
    cmp     rax, r11
    je      .tntc3
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tntc3:
    inc     r12
    mov     rdi, 84             ; "z"
    call    numberToCharacter
    mov     r11, 0x7a           ; "z"
    cmp     rax, r11
    je      .tntc4
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tntc4:
    inc     r12
    mov     rdi, 57             ; "\"
    call    numberToCharacter
    mov     r11, 0x5c           ; "\"
    cmp     rax, r11
    je      .tntc5
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tntc5:
    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    ret

global _testOurStrtol
_testOurStrtol:

    mov     r12, 1
    mov     rdi, testingMsg
    mov     rsi, mOurStrtol
    xor     rax, rax
    call    printf

.tostl1:
    mov     rdi, strtolT1
    call    _strtol
    mov     rdi, [strtolTR1]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl2
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl2:
    add     r12, 1
    mov     rdi, strtolT2
    call    _strtol
    mov     rdi, [strtolTR2]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl3
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl3:
    add     r12, 1
    mov     rdi, strtolT3
    call    _strtol
    mov     rdi, [strtolTR3]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl4
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl4:
    add     r12, 1
    mov     rdi, strtolT4
    call    _strtol
    mov     rdi, [strtolTR4]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl5
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl5:
    add     r12, 1
    mov     rdi, strtolT5
    call    _strtol
    mov     rdi, [strtolTR5]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl6
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl6:
    add     r12, 1
    mov     rdi, strtolT6
    call    _strtol
    mov     rdi, [strtolTR6]
;    call    printRAX
;    call    printReg
    cmp     rax, rdi
    je      .tostl7
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tostl7:

    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    ret

global _testRandBytes
_testRandBytes:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 16

    mov     rdi, testingMsg
    mov     rsi, mRandBytes
    xor     rax, rax
    call    printf

    mov     rdi, 128    ; 128 bytes
    call    malloc
    mov     [rbp-8], rax
    cmp     qword [rbp-8], 0
    jne     getRandBytes
    mov     rdi, mMallocFailed
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit
getRandBytes:
    mov     rdi, qword [rbp-8]
    mov     rsi, 128
    call    RAND_bytes
    mov     rsi, [rbp-8]
    mov     rdx, 128
    call    printByteArray

    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    mov     rdi, [rbp-8]
    call    free

    mov     rsp, rbp
    pop     rbp
    ret


global _testCreatePadPage
_testCreatePadPage:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 48

    mov     r12, 1
    mov     rdi, testingMsg
    mov     rsi, mCreatePadPage
    xor     rax, rax
    call    printf

    fflush
    call    printEndl

    ; test page 1
    mov     rdi, 125    ; size = 125
    call    createPadPage
    mov     [rbp-8], rax

    mov     rdi, mPageEqualsMsg
    mov     rsi, [rbp-8]
    xor     rax, rax
    call    printf

    mov     rdi, [rbp-8]
    call    free

    ; test page 2
    mov     rdi, 250    ; size = 250
    call    createPadPage
    mov     [rbp-8], rax

    mov     rdi, mPageEqualsMsg
    mov     rsi, [rbp-8]
    xor     rax, rax
    call    printf

    mov     rdi, [rbp-8]
    call    free

    fflush

.tcppret:
    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    mov     rsp, rbp
    pop     rbp
    ret

global  _testCreatePadPageEncryptAndDecrypt
_testCreatePadPageEncryptAndDecrypt:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 48

    mov     rdi, testingMsg
    mov     rsi, mCreatePageED
    xor     rax, rax
    call    printf

    mov     rdi, 125        ; size = 125
    call    createPadPage
    mov     [rbp-8], rax
    cmp     qword [rbp-8], 0
    jne     .tCPPED1
    mov     rdi, 1
    call    _exit

.tCPPED1:
    fflush
    call    printEndl

    mov     rdi, mPageEqualsMsg
    mov     rsi, [rbp-8]
    xor     rax, rax
    call    printf

    mov     rdi, mEncryptingMsg
    xor     rax, rax
    call    printf

    mov     rdi, testMsg1
    mov     rsi, [rbp-8]
    call    encryptMessageWithPad
    mov     [rbp-16], rax
    cmp     qword [rbp-16], 0
    jne     .tCPPED2
    mov     rdi, 1
    call    _exit

.tCPPED2:
    mov     rdi, mResultMsg
    mov     rsi, [rbp-16]
    xor     rax, rax
    call    printf

    mov     rdi, mDecryptingMsg
    xor     rax, rax
    call    printf

    mov     rdi, [rbp-16]
    mov     rsi, [rbp-8]
    call    decryptMessageWithPad
    mov     [rbp-32], rax
    cmp     qword [rbp-32], 0
    jne     .tCPPED3
    mov     rdi, 1
    call    _exit

.tCPPED3:
    mov     rdi, mResultMsg
    mov     rsi, [rbp-32]
    xor     rax, rax
    call    printf

    ; compare
    mov     rdi, [rbp-32]
    mov     rsi, testMsg1
    call    strcmp
    cmp     rax, 0
    je      .tCPPEDSuccess
    mov     rdi, mResultMsg
    mov     rsi, mFailMsg
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tCPPEDSuccess:

    mov     rdi, testOkMsg
    xor     rax, rax
    call    printf

    ; TODO: free

    mov     rsp, rbp
    pop     rbp
    ret

global  _testEncryptMessageWithPad
_testEncryptMessageWithPad:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    push    r12

    mov     rdi, testingMsg
    mov     rsi, mEncryptMsg
    xor     rax, rax
    call    printf

    fflush

    ; test #1
    mov     r12, 1
    mov     rdi, testMsg1
    mov     rsi, testKey1
    call    encryptMessageWithPad
    mov     qword [rbp-8], rax

    mov     rdi, mResultMsg
    mov     rsi, qword [rbp-8]
    xor     rax, rax
    call    printf

    mov     rdi, qword [rbp-8]
    mov     rsi, testCT1
    call    strcmp
    cmp     rax, 0
    je      .tEMWPOk
    mov     rdi, testFailMsg
    mov     rsi, r12
    xor     rax, rax
    call    printf
    mov     rdi, 1
    call    _exit

.tEMWPOk:
    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    pop     r12
    mov     rsp, rbp
    pop     rbp
    ret

global  _testDecryptMessageWithPad
_testDecryptMessageWithPad:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    push    r12

    mov     rdi, testingMsg
    mov     rsi, mDecryptMsg
    xor     rax, rax
    call    printf

    fflush
    call    printEndl

    ; test #1
    mov     r12, 1
    mov     rdi, testCT1
    mov     rsi, testKey1
    call    decryptMessageWithPad
    mov     qword [rbp-8], rax

    ;   print result
    mov     rdi, mDecryptTestRes
    mov     rsi, r12
    mov     rdx, testCT1
    mov     rcx, qword [rbp-8]
    mov     r8,  testMsg1
    xor     rax, rax
    call    printf

    ; compare result
    mov     rdi, qword [rbp-8]
    mov     rsi, testMsg1
    call    strcmp
    cmp     rax, 0
    jne     .tDMWP1Fail
    mov     rsi, mPassMsg
    jmp     .tDMWP1PrintRes
.tDMWP1Fail:
    mov     rsi, mFailMsg
.tDMWP1PrintRes:
    mov     rdi, mResultMsg
    xor     rax, rax
    call    printf

.tDMWP2:

    ; test #2
    add     r12, 1
    mov     rdi, testCT2
    mov     rsi, testKey2
    call    decryptMessageWithPad
    mov     qword [rbp-8], rax

    ;   print result
    mov     rdi, mDecryptTestRes
    mov     rsi, r12
    mov     rdx, testCT2
    mov     rcx, qword [rbp-8]
    mov     r8,  testMsg2
    xor     rax, rax
    call    printf

    ; compare result
    mov     rdi, qword [rbp-8]
    mov     rsi, testMsg2
    call    strcmp
    cmp     rax, 0
    jne     .tDMWP2Fail
    mov     rsi, mPassMsg
    jmp     .tDMWP2PrintRes
.tDMWP2Fail:
    mov     rsi, mFailMsg
.tDMWP2PrintRes:
    mov     rdi, mResultMsg
    xor     rax, rax
    call    printf

.tDMWP3:

    ; test #3
    add     r12, 1
    mov     rdi, testCT3
    mov     rsi, testKey3
    call    decryptMessageWithPad
    mov     qword [rbp-8], rax

    ;   print result
    mov     rdi, mDecryptTestRes
    mov     rsi, r12
    mov     rdx, testCT3
    mov     rcx, qword [rbp-8]
    mov     r8,  testMsg3
    xor     rax, rax
    call    printf

    ; compare result
    mov     rdi, qword [rbp-8]
    mov     rsi, testMsg3
    call    strcmp
    cmp     rax, 0
    jne     .tDMWP3Fail
    mov     rsi, mPassMsg
    jmp     .tDMWP3PrintRes
.tDMWP3Fail:
    mov     rsi, mFailMsg
.tDMWP3PrintRes:
    mov     rdi, mResultMsg
    xor     rax, rax
    call    printf

.tDMWP4:
    mov     rdi, testOkMsg
    xor     eax, eax
    call    printf

    pop     r12
    mov     rsp, rbp
    pop     rbp
    ret

; *****************************************************************************
; Begin Program
global _start
_start:

    call    _testCharacterToNumber
    call    _testNumberToCharacter
    call    _testOurStrtol
    call    _testRandBytes
    call    _testEncryptMessageWithPad
    call    _testDecryptMessageWithPad
    call    _testCreatePadPage
    call    _testCreatePadPageEncryptAndDecrypt

    push    rbp
    mov     rbp, rsp
    sub     rbp, 32


    mov     rdi, 128
    call    malloc
    mov     qword [rbp-8], rax

    cmp     qword [rbp-8], 0
    jne     jfiowfjeiwo
    mov     rdi, 2
    call    _exit

jfiowfjeiwo:

    mov     rax, qword [rbp-8]
    mov     byte [rax], 120

    mov     rdi, rax
    call    free


    mov     rdi, allTestsOkMsg
    xor     rax, rax
    call    printf

    mov     rdi, 0
    call    _exit

    mov     rsp, rbp
    pop     rbp

    ret

global  _exit
_exit:
    mov     rax, 60   ; exit()
    syscall
