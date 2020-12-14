; Macros
%include "definitions.mac"


; *****************************************************************************
; Data Section
section 	.data

extern  geterrno
extern  seterrno

; libc function references
extern  stdin
extern  getchar     ;   int getchar()
extern  fgets       ;   char * fgets (char *s, int count, FILE *stream)
extern  fflush      ;   fflush(FILE *stream)
extern  printf      ;   int printf(const char *format, ...)
extern  sprintf     ;   int sprintf(char *str, const char *format, ...)
extern  strtol      ;   long int strtol (const char *restrict string, char **restrict tailptr, int base)
extern  strlen      ;   size_t strlen(const char *s)
extern  malloc      ;   void *malloc(size_t size)
extern  free        ;   void free(void *ptr)
extern  memset      ;   void *memset(void *s, int c, size_t n)
extern  perror      ;   void perror (const char *message)

; HLL call
;   int pbkdf2_test(char *pass, int passlen, char **key_out)
extern  pbkdf2_test

extern  openFile
extern  printNewline
extern  createPadPage
extern  encryptMessageWithPad

; Constants

MAX_MENU_ENTRIES    equ 16

; Variable Definitions
space               db  " "

; Main menu variables
menuItemFormat      db  "%2d. %s",10,0
mainMenuPrompt      db  "What would you like to do?",10,10,0
createPadPrompt     db  "Create a new pad",0
writeMessagePrompt  db  "Write a message to an agent",0
quitProgramPrompt   db  " q. Quit to operating system",10,10,0
menuSelectPrompt    db  "Enter selection: ",0
invalidSelection    db  "Invalid selection. Try again.",10,10,0

; Create pad menu variables
msgCreatePad        db  "Okay let's create a pad.",10,10,0
promptAgentNum      db  "Enter agent number: ",0
msgInvalidFileName  db  "Invalid entry. Agent ID must consist only of digits.",10,10,0
msgFileNameTooLong  db  "Invalid entry. Agent ID cannot exceed 15 digits.",10,10,0
fileNameFormat      db  "./%s.txt",0
msgCreatingPad      db  "Creating true random one time pad...",0
msgPadCreated       db  "Pad created and saved to %s",10,0
msgPadWriteError    db  "Error writing pad data",0

; Create message menu variables
msgWriteMessage     db  "Okay, let's encrypt a message.",10,0
msgAgentForPage     db  "We will encode a message from file %s using page %ld.",10,10,0
msgPromptMessage    db  "Secret message: ",0
msgErrMsgTooLong    db  "Error: Message exceeds pad length. Enter a shorter message.",10,0
msgInMessage        db  "   Plaintext => %s",10,0
msgCipherKey        db  "         Pad => %s",10,0
msgCiphertext       db  "  Ciphertext => ",0
msgPageDestroyed    db  "Page destroyed. Agent's next page is %ld.",10,0

; Generic message variables
msgMallocFailed     db  "Failed to allocate memory.",10,0
msgFileReadIOError  db  "Error reading file",0
msgFileReadEOFError db  "Reached end-of-file without finding current page. File corrupted or not a pad file?",10,0

msgDecryptedMessage	db	"Your message is: %s",10,0
testMessage         db	"This is a test!",0
msgYourKeyMessage   db  "Your key (from assembly) = %16s",10,0
msgNotSecretPass    db  "This is a not-so-secret pass. It's hiding in plain sight.",0
passwordLength      dd  59
msgAddressOf        db  "The address of val = %X",10,0
msgValueOf          db  "The value of val = %d",10,0
msgFail             db  "Failed",10,0
secretkey           dq  0

; *****************************************************************************
; BSS Section
section		.bss

;
; Variable Declarations
;
menuEntries     resq    MAX_MENU_ENTRIES    ; max 15 menu items, end with NULL item
                                            ; menuEntries[0] = addr     ; first
                                            ; menuEntries[1] = addr     ; second
                                            ; menuEntries[2] = addr     ; last
                                            ; menuEntries[3] = 0        ; terminator

;
; Code Section
;
section		.text

; *****************************************************************************
; Main menu function
; Preconditions:
;   - menuEntries is initialized with valid menu items
; Postconditions:
;   - rax contains the return value from running the menu
;
; Return value:
;   -1 if quit was selected, otherwise a value from 1 to MAX_MENU_ENTRIES representing the selected menu entry
;
global  main_menu
main_menu:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 128     ; char buf[40]
    push    rbx
    push    r12
    push    r15

mainMenuStart:
    ; Initialize register variables
    mov     r12, 0                          ; counter
    mov     r15, 0                          ; total number of menu items
    mov     rdi, mainMenuPrompt             ; Display prompt "What would you like to do?"
    xor     eax, eax                        ; variable arg function, no varargs; set AL to 0
    call    printf

    ; Display menu items
menuItemLoop:

    mov     rax, [menuEntries+8*r12]        ; get address of message from menuEntries
    cmp     rax, 0                          ; 0 = end of menu items
    je      menuItemLoopDone
    inc     r15                             ; increment # of menu items
    mov     rdx, rax                        ; menu item string
    mov     rsi, r12
    inc     rsi                             ; menu item #
    mov     rdi, menuItemFormat             ; format string
    xor     eax, eax
    call    printf

    inc     r12                             ; next menu item
    jmp     menuItemLoop
menuItemLoopDone:

    ; Display "Quit" option
    mov     rdi, quitProgramPrompt          ; Quit to OS message
    xor     eax, eax
    call    printf

    ; Prompt for input & read selection
    mov     rdi, menuSelectPrompt
    xor     eax, eax
    call    printf

    mov     byte [rbp-32+15], 127   ; sentinel value for input length
    __seterrno  0                   ; clear libc errno
    mov     rdx, [stdin]            ; FILE *fp = &stdin
    mov     rsi, 16                 ; count = 16
    lea     rdi, qword [rbp-32]     ; char *s = &buf
    call    fgets

    cmp     rax, 0          ; return == 0?
    je      mainMenuStart   ; re-display menu
    cmp     rax, 0          ; check for read error
    jne     checkInput      ; if return != 0: no error
    mov     rdi, 0          ; null
    call    perror          ; display error based on errno
    jmp     menuItemLoop

checkInput:
    movzx   rax, byte [rbp-32+16]   ; buf[len-1]
    cmp     byte [rbp], 0           ; null?
    jne     checkEntry
    movzx   rax, byte [rbp-32+15]   ; buf[len-2]
    cmp     rax, 10                 ; '\n'?
    je      checkEntry              ; okay
    cmp     rax, 127                ; sentinel?
    je      checkEntry              ; if yes, check entry
    movzx   rax, byte [rbp-32]
    consumeStdin                    ; consume remainder of stdin

checkEntry:
    ; Check entry
    movzx   rax, byte [rbp-32]  ; char c = buf[0]
    cmp     rax, 0x71   ; 'q'   ; compare c to 'q'
    jne     checkInput2
    mov     rax, -1             ; got 'q'
    jmp     mainMenuReturn
checkInput2:
    cmp     rax, 0x51           ; compare c to 'Q'
    jne     itemCheck
    mov     rax, -1             ; got 'Q'
    jmp     mainMenuReturn

itemCheck:

    __seterrno  0
    lea     rdi, qword [rbp-32]     ; buf
    mov     rsi, 0                  ; null
    mov     rdx, 10                 ; base 10
    xor     rax, rax
    call    strtol

    mov     r12, rax                ; store return value
    call    geterrno                ; get libc errno
    cmp     rax, 0                  ; 0?
    je      itemCheck2              ; if 0: okay
    mov     rdi, 0                  ; null
    call    perror                  ; show error message from strtol
    jmp     menuItemLoop            ; re-display menu

itemCheck2:
    mov     rax, r12                ; get strtol return value

    cmp     rax, 0                  ; if entry == 0
    je      noSuchMenuItem          ; invalid entry
    jl      noSuchMenuItem          ; if < 0: invalid entry
    cmp     rax, r15                ; compare to # of items
    jg      noSuchMenuItem          ; if > num items: error

    ; something valid was selected
    jmp     mainMenuReturn

noSuchMenuItem:
    mov     rdi, invalidSelection   ; invalid selection
    xor     eax, eax
    call    printf
    jmp     mainMenuStart           ; re-display menu

mainMenuReturn:
    pop     r15
    pop     r12
    pop     rbx
    mov     rsp, rbp
    pop     rbp

    ret

; Menu option to create a new pad
global create_pad_menu
create_pad_menu:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 128

    ;   [rbp- 8] = file descriptor
    ;   [rbp-32] = char filename[24]
    ;   [rbp-56] = counter
    ;   [rbp-64] = char *page

    ; create a pad
    mov     rdi, msgCreatePad
    xor     rax, rax
    call    printf

    ; - Get agent number
cpmFileNameInput:

    lea     rax, [rbp-32]
    mov     rdi, rax
    call    get_agent_file          ; invoke method to get agent number

    lea     rdi, [rbp-32]           ; file name
    mov     rsi, O_CREAT | O_RDWR   ; file open options
    mov     rdx, S_IRUSR | S_IWUSR  ; file permissions
    call    openFile                ; invoke open file menu (outputs message on error)
    cmp     rax, 0                  ; check result of file open
    jl      createPadReturn         ; if < 0: error

    mov     qword [rbp-8], rax      ; store return

    ; output message
    mov     rdi, msgCreatingPad
    xor     rax, rax
    call    printf

    ; - Create random pad of p pages; n bytes per page
    ; for i = 0; i < pages; ++i
    mov     qword [rbp-56], 0   ; i = 0
createPadPageLoop:
    cmp     qword [rbp-56], 250
    jge     createPadPageLoopDone

    ; create page
    mov     rdi, PAD_PAGE_SIZE
    call    createPadPage
    mov     qword [rbp-64], rax     ; TODO: check return

    ; write page to file
    mov     rax, SYS_write
    mov     rdi, qword [rbp-8]
    mov     rsi, qword [rbp-64]
    mov     rdx, PAD_PAGE_SIZE
    syscall

    ; free page
    push    rax
    mov     rdi, qword [rbp-64]
    call    free
    pop     rax

    cmp     rax, 0                  ; write success?
    jge     createPadPageLoopNext
    ; write failed, display error
    cdq
    xor     eax, edx
    sub     eax, edx
    cdqe
    __seterrno  rax
    mov     rdi, msgPadWriteError
    call    perror
    jmp     createPadPageLoopDoneErr    ; break

    ; loop
createPadPageLoopNext:
    add     qword [rbp-56], 1
    jmp     createPadPageLoop
createPadPageLoopDone:

    mov     rdi, msgPadCreated          ; pad created
    lea     rsi, qword [rbp-32]
    xor     rax, rax
    call    printf

createPadPageLoopDoneErr:

    mov     rdi, qword [rbp-8]
    mov     rax, SYS_close              ; close file
    syscall

createPadReturn:
    mov     rsp, rbp
    pop     rbp
    ret

; Menu option to write a new message to an agent
global  create_message_menu
create_message_menu:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128

    ;   [rbp- 8] = file descriptor
    ;   [rbp-32] = char name[24]
    ;   [rbp-48] = tmp
    ;   [rbp-56] = counter
    ;   [rbp-64] = char *page
    ;   [rbp-72] = char *message
    ;   [rbp-80] = char *encrypted
    ;   [rbp-88] = int page#

    mov     qword [rbp-72], 0       ; message = null
    mov     rdi, PAD_PAGE_SIZE + 1
    call    malloc
    mov     qword [rbp-64], rax

    cmp     rax, 0
    jne     createMessagePrompt
    mov     rdi, msgMallocFailed
    xor     rax, rax
    call    printf
    jmp     createMessageReturn

createMessagePrompt:
    mov     rdi, msgWriteMessage
    xor     rax, rax
    call    printf

    ; get agent number
    lea     rax, [rbp-32]
    mov     rdi, rax
    call    get_agent_file

    ; open file for reading
    lea     rdi, [rbp-32]
    mov     rsi, O_RDWR
    xor     rdx, rdx
    call    openFile

    cmp     rax, 0
    jl      createMessageReturnFree

    mov     qword [rbp-8], rax      ; assign file handle

    ; find current page (read until c != '\0')
    mov     qword [rbp-56], 0
    mov     qword [rbp-88], 1       ; current page number

findCurrentPageLoop:
    ; zero out page buffer
    mov     rdi, qword [rbp-64]     ; page
    mov     rsi, 0                  ; \0
    mov     rdx, PAD_PAGE_SIZE + 1  ; length
    call    memset

    ;   read 1 page from file
    mov     rdi, qword [rbp-8]      ; fd
    mov     rax, qword [rbp-64]     ; buf
    mov     rsi, rax
    mov     rdx, PAD_PAGE_SIZE      ; length
    mov     rax, SYS_read
    syscall

    mov     [rbp-48], rax               ; save return value
    cmp     qword [rbp-48], 0
    jns     findCurrentPageCheckReadSize
    jmp     findCurrentPageLoopExit     ; exit loop
findCurrentPageCheckReadSize:
    cmp     qword [rbp-48], PAD_PAGE_SIZE - 1   ; check if bytes read < page size
    jg      findCurrentPageLoopNext
    mov     qword [rbp-48], 0           ; eof
    jmp     findCurrentPageLoopExit
findCurrentPageLoopNext:
    mov     rax, [rbp-64]                   ; *p = page
    cmp     byte [rax], 0                   ; compare first byte in buffer to NULL
    jne     findCurrentPageLoopExit         ; break if byte != NULL
    add     qword [rbp-56], PAD_PAGE_SIZE   ; advance pointer by PAD_PAGE_SIZE bytes
    add     qword [rbp-88], 1               ; current page += 1
    jmp     findCurrentPageLoop             ; loop
findCurrentPageLoopExit:

    ; check error
    mov     rax, qword [rbp-48]
    cmp     qword [rbp-48], 0
    jg      createMessageReadPadPage
    cmp     qword [rbp-48], 0
    je      createMessageReadPageEOF
    cmp     qword [rbp-48], PAD_PAGE_SIZE
    jb      createMessageReadPageEOF
    ; display read error message
    cdq
    xor     eax, edx
    sub     eax, edx
    cdqe
    __seterrno  rax
    mov     rdi, msgFileReadIOError
    call    perror
    jmp     createMessageReturnFree
createMessageReadPageEOF:
    ; display EOF error
    mov     rdi, msgFileReadEOFError
    xor     rax, rax
    call    printf
    jmp     createMessageReturnFree

    ; read PAD_PAGE_SIZE bytes
createMessageReadPadPage:
    ;   qword [rbp-64] is the page of bytes

    ; output page number message
    mov     rdi, msgAgentForPage
    lea     rsi, qword [rbp-32]
    mov     rdx, qword [rbp-88]
    xor     rax, rax
    call    printf

    ; get message from operator
    call    read_message_from_operator
    mov     qword [rbp-72], rax

    call    printNewline
    mov     rdi, msgInMessage
    mov     rsi, qword [rbp-72]
    xor     rax, rax
    call    printf

    mov     rdi, msgCipherKey
    mov     rsi, qword [rbp-64]
    xor     rax, rax
    call    printf

    ; encrypt message with pad
    mov     rdi, qword [rbp-72]
    mov     rsi, qword [rbp-64]
    call    encryptMessageWithPad
    mov     qword [rbp-80], rax
    ;       TODO: if rax == 0

    ; output formatted message
    mov     rdi, msgCiphertext
    xor     rax, rax
    call    printf
    fflush
    mov     rax, qword [rbp-80]
    mov     rdi, rax
    call    output_formatted_ciphertext
    ; free encrypted message
    mov     rax, qword [rbp-80]
    mov     rdi, rax
    call    free

    ; burn page (fill with null bytes)
    mov     rax, qword [rbp-88]
    sub     rax, 1
    xor     rdx, rdx
    mov     rdi, PAD_PAGE_SIZE
    imul    rdi

    mov     rdi, [rbp-8]    ; fd
    mov     rsi, rax        ; offset
    mov     rdx, SEEK_SET
    mov     rax, SYS_lseek
    syscall

    ;   TODO: check return
    mov     rdi, qword [rbp-64]
    mov     rsi, 0
    mov     rdx, PAD_PAGE_SIZE
    call    memset

    mov     rdi, qword [rbp-8]  ; fd
    mov     rsi, qword [rbp-64] ; buf
    mov     rdx, PAD_PAGE_SIZE
    mov     rax, SYS_write
    syscall

    mov     rdi, msgPageDestroyed
    mov     rsi, qword [rbp-88]
    add     rsi, 1
    xor     rax, rax
    call    printf

createMessageReturnFree:
    mov     rax, qword [rbp-64]     ; free page
    mov     rdi, rax
    call    free
    cmp     qword [rbp-72], 0
    je      createMessageReturn
    mov     rax, qword [rbp-72]     ; free message
    mov     rdi, rax
    call    free

createMessageReturn:
    mov     rsp, rbp
    pop     rbp
    ret

; *****************************************************************************
; Prompt operator for agent number and return file path
;   Prompt for agent number, validate input, and set file path in supplied
;   buffer
;
; Preconditions:
;   - rdi contains the address of a buffer to place a file path (max 16 bytes)
; Postconditions:
;   - supplied buffer contains a null terminate string of the agent file to use
;   - registers are not preserved
;
global  get_agent_file
get_agent_file:

    push    rbp
    mov     rbp, rsp
    sub     rsp, 24

    ;   [rbp-24] = file name buffer
    ;   [rbp-16] = temp[16]

    mov     qword [rbp-24], rdi   ; save buf

gafGetAgentNumber:
    ; prompt for agent number
    mov     rdi, promptAgentNum
    xor     rax, rax
    call    printf

    ; read input from user
    lea     rdi, [rbp-16]       ; address of temp buffer
    mov     rsi, 16             ; # of bytes to read, including newline
    mov     rdx, [stdin]        ; stdin
    call    fgets

    mov     rcx, 0  ; i = 0
    mov     rdx, 1  ; valid = 0
checkFileName:
    cmp     rcx, 16
    jae     checkFileNameTooLong
    movzx   rax, byte [rbp-16+rcx]

    cmp     rax, 10             ; end of input
    je      checkFileNameValid  ; newline

    cmp     rax, '0'
    jb      checkFileNameInvalid    ; if c < '0': invalid
    cmp     rax, '9'
    ja      checkFileNameInvalid    ; if c > '9': invalid

    jmp     checkFileNameNextByte

checkFileNameInvalid:
    mov     rdx, 0                  ; valid = 0

checkFileNameNextByte:
    inc     rcx
    jmp     checkFileName

checkFileNameTooLong:               ; input too long
    consumeStdin                    ; consume remainder of stdin
    mov     rdi, msgFileNameTooLong ; output error message
    xor     rax, rax
    call    printf
    jmp     gafGetAgentNumber

checkFileNameValid:

    cmp     rdx, 1
    je      checkFileNameDone
    mov     rdi, msgInvalidFileName
    xor     rax, rax
    call    printf
    jmp     gafGetAgentNumber

checkFileNameDone:
    ; overwrite trailing newline of file
    lea     rax, [rbp-16+rcx]
    mov     byte [rax], 0

    ; - format file name
    mov     rax, qword [rbp-24]
    mov     rdi, rax
    mov     rsi, fileNameFormat
    lea     rdx, [rbp-16]
    xor     rax, rax
    call    sprintf

    mov     rsp, rbp
    pop     rbp
    ret

global read_message_from_operator
read_message_from_operator:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48

    ; allocate buffer (PAD_PAGE_SIZE+2) (extra byte for \n + null byte)
    mov     rdi, PAD_PAGE_SIZE + 2
    call    malloc
    mov     qword [rbp-8], rax
    cmp     rax, 0
    jne     rmfoPromptMessage
    mov     rdi, msgMallocFailed
    xor     rax, rax
    call    printf
    mov     rax, 0
    jmp     rmfoReturn

rmfoPromptMessage:
    ; prompt for input message
    mov     rdi, msgPromptMessage
    xor     rax, rax
    call    printf

    ; read message
rmfoReadMessage:
    mov     rdi, qword [rbp-8]
    mov     rsi, 0
    mov     rdx, PAD_PAGE_SIZE + 2
    call    memset

    ;   read message
    mov     rax, qword [rbp-8]
    mov     rdi, rax
    mov     rsi, PAD_PAGE_SIZE + 2
    mov     rdx, [stdin]
    call    fgets

    ; check length
    ; if (str[PAD_PAGE_SIZE-1] != 0 && str[PAD_PAGE_SIZE-1] != '\n'): msg too long
    mov     rax, [rbp-8]
    add     rax, PAD_PAGE_SIZE
    movzx   eax, byte [rax]
    cmp     rax, 0
    je      rmfoLengthOkay
    cmp     rax, 10
    je      rmfoLengthOkay
    consumeStdin
    mov     rdi, msgErrMsgTooLong
    xor     rax, rax
    call    printf
    jmp     rmfoPromptMessage

rmfoLengthOkay:

    ; remove trailing newline from message (if present)
    mov     rcx, 0
rmfoRemovenewlineLoop:
    cmp     rcx, PAD_PAGE_SIZE + 1
    jge     rmfoRemoveNewlineLoopExit
    mov     rax, [rbp-8]
    add     rax, rcx
    movzx   rdx, byte [rax]
    cmp     rdx, 0
    je      rmfoRemoveNewlineLoopExit
    cmp     rdx, 10
    jne     rmfoRemovenewlineLoopNext
    mov     byte [rax], 0
    jmp     rmfoRemoveNewlineLoopExit
rmfoRemovenewlineLoopNext:
    add     rcx, 1
    jmp     rmfoRemovenewlineLoop
rmfoRemoveNewlineLoopExit:

    mov     rax, [rbp-8]        ; *ret = message

rmfoReturn:
    mov     rsp, rbp
    pop     rbp
    ret

global output_formatted_ciphertext
output_formatted_ciphertext:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32

    ;       [rbp- 8] = ciphertext
    ;       [rbp-16] = length
    ;       [rbp-24] = counter
    ;       [rbp-32] = outbuf

    mov     qword [rbp-8], rdi      ; tmp = buf

    ; get length
    mov     rax, qword [rbp-8]
    mov     rdi, rax
    call    strlen
    mov     qword [rbp-16], rax

    ; for i = 0; i < length; ++i
    mov     qword [rbp-24], 0
ofcLoopNext:
    mov     rax, qword [rbp-24]
    cmp     rax, qword [rbp-16]
    jg      ofcLoopEnd
    mov     rdi, STDOUT
    mov     rsi, qword [rbp-8]
    add     rsi, qword [rbp-24]
    mov     rdx, 1
    mov     rax, SYS_write
    syscall
    mov     rax, qword [rbp-24]
    add     rax, 1
    cqo
    mov     rcx, 5
    idiv    rcx
    mov     rax, rdx
    cmp     rax, 0
    jne     ofcLoopNextIter
    ;   output space
    mov     rdi, STDOUT
    mov     rsi, space
    mov     rdx, 1
    mov     rax, SYS_write
    syscall
ofcLoopNextIter:
    add     qword [rbp-24], 1
    jmp     ofcLoopNext
ofcLoopEnd:

    call    printNewline

    mov     rsp, rbp
    pop     rbp
    ret


; *****************************************************************************
; Begin Program
global _start
_start:

    ; Set up menu items
    mov     rax, createPadPrompt                ; First menu item - Create pad
    mov     qword [menuEntries+0x00], rax
    mov     rax, writeMessagePrompt             ; Second menu item - Write a message
    mov     qword [menuEntries+0x08], rax
    mov     qword [menuEntries+0x10], 0         ; Terminate menu

showMainMenu:
    ; Display main menu
    call    main_menu

    cmp     rax, -1     ; compare rax to -1 (quit code)
    je      _exit       ; jump if equal

    cmp     rax, 1      ; item 1 selected
    jne     .c2
    call    create_pad_menu
    jmp     _endMenu

.c2:
    cmp     rax, 2      ; item 2 selected
    jne     .c3
    call    create_message_menu
    jmp     _endMenu

.c3:
    ; encode a message
    ; - Get agent number
    ; - Determine next page
    ; - Get message
    ; - Get page from pad
    ; - Encode message with pad
    ; - Destroy page

    mov     rdi, msgNotSecretPass
    mov     esi, dword [passwordLength]
    lea     rdx, [secretkey]
	call    pbkdf2_test

	cmp     rax, 1
	je      pbkdf2_success

    mov     rdi, msgFail
    xor     eax, eax
    call    printf
    jmp     _exit

pbkdf2_success:
    mov     rax, qword [secretkey]
    mov     rdi, msgYourKeyMessage
    mov     rsi, rax
    xor     eax, eax
    call    printf

_endMenu:
    call    printNewline
    jmp     showMainMenu

_exit:
    mov     rax, SYS_exit   ; exit()
    mov     rdi, 0          ; return value
    syscall
