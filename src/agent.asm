; Macros
%include "definitions.mac"

%macro  __perror    1
    ; calculate -errno
    cdq                 ; sign extend
    xor     eax, edx    ; flip bits
    sub     eax, edx    ; subtract high from low
    cdqe                ; rax = sign extend eax
    __seterrno  rax     ; set errno for perror
    mov     rdi, %1     ; message
    call    perror
%endmacro

; *****************************************************************************
; Data Section
section 	.data

extern  seterrno

; libc function references
extern  stdin
extern  getchar     ;   int getchar()
extern  fflush      ;   fflush(FILE *stream)
extern  fgets       ;   char * fgets (char *s, int count, FILE *stream)
extern  printf      ;   int printf(const char *format, ...)
extern  free        ;   void free(void *ptr)
extern  memset      ;   void *memset(void *s, int c, size_t n)
extern  perror      ;   void perror (const char *message)

; fp_lib function references
extern  openFile                ; safe file open with error handling
extern  printNewline            ; prints a newline to console
extern  createPadPage           ; create a one-time pad to burn a page
extern  decryptMessageWithPad   ; decrypting a message
extern  _strtol                 ; string to number

; Variable Definitions

; Main program variables
msgWelcomeMessage   db  "Hello agent. Novus ordo seclorum.",10,10,0
msgPromptNextPage   db  "Enter your next page number to decode a message: ",0
msgEnterMessage     db  "Enter message: ",0
msgDecryptedResult  db  "Your message is: %s",10,0
msgBurnPagePrompt   db  "Would you like to burn the page? [Y/N]: ",0
msgPageBurned       db  "Page destroyed. Your next page is %ld. Be vigilant.",10,10,0

agentFileName       db  "./agent.txt",0

; Generic message variables
msgStatFailed       db  "stat failed",0
msgEmptyFile        db  "Error: File is empty.",10,0
msgInvalidFileSize  db  "Error: Invalid file size; does not align with page size",10,0
msgInvalidPageNum   db  "Invalid page number. Must be in range 1-9999.",10,0
msgInvalidPageOff   db  "Invalid page number. Exceeds file range.",10,0
msgSeekFailure      db  "Seek to page offset failed",0
msgReadFailure      db  "Failed to read page",0
msgReadIncomplete   db  "Failed to read page; expected %ld bytes, got %ld.",10,0
msgDecryptionFailed db  "Decryption failed!",10,0
msgInvalidSelection db  "Invalid selection.",10,0
msgCreatePageFailed db  "Failed to create random pad; page cannot be destroyed.",10,0
msgSeekDestroyFail  db  "Seek to page offset failed; page cannot be destroyed.",10,0
msgDestroyFailed    db  "Failed to destroy page; write failed",0
msgDestroyWriteFail db  "Failed to destroy page; could not write complete buffer to file",10,0

; *****************************************************************************
; BSS Section
section		.bss

;
; Variable Declarations
;
fd          resq    1                       ; file descriptor for reading/writing pad file
filesize    resq    1                       ; size of the pad file in bytes
statbuf     resb    144                     ; buffer for file info from fstat()
pagenumbuf  resb    8                       ; buffer to read input for page number
pagenum     resq    1                       ; current page number as supplied by user
pageoffset  resq    8                       ; offset in bytes of current page in file
page        resb    PAD_PAGE_SIZE + 1       ; key (pad) - read from file
ciphertext  resb    PAD_PAGE_SIZE * 2 + 1   ; ciphertext as supplied by user
secret      resq    1                       ; pointer to decrypted ciphertext

;
; Code Section
;
section		.text

; *****************************************************************************
; Begin Program
global _start
_start:

    ; Show greeting
    mov     rdi, msgWelcomeMessage
    xor     rax, rax
    call    printf

    ; Load pad (open file, validate size)
    mov     rdi, agentFileName      ; string containing path of file to open
    mov     rsi, O_RDWR             ; SYS_open flags
    call    openFile                ; outputs error message on failure
    mov     qword [fd], rax         ; save return value
    cmp     rax, 0                  ; compare return to 0
    jge     determineFileSize       ; if >= 0: okay
    mov     rdi, 2                  ; exit code
    jmp     _errexit                ; exit

determineFileSize:
    ; Determine file size using fstat
    mov     rdi, [fd]               ; file descriptor to get info for
    mov     rsi, statbuf            ; pointer to buffer for file info
    mov     rax, SYS_fstat
    syscall                         ; call fstat()
    cmp     rax, 0                  ; check return, 0 = success
    je      determineFileSizeOk
    __perror    msgStatFailed       ; display error
    mov     rdi, 2                  ; exit code
    jmp     _errexit                ; exit
determineFileSizeOk:                ; stat succeeded
    mov     rdi, statbuf
    add     rdi, 48                 ; statbuf.st_size
    mov     rax, qword [rdi]        ; get filesize
    mov     qword [filesize], rax   ; store filesize

checkFileSize:
    ; Ensure the file size is > 0
    cmp     qword [filesize], 0     ; compare to 0
    ja      checkFileSizeMultiple   ; jump if above 0
    mov     rdi, msgEmptyFile       ; file is empty
    xor     rax, rax
    call    printf                  ; show error
    mov     rdi, 2
    jmp     _errexit                ; exit
checkFileSizeMultiple:
    ; Ensure file size is a multiple of pad page size
    mov     rax, qword [filesize]   ; filesize
    cqo                             ; sign extend for division
    mov     rdi, PAD_PAGE_SIZE      ; divisor
    idiv    rdi                     ; filesize / PAD_PAGE_SIZE
    cmp     rdx, 0                  ; if filesize % PAD_PAGE_SIZE == 0: okay
    je      promptForPageNumber
    mov     rdi, msgInvalidFileSize ; file size invalid
    xor     rax, rax
    call    printf                  ; show error
    mov     rdi, 2
    jmp     _errexit                ; exit

promptForPageNumber:
    ; Prompt for page number
    mov     rdi, msgPromptNextPage
    xor     rax, rax
    call    printf

    ; Read and validate page number (up to 4 digits)
getPageFromAgent:
    ; zero memory
    mov     rdi, pagenumbuf     ; buffer for holding input
    mov     rsi, 0
    mov     rdx, 8
    call    memset
    ; read input
    mov     rdi, pagenumbuf     ; read 5 bytes (plus null) of input into buffer
    mov     rsi, 6
    mov     rdx, [stdin]
    call    fgets
    cmp     rax, 0              ; read error or EOF?
    je      promptForPageNumber ; re-prompt

    ; empty input?
    cmp     byte [pagenumbuf], 10   ; if buf[0] == '\n'
    je      promptForPageNumber     ; re-prompt

    ; check length
    ; if (buf[4] != 0 && str[4] != '\n'): msg too long
    lea     rbx, [pagenumbuf+4]     ; check end of buffer
    movzx   rax, byte [rbx]
    cmp     rax, 0                  ; if null: okay
    je      getPageLengthOkay
    cmp     rax, 10                 ; if '\n': okay
    je      getPageLengthOkay
    consumeStdin                    ; input too long, consume stdin
    mov     rdi, msgInvalidPageNum  ; invalid page number
    xor     rax, rax
    call    printf
    jmp     promptForPageNumber     ; re-prompt
getPageLengthOkay:

    ; Validate digits (page can only contain [0-9]
    mov     rsi, pagenumbuf
    mov     rcx, 0                          ; i = 0
getPageValidateDigitsLoopIter:
    cmp     rcx, 4
    jge     getPageValidateDigitsLoopExit   ; if i >= 4: break
    lea     rax, byte [pagenumbuf+rcx]      ; c = buf[i]
    movzx   rax, byte [rax]
    cmp     rax, 10                         ; if c == '\n': break
    je      getPageValidateDigitsLoopExit
    cmp     rax, '0'                        ; if c < '0': invalid
    jb      pageNumberInvalid
    cmp     rax, '9'                        ; if c > '9': invalid
    ja      pageNumberInvalid
    add     rcx, 1                          ; i += 1
    jmp     getPageValidateDigitsLoopIter   ; loop
pageNumberInvalid:
    mov     rdi, msgInvalidPageNum          ; page number invalid
    xor     rax, rax
    call    printf
    jmp     promptForPageNumber             ; re-prompt
getPageValidateDigitsLoopExit:

    ; convert string to int
    mov     rdi, pagenumbuf
    call    _strtol
    mov     [pagenum], rax                  ; store page number

    cmp     qword [pagenum], 0
    jg      calculatePageOffset             ; if page > 0: okay
    mov     rdi, msgInvalidPageNum          ; page number invalid
    xor     rax, rax
    call    printf
    jmp     promptForPageNumber             ; re-prompt

calculatePageOffset:
    ; calculate page offset in file
    sub     rax, 1                          ; page - 1
    cqo                                     ; sign extend
    mov     rdi, PAD_PAGE_SIZE              ; set multiplier
    imul    rdi                             ; offset = (page - 1) * PAD_PAGE_SIZE
    mov     qword [pageoffset], rax         ; rax = offset in bytes of next page

    ; if filesize - PAD_PAGE_SIZE > offset: invalid page
    mov     rdi, [filesize]                 ; get filesize
    sub     rdi, PAD_PAGE_SIZE              ; subtract page size
    cmp     rax, rdi
    jle     seekToPageOffset                ; if result <= offset: error
    mov     rdi, msgInvalidPageOff
    xor     rax, rax
    call    printf
    jmp     promptForPageNumber             ; re-prompt
seekToPageOffset:
    ; read page bytes from file starting at offset
    mov     rdi, [fd]                       ; file descriptor
    mov     rsi, rax                        ; offset
    mov     rdx, SEEK_SET                   ; set cursor to offset
    mov     rax, SYS_lseek                  ; lseek
    syscall                                 ; syscall
    cmp     rax, 0                          ; check success
    jge     readPageFromFile                ; if result < 0: error
    __perror msgSeekFailure
    mov     rdi, 2
    jmp     _errexit

readPageFromFile:
    ; read a page of bytes from file. file pointer is positioned at start of page
    mov     rdi, [fd]               ; file descriptor
    mov     rsi, page               ; buffer for read
    mov     rdx, PAD_PAGE_SIZE      ; number of bytes to read
    mov     rax, SYS_read
    syscall
    cmp     rax, 0                  ; check error
    jge     readPageFromFileSuccess ; if res >= 0: success
    __perror msgReadFailure
    mov     rdi, 2
    jmp     _errexit

readPageFromFileSuccess:
    ; ensure bytes read == PAD_PAGE_SIZE
    cmp     rax, PAD_PAGE_SIZE
    je      promptForCiphertext     ; if bytes read == PAD_PAGE_SIZE: success
    mov     rdi, msgReadIncomplete  ; incomplete read
    xor     rax, rax
    call    printf
    mov     rdi, 2
    jmp     _errexit                ; exit

promptForCiphertext:
    ; add trailing null byte to page
    lea     rdi, [page+PAD_PAGE_SIZE]
    mov     byte [rdi], 0               ; set null byte on page
    ; zero ciphertext buffer
    mov     rdi, ciphertext             ; buffer for holding ciphertext
    mov     rsi, 0
    mov     rdx, PAD_PAGE_SIZE * 2 + 1  ; sizeof buffer
    call    memset

    ; Prompt for ciphertext
    mov     rdi, msgEnterMessage
    xor     rax, rax
    call    printf
    fflush

    ; Read input (up to PAD_PAGE_SIZE * 2 bytes, ignoring spaces)
    ; Note: there is no validation of valid page table characters
    mov     rdi, 0                  ; buffer destination index
    mov     rcx, 0                  ; character counter
readCipherTextLoopIter:
    push    rcx                     ; store counter
    mov     rdi, STDIN              ; read from standard input
    lea     rsi, byte [pagenumbuf]  ; temporary
    mov     rdx, 1                  ; read 1 byte
    mov     rax, SYS_read
    syscall
    pop     rcx                     ; restore counter

    movzx   rax, byte [pagenumbuf]  ; check char from temp buffer
    cmp     rax, 10
    je      readCiperTextLoopExit   ; if '\n': break
    cmp     rax, ' '
    je      readCipherTextLoopIter  ; if c == ' ': continue
    cmp     rcx, PAD_PAGE_SIZE * 2
    ja      readCipherTextLoopIter  ; if p > PAD_PAGE_SIZE * 2: continue
    lea     rdi, [ciphertext+rcx]
    mov     byte [rdi], al          ; ciphertext[p] = c
    add     rcx, 1                  ; increment counter
    jmp     readCipherTextLoopIter
readCiperTextLoopExit:

    ; Debug - print stripped input from user
;    mov     rdi, ciphertext
;    xor     rax, rax
;    call    printf
;    call    printNewline

    ; Decrypt message
    mov     rdi, ciphertext         ; ciphertext from user
    mov     rsi, page               ; one-time pad page from file
    call    decryptMessageWithPad   ; call decryption
    mov     qword [secret], rax     ; store pointer to result

    cmp     rax, 0                  ; decrypt fail?
    jne     outputDecryptedMessage
    mov     rdi, msgDecryptionFailed    ; decryption failed
    xor     rax, rax
    call    printf
    mov     rdi, 2
    jmp     _errexit                    ; exit

outputDecryptedMessage:
    mov     rdi, msgDecryptedResult     ; decrypted result message
    mov     rsi, qword [secret]         ; plaintext
    xor     rax, rax
    call    printf
    fflush

    ; free allocated memory for secret
    mov     rdi, [secret]
    call    free

promptBurnPage:
    ; Prompt to burn page
    mov     rdi, msgBurnPagePrompt      ; burn page?
    xor     rax, rax
    call    printf
    fflush

    ; If yes, burn page (random bytes, not 0)
    ; read 1 byte of input from STDIN (Y/N), consume any remaining input
    mov     rdi, STDIN
    mov     rsi, pagenumbuf     ; temporary
    mov     rdx, 1
    mov     rax, SYS_read
    syscall

    movzx   rax, byte [pagenumbuf]      ; input
    cmp     rax, 10
    je      promptBurnPage
    consumeStdin                        ; consume remainder of input
    cmp     rax, 'Y'                    ; c == 'Y'?
    je      destroyPage                 ; destroy
    cmp     rax, 'y'                    ; c == 'y'?
    je      destroyPage                 ; destroy
    cmp     rax, 'n'                    ; c == 'n'?
    je      promptForCiphertext         ; try again
    cmp     rax, 'N'                    ; c == 'n'?
    je      promptForCiphertext         ; try again
    mov     rdi, msgInvalidSelection    ; else: invalid entry
    xor     rax, rax
    call    printf
    jmp     promptBurnPage              ; re-prompt

destroyPage:
    ; Destroy page
    mov     rdi, PAD_PAGE_SIZE          ; # of bytes for creating a new pad to burn page
    call    createPadPage               ; invoke createPadPage
    mov     qword [secret], rax         ; *secret = page
    cmp     rax, 0                      ; check failure
    jne     destroyPageSeek             ; no error
    ; output error
    mov     rdi, msgCreatePageFailed    ; failed to create pad
    xor     rax, rax
    call    printf
    mov     rdi, 2
    jmp     _errexit                    ; exit

destroyPageSeek:
    ; Overwrite bytes in file with burned page
    ; Seek to offset to overwrite
    mov     rdi, [fd]               ; file descriptor
    mov     rsi, [pageoffset]       ; offset in file
    mov     rdx, SEEK_SET           ; set cursor
    mov     rax, SYS_lseek
    syscall                         ; invoke seek
    cmp     rax, 0                  ; seek success?
    jge     destroyPageWrite        ; no error
    __perror msgSeekDestroyFail     ; seek failed message
    mov     rdi, 2
    jmp     _errexit                ; exit

destroyPageWrite:
    ; Write random bytes from new page to file
    mov     rdi, [fd]               ; file descriptor
    mov     rsi, [secret]           ; random pad
    mov     rdx, PAD_PAGE_SIZE      ; number of bytes to write
    mov     rax, SYS_write
    syscall
    cmp     rax, 0                  ; check return value
    jge     destroyPageWriteCheckBytesWritten   ; no error
    __perror msgDestroyFailed       ; failed to destroy page
    call    perror
    mov     rdi, 2
    jmp     _errexit                ; exit

destroyPageWriteCheckBytesWritten:
    ; Ensure number of bytes written == PAD_PAGE_SIZE
    cmp     rax, PAD_PAGE_SIZE          ; if written == PAD_PAGE_SIZE
    je      destroyPageWriteSuccess     ; no error
    mov     rdi, msgDestroyWriteFail    ; failed to destroy page
    xor     rax, rax
    call    printf
    mov     rdi, 2
    jmp     _errexit                    ; exit

destroyPageWriteSuccess:
    ; Output closing msesage
    call    printNewline
    mov     rdi, msgPageBurned          ; page destroyed. show outro
    mov     rsi, [pagenum]              ; current page number
    add     rsi, 1                      ; add one to current page
    xor     rax, rax
    call    printf
    fflush
    jmp     _exit

_exit:      mov     rdi, 0          ; return value
_errexit:   mov     rax, SYS_exit   ; exit()
            syscall
