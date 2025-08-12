; Test Snippet: Demonstrating nested pointer patterns
; This code section demonstrates multiple levels of pointers and potential aliasing cases

section .data
    ; Data for pointer tests
    ptr1 dq val1        ; level 1 pointer
    ptr2 dq ptr1        ; level 2 pointer
    alias dq ptr1       ; alias of level 1 pointer

section .text
    global _start

_start:
    ; Load first level pointer
    mov rax, [ptr1]
    ; Load second level pointer
    mov rbx, [ptr2]
    ; Alias usage
    mov rcx, [alias]

    ; Perform pointer arithmetic
    add rax, 4
    sub rbx, 2

    ; Multiple dereference levels
    mov rdx, [rax]
    mov rsi, [rbx]

    ; Use the alias again
    mov rdi, [rcx]

    ; Exit
    mov eax, 60        ; syscall: exit
    xor edi, edi       ; status: 0
    syscall

segment .bss
val1:
    resb 8

