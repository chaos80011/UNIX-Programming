mov rdi, 24

r:
    cmp rdi, 0
    je zero
    cmp rdi, 1
    je one

    dec rdi
    push rdi
    call r
    pop rdi
    mov rcx, 2
    mul rcx
    mov rcx, rax

    dec rdi
    push rdi
    call r
    pop rdi
    mov ebx, 3
    mul rbx

    add rax, rcx

zero:
    mov rax, 0
    ret

one: 
    mov rax, 1
    ret