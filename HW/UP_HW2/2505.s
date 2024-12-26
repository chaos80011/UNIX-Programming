mov ecx, 15
mov edx, 0x600000

L1:
    mov bx, ax
    shr bx, cl
    and bx, 1
    add bl, '0'
    mov [edx], bl
    inc edx
    loop L1

mov bx, ax
shr bx, cl
and bx, 1
add bl, '0'
mov [edx], bl

done: