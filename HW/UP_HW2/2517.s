mov R8, 1
mov R9, -1
cmp eax, 0
jge L1
mov [0x600000], R9
jmp Var2

L1:
    mov [0x600000], R8
    jmp Var2

Var2:
    cmp ebx, 0
    jge L2
    mov [0x600004], R9
    jmp Var3

L2:
    mov [0x600004], R8
    jmp Var3

Var3:
    cmp ecx, 0
    jge L3
    mov [0x600008], R9
    jmp Var4

L3:
    mov [0x600008], R8
    jmp Var4

Var4:
    cmp edx, 0
    jge L4
    mov [0x60000c], R9
    jmp end

L4:
    mov [0x60000c], R8

end:

done: