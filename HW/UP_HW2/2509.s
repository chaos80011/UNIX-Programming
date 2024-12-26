mov ecx, 0x600000
mov edx, 0x600010

L1:
    cmp ecx, 0x60000f
    jge end
    mov bl, [ecx]
    cmp bl, 'a'
    jge no_convert
    add bl, 0x20
    jmp no_convert

no_convert:
    mov [edx], bl
    inc ecx
    inc edx
    jmp L1

end:

done: