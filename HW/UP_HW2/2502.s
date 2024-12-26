mov ecx, 9
jmp outer_loop

outer_loop:
	cmp ecx, 0
	jle end
    mov ebx, 0
	jmp inner_loop

inner_loop:
    mov eax, [0x600000 + ebx * 4]
	mov edx, [0x600000 + ebx * 4 + 4]
    cmp eax, edx
    jle no_swap
    mov [0x600000 + ebx * 4], edx
	mov [0x600000 + ebx * 4 + 4], eax
	jmp no_swap

no_swap:
    inc ebx
    cmp ebx, ecx
    jl inner_loop
	dec ecx
    jmp outer_loop

end:

done: