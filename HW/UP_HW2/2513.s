mov eax, [0x600000]
mov ebx, -5
imul ebx
mov edi, eax

mov eax, [0x600004]
neg eax
cdq
mov ecx, [0x600008]
idiv ecx
mov ecx, edx

mov eax, edi
cdq
idiv ecx
mov [0x60000c], eax
done: