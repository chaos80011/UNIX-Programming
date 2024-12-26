mov eax, [0x600000]
mov ebx, [0x600004]
mul ebx
neg eax
add eax, [0x600008]
done: