xor ebx, ebx
mov eax, [0x600000]
shl eax, 4
add ebx, eax
mov eax, [0x600000]
shl eax, 3
add ebx, eax
mov eax, [0x600000]
shl eax, 1
add ebx, eax
mov [0x600004], ebx
done: