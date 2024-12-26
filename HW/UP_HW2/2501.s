mov eax, [0x600000]
mov ebx, [0x600004]
mov ecx, [0x600008]
xor edx, edx
add edx, eax
add edx, ebx
sub edx, ecx
mov [0x60000c], edx
done: