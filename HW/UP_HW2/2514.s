mov eax, [0x600000]
imul dword ptr [0x600004]
neg eax

mov ecx, [0x600008]
sub ecx, ebx
cdq
idiv ecx
mov [0x600008], eax

done: