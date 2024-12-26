mov al, [0x600000]
cmp al, 0x61
jl end
sub al, 0x20
jmp end

end:
    mov [0x600001], al

done: