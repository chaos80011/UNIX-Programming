cmp ch, 0x61 ; 'a'
jl L1
cmp ch, 0x7A ; 'z'
jg end
sub ch, 0x20
jmp end


L1:
    cmp ch, 0x41 ; 'A'
    jl end
    cmp ch, 0x5A ; 'Z'
    jg end
    add ch, 0x20

end:

done: