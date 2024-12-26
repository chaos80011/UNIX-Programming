from pwn import *

def python_list_to_c_array(input_list):
    c_array_str = "{"
    for i in range(len(input_list)):
        if i != 0:
            c_array_str += ", "
        c_array_str += str(input_list[i])
    c_array_str += "}"
    return c_array_str

elf = ELF('./maze')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
python_list = []
for s in [ f"move_{i}" for i in range(1200)]:
   if s in elf.got:
      python_list.append(hex(elf.got[s]))
c_array = python_list_to_c_array(python_list)
with open('got.txt', 'w') as f:
   f.write(str(c_array))

