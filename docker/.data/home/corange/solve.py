#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
from pwn import *
import threading

def identify_numbers_and_symbols(input_list):
    digit_patterns = {
        '1': [
            " ─┐  ",
            "  │  ",
            "  │  ",
            "  │  ",
            " ─┴─ "
        ],
        '2': [
            "┌───┐",
            "    │",
            "┌───┘",
            "│    ",
            "└───┘"
        ],
        '3': [
            "┌───┐",
            "    │",
            " ───┤",
            "    │",
            "└───┘"
        ],
        '4': [
            "│   │",
            "│   │",
            "└───┤",
            "    │",
            "    │"
        ],
        '5': [
            "┌────",
            "│    ",
            "└───┐",
            "    │",
            "└───┘"
        ],
        '6': [
            "┌───┐",
            "│    ",
            "├───┐",
            "│   │",
            "└───┘"
        ],
        '7': [
            "┌───┐",
            "│   │",
            "    │",
            "    │",
            "    │"
        ],
        '8': [
            "┌───┐",
            "│   │",
            "├───┤",
            "│   │",
            "└───┘"
        ],
        '9': [
            "┌───┐",
            "│   │",
            "└───┤",
            "    │",
            "└───┘"
        ],
        '0': [
            "┌───┐",
            "│   │",
            "│   │",
            "│   │",
            "└───┘"
        ],
        '+': [
            "     ",
            "  │  ",
            "──┼──",
            "  │  ",
            "     "
        ],
        '-': [
            "     ",
            "     ",
            "─────",
            "     ",
            "     "
        ],
        '*': [
            "     ",
            " ╲ ╱ ",
            "  ╳  ",
            " ╱ ╲ ",
            "     "
        ],
        '//': [
            "     ",
            "  •  ",
            "─────",
            "  •  ",
            "     "
        ]
    }

    # 將列表轉置，使每個數字或符號的垂直列成為一個元素

    small_expression = ""
    start = 1
    end = 6

    for i in range(7):
        extracted_substrings = [s[start:end] for s in input_list]
        matching_pattern = None
        for key, pattern in digit_patterns.items():
            if extracted_substrings == pattern:
                matching_pattern = key
                break 
        
        small_expression += matching_pattern

        start += 7
        end += 7

    return small_expression

def handle_interactive_output(r):
    extra_info = None
    for i in range(4):
        extra_info = r.recvline().strip().decode()
        print(extra_info)
    number_of_problem = int(extra_info.split()[3])
    print(number_of_problem)



def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

if __name__ == "__main__":
    r = remote("up.zoolab.org", 10681)
    # if len(sys.argv) == 2:
    #     r = remote('localhost', int(sys.argv[1]))
    # elif len(sys.argv) == 3:
    #     r = remote(sys.argv[2], int(sys.argv[1]))
    # else:
    #     r = process('./pow.py')
    solve_pow(r);


    extra_info = None
    for i in range(4):
        extra_info = r.recvline().strip().decode()
        print(extra_info)
    number_of_problem = int(extra_info.split()[3])
    r.recvline()

    for i in range(number_of_problem):
        hash_info = r.recvuntil(b'= ?').strip().decode()
        print(hash_info)
        problem = base64.b64decode(hash_info.split()[2]).decode('utf-8')
        print(problem)
        print(len(problem))
        big_expression = [
            f"{problem[0:49]}",
            f"{problem[50:99]}",
            f"{problem[100:149]}",
            f"{problem[150:199]}",
            f"{problem[200:249]}"
        ]
        small_expression = identify_numbers_and_symbols(big_expression)
        print(small_expression)
        answer = eval(small_expression)
        print(answer)
        r.sendline(str(answer).encode())
    

    r.interactive()
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
