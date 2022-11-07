from pwn import *

if not args.LOCAL:
    p = remote("pwn.chall.pwnoh.io", 13380)
else:
    p = process("python3 maze.py", shell=True)

flagx, flagy = (int(x) for x in p.recvline().decode().split())
print(flagx, flagy)

frog_warnings = ["ribbit", "giggle", "chirp"]
nebula_warnings = ["light", "dust", "dense"]
warningtodist = {x: i for i, x in enumerate(frog_warnings)} | {
    x: i for i, x in enumerate(nebula_warnings)
}

print(warningtodist)
map = {}
pos = 0, 2034 - 1
dirdxdy = {"a": [0, -1], "w": [-1, 0], "s": [1, 0], "d": [0, 1]}
map[pos] = 0
while True:

    print(map)
    dir = input().strip()
    dx, dy = dirdxdy[dir]
    newpos = pos[0] + dx, pos[1] + dy
    if map[pos] == 1 and newpos in map:
        print("no")
        continue
    pos = newpos
    p.sendline(dir.encode())
    p.recvline()
    warning = p.recv(timeout=0.5).decode().split("\n")
    dist = min((warningtodist[w] for w in warning if w), default=0)
    map[pos] = dist
