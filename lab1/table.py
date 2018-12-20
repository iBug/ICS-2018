def move(x):
    n = 0
    while x and x % 2 == 0:
        n += 1
        x >>= 1
    return x, n

l = [move(x) for x in range(0, 0x8000, 2)]


with open("table.txt", "w") as f:
    for a, b in l:
        print(".FILL {}".format(a), file=f)
        print(".FILL {}".format(b), file=f)
