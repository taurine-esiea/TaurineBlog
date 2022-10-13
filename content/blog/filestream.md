---
createdAt: 2022-08-19
title: "Linux file stream internals for fun and profit"
description: "File streams are now a very common attack surface, here is a high level introduction that should make you understand the design of known attacks beyond the code reading for a particular function."
type: 'Projects'
tags: ["pwn"]
---

# Linux file stream internals for fun and profit

# Introduction

File streams are now a very common attack surface, here is a high level introduction that should make you understand the design of known attacks beyond the code reading for a particular function. I already talked about FSOP [here](../catastrophe/#fsop-on-stdout-to-leak-environ). This article reviews [glibc 2.36](https://elixir.bootlin.com/glibc/glibc-2.36/source). Most of this article comes from [this](https://ray-cp.github.io/archivers/IO_FILE_arbitrary_read_write) awesome series of articles about the `_IO_FILE` strcuture.

# Global design

As said in my previous writeup:
> Basically on linux “everything is a file” from the character device the any stream (error, input, output, opened file) we can interact with a resource by just by opening it and getting a file descriptor on it, right ? This way each file descripor has an associated structure called FILE you may have used if you have already done some stuff with files on linux.

The `struct _IO_FILE` is defined as follows:
```c
/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

Before starting to describe each field of the structure, you have to understand that according to behaviour of the function that uses a file stream, only a small part of the `_IO_FILE` structure is used. For example if the file stream is byte oriented, `_IO_wide_data` related operations are not used.

Let's review the fields of the structure:
- `_flags`: High-order word is `_IO_MAGIC`, rest is flags.
- `_IO_read_ptr` address of input within the input buffer that has been already used.
- `_IO_read_end` end address of the input buffer.
- `_IO_read_base` base address of the input buffer.
- `_IO_write_base` base address of the ouput buffer.
- `_IO_write_ptr` points to the character that hasn’t been printed yet.
- `_IO_write_end` end address of the output buffer.
- `_IO_buf_base` base address for both input and output buffer.
- `_IO_buf_end` end address for both input and output buffer.
- `_chain` stands for the single linked list that links of all file streams.
- `_fileno` stands for the file descriptor associated to the file.
- `_vtable_offset` stands for the offset of the vtable we have to use.
- `_offset` stands for the current offset within the file.

# Common functions

- `_IO_setb (FILE *f, char *base, char *end, int do_user_buf)`: Initializes the base buffer. Here is its implementation:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/genops.c#L328

void
_IO_setb (FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
```

`_IO_USER_BUF`: Don't deallocate buffer on close.

- `_IO_setg(fp, base, current, end)`: Initializes read pointers. Here is its code:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/libioP.h#L520

#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
	(fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
```

# fopen

Let's review the opening process of a file and how the `_IO_FILE` structure is intitialized. `fopen` is implemented in `libio/iofopen.c`:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/iofopen.c#L83
FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}

strong_alias (_IO_new_fopen, __new_fopen)
versioned_symbol (libc, _IO_new_fopen, _IO_fopen, GLIBC_2_1);
versioned_symbol (libc, __new_fopen, fopen, GLIBC_2_1);

# if !defined O_LARGEFILE || O_LARGEFILE == 0
weak_alias (_IO_new_fopen, _IO_fopen64)
weak_alias (_IO_new_fopen, fopen64)
# endif
```

Then it calls `__fopen_internal`:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/iofopen.c#L56
FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_new_file_init_internal (&new_f->fp);
  if (_IO_file_fopen ((FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```

First, a `struct locked_FILE` is allocated on the heap. `_IO_no_init` -- and `_IO_old_init` within it -- null out the structure:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/genops.c#L561
void
_IO_no_init (FILE *fp, int flags, int orientation,
	     struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
{
  _IO_old_init (fp, flags);
  fp->_mode = orientation;
  if (orientation >= 0)
    {
      fp->_wide_data = wd;
      fp->_wide_data->_IO_buf_base = NULL;
      fp->_wide_data->_IO_buf_end = NULL;
      fp->_wide_data->_IO_read_base = NULL;
      fp->_wide_data->_IO_read_ptr = NULL;
      fp->_wide_data->_IO_read_end = NULL;
      fp->_wide_data->_IO_write_base = NULL;
      fp->_wide_data->_IO_write_ptr = NULL;
      fp->_wide_data->_IO_write_end = NULL;
      fp->_wide_data->_IO_save_base = NULL;
      fp->_wide_data->_IO_backup_base = NULL;
      fp->_wide_data->_IO_save_end = NULL;

      fp->_wide_data->_wide_vtable = jmp;
    }
  else
    /* Cause predictable crash when a wide function is called on a byte
       stream.  */
    fp->_wide_data = (struct _IO_wide_data *) -1L;
  fp->_freeres_list = NULL;
}

// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/genops.c#L530

void
_IO_old_init (FILE *fp, int flags)
{
  fp->_flags = _IO_MAGIC|flags;
  fp->_flags2 = 0;
  if (stdio_needs_locking)
    fp->_flags2 |= _IO_FLAGS2_NEED_LOCK;
  fp->_IO_buf_base = NULL;
  fp->_IO_buf_end = NULL;
  fp->_IO_read_base = NULL;
  fp->_IO_read_ptr = NULL;
  fp->_IO_read_end = NULL;
  fp->_IO_write_base = NULL;
  fp->_IO_write_ptr = NULL;
  fp->_IO_write_end = NULL;
  fp->_chain = NULL; /* Not necessary. */

  fp->_IO_save_base = NULL;
  fp->_IO_backup_base = NULL;
  fp->_IO_save_end = NULL;
  fp->_markers = NULL;
  fp->_cur_column = 0;
#if _IO_JUMPS_OFFSET
  fp->_vtable_offset = 0;
#endif
#ifdef _IO_MTSAFE_IO
  if (fp->_lock != NULL)
    _IO_lock_init (*fp->_lock);
#endif
}
```

Then it initializes the vtable field field to `&_IO_file_jumps` initialized in `/source/libio/fileops.c#L1432`:
```c
// /source/libio/fileops.c#L1432


const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_file_jumps)
```

Most of the intialization stuff stands in the `_IO_new_file_init_internal` function:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/fileops.c#L105

void
_IO_new_file_init_internal (struct _IO_FILE_plus *fp)
{
  /* POSIX.1 allows another file handle to be used to change the position
     of our file descriptor.  Hence we actually don't know the actual
     position before we do the first fseek (and until a following fflush). */
  fp->file._offset = _IO_pos_BAD;
  fp->file._flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp);
  fp->file._fileno = -1;
}
```

`fp->file._flags` is initialized to `CLOSED_FILEBUF_FLAGS` which means according to its definition:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/fileops.c#L100

#define CLOSED_FILEBUF_FLAGS \
  (_IO_IS_FILEBUF+_IO_NO_READS+_IO_NO_WRITES+_IO_TIED_PUT_GET)

// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/libio.h#L78
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
```

Then the `fp` (the file pointer) is linked into the single linked list that keeps track of every file stream, for which the HEAD is `_IO_list_all`.
`_IO_link_in` is defined like this:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/genops.c#L86

void
_IO_link_in (struct _IO_FILE_plus *fp)
{
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (FILE *) fp;
      _IO_flockfile ((FILE *) fp);
#endif
      fp->file._chain = (FILE *) _IO_list_all;
      _IO_list_all = fp;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
libc_hidden_def (_IO_link_in)
```

Once it has been initialized, `_IO_file_fopen` is called to open the file with the right file and mode. Here is its definition:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/fileops.c#L211

FILE *
_IO_new_file_fopen (FILE *fp, const char *filename, const char *mode,
		    int is32not64)
{
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  FILE *result;
  const char *cs;
  const char *last_recognized;

  if (_IO_file_is_open (fp))
    return 0;
  switch (*mode)
    {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      omode = O_WRONLY;
      oflags = O_CREAT|O_TRUNC;
      read_write = _IO_NO_READS;
      break;
    case 'a':
      omode = O_WRONLY;
      oflags = O_CREAT|O_APPEND;
      read_write = _IO_NO_READS|_IO_IS_APPENDING;
      break;
    default:
      __set_errno (EINVAL);
      return NULL;
    }
  last_recognized = mode;
  for (i = 1; i < 7; ++i)
    {
      switch (*++mode)
	{
	case '\0':
	  break;
	case '+':
	  omode = O_RDWR;
	  read_write &= _IO_IS_APPENDING;
	  last_recognized = mode;
	  continue;
	case 'x':
	  oflags |= O_EXCL;
	  last_recognized = mode;
	  continue;
	case 'b':
	  last_recognized = mode;
	  continue;
	case 'm':
	  fp->_flags2 |= _IO_FLAGS2_MMAP;
	  continue;
	case 'c':
	  fp->_flags2 |= _IO_FLAGS2_NOTCANCEL;
	  continue;
	case 'e':
	  oflags |= O_CLOEXEC;
	  fp->_flags2 |= _IO_FLAGS2_CLOEXEC;
	  continue;
	default:
	  /* Ignore.  */
	  continue;
	}
      break;
    }

  result = _IO_file_open (fp, filename, omode|oflags, oprot, read_write,
			  is32not64);

  if (result != NULL)
    {
      /* Test whether the mode string specifies the conversion.  */
      cs = strstr (last_recognized + 1, ",ccs=");
      if (cs != NULL)
	{
	  /* Yep.  Load the appropriate conversions and set the orientation
	     to wide.  */
	  struct gconv_fcts fcts;
	  struct _IO_codecvt *cc;
	  char *endp = __strchrnul (cs + 5, ',');
	  char *ccs = malloc (endp - (cs + 5) + 3);

	  if (ccs == NULL)
	    {
	      int malloc_err = errno;  /* Whatever malloc failed with.  */
	      (void) _IO_file_close_it (fp);
	      __set_errno (malloc_err);
	      return NULL;
	    }

	  *((char *) __mempcpy (ccs, cs + 5, endp - (cs + 5))) = '\0';
	  strip (ccs, ccs);

	  if (__wcsmbs_named_conv (&fcts, ccs[2] == '\0'
				   ? upstr (ccs, cs + 5) : ccs) != 0)
	    {
	      /* Something went wrong, we cannot load the conversion modules.
		 This means we cannot proceed since the user explicitly asked
		 for these.  */
	      (void) _IO_file_close_it (fp);
	      free (ccs);
	      __set_errno (EINVAL);
	      return NULL;
	    }

	  free (ccs);

	  assert (fcts.towc_nsteps == 1);
	  assert (fcts.tomb_nsteps == 1);

	  fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
	  fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_write_base;

	  /* Clear the state.  We start all over again.  */
	  memset (&fp->_wide_data->_IO_state, '\0', sizeof (__mbstate_t));
	  memset (&fp->_wide_data->_IO_last_state, '\0', sizeof (__mbstate_t));

	  cc = fp->_codecvt = &fp->_wide_data->_codecvt;

	  cc->__cd_in.step = fcts.towc;

	  cc->__cd_in.step_data.__invocation_counter = 0;
	  cc->__cd_in.step_data.__internal_use = 1;
	  cc->__cd_in.step_data.__flags = __GCONV_IS_LAST;
	  cc->__cd_in.step_data.__statep = &result->_wide_data->_IO_state;

	  cc->__cd_out.step = fcts.tomb;

	  cc->__cd_out.step_data.__invocation_counter = 0;
	  cc->__cd_out.step_data.__internal_use = 1;
	  cc->__cd_out.step_data.__flags = __GCONV_IS_LAST | __GCONV_TRANSLIT;
	  cc->__cd_out.step_data.__statep = &result->_wide_data->_IO_state;

	  /* From now on use the wide character callback functions.  */
	  _IO_JUMPS_FILE_plus (fp) = fp->_wide_data->_wide_vtable;

	  /* Set the mode now.  */
	  result->_mode = 1;
	}
    }

  return result;
}
libc_hidden_ver (_IO_new_file_fopen, _IO_file_fopen)
```

That's a pretty huge function but most of it is just parsing and handling of a specific encoding for the file. First it checks if the file is already open then it parses the mode and once it's done it calls `_IO_file_open` with the right flags. Then is the file requires a specific encoding it intitializes `_wide_data` and so on to properly handle it. Let's take a look at the  `_IO_file_open` function:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/fileops.c#L180

FILE *
_IO_file_open (FILE *fp, const char *filename, int posix_mode, int prot,
	       int read_write, int is32not64)
{
  int fdesc;
  if (__glibc_unlikely (fp->_flags2 & _IO_FLAGS2_NOTCANCEL))
    fdesc = __open_nocancel (filename,
			     posix_mode | (is32not64 ? 0 : O_LARGEFILE), prot);
  else
    fdesc = __open (filename, posix_mode | (is32not64 ? 0 : O_LARGEFILE), prot);
  if (fdesc < 0)
    return NULL;
  fp->_fileno = fdesc;
  _IO_mask_flags (fp, read_write,_IO_NO_READS+_IO_NO_WRITES+_IO_IS_APPENDING);
  /* For append mode, send the file offset to the end of the file.  Don't
     update the offset cache though, since the file handle is not active.  */
  if ((read_write & (_IO_IS_APPENDING | _IO_NO_READS))
      == (_IO_IS_APPENDING | _IO_NO_READS))
    {
      off64_t new_pos = _IO_SYSSEEK (fp, 0, _IO_seek_end);
      if (new_pos == _IO_pos_BAD && errno != ESPIPE)
	{
	  __close_nocancel (fdesc);
	  return NULL;
	}
    }
  _IO_link_in ((struct _IO_FILE_plus *) fp);
  return fp;
}
libc_hidden_def (_IO_file_open)
```

If the mode doesn't allow the open process to be a cancellation point it calls `__open_nocancel`, else it calls `__open`. When the file is open, it initializes flags, file descriptor (fileno) and links the actual file pointer to the single linked list that stores every file stream (if that's not already the case).

Then we're back into `__fopen_internal` to call `__fopen_maybe_mmap` on the newly open file:
```c
// https://elixir.bootlin.com/glibc/glibc-2.36/source/libio/iofopen.c#L34

FILE *
__fopen_maybe_mmap (FILE *fp)
{
#if _G_HAVE_MMAP
  if ((fp->_flags2 & _IO_FLAGS2_MMAP) && (fp->_flags & _IO_NO_WRITES))
    {
      /* Since this is read-only, we might be able to mmap the contents
	 directly.  We delay the decision until the first read attempt by
	 giving it a jump table containing functions that choose mmap or
	 vanilla file operations and reset the jump table accordingly.  */

      if (fp->_mode <= 0)
	_IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps_maybe_mmap;
      else
	_IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps_maybe_mmap;
      fp->_wide_data->_wide_vtable = &_IO_wfile_jumps_maybe_mmap;
    }
#endif
  return fp;
}
```

I think the comment is enough explicit, once `__fopen_maybe_mmap` is called the `fp` is returned given the file descriptor has properly been allocated, initialized and that the file is open. Else it means that there are some errors, then the `fp` is unlinked from the single linked that stores every file stream, and the `locked_FILE` is freed, returning `NULL` indicating an error.

That's basically how `fopen` works !

# fread

Once a `_IO_FILE` structure has been initialized and linked into the `_IO_list_all` single linked list, several operations can occur. A basic primitive would be to read data from a file, that's what fread does with the use of certain fields of `_IO_FILE`.

Here is a basic description of what `fread` does, the schema comes from [the incredible article of raycp](https://ray-cp.github.io/archivers/IO_FILE_fread_analysis).

<p align="center" width="100%">
    fread algorithm.<br>
    <img width="80%" src="/fread.png">
    </br>
</p>

According to the man: "The function fread() reads nmemb items of data, each size bytes long, from the stream pointed to by stream, storing them at the location given by ptr.". Now let's dig deeper within the code. `fread` is defined there:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/iofread.c#L30

size_t
_IO_fread (void *buf, size_t size, size_t count, FILE *fp)
{
  size_t bytes_requested = size * count;
  size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
libc_hidden_def (_IO_fread)
```

If the amount of requested bytes is null, zero is returned. `CHECK_FILE` checks (if `IO_DEBUG` is enabled) if `fp` exists and if `fp->flags` is properely structured:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/libioP.h#L866

#ifdef IO_DEBUG
# define CHECK_FILE(FILE, RET) do {				\
    if ((FILE) == NULL						\
	|| ((FILE)->_flags & _IO_MAGIC_MASK) != _IO_MAGIC)	\
      {								\
	__set_errno (EINVAL);					\
	return RET;						\
      }								\
  } while (0)
#else
# define CHECK_FILE(FILE, RET) do { } while (0)
#endif
```

Then `_IO_sgetn` is called:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/genops.c#L408

size_t
_IO_sgetn (FILE *fp, void *data, size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}
libc_hidden_def (_IO_sgetn)
```

When this is the first time `_IO_sgetn` is called, on most of the platforms (the one which support `mmap`) the `vtable` is initialized to `_IO_file_jumps_maybe_mmap`:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L1481

const struct _IO_jump_t _IO_file_jumps_maybe_mmap libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow_maybe_mmap),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_new_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn_maybe_mmap),
  JUMP_INIT(seekoff, _IO_file_seekoff_maybe_mmap),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, (_IO_setbuf_t) _IO_file_setbuf_mmap),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

Which means `_IO_sgetn` calls `_IO_file_xsgetn_maybe_mmap`:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L1409

static size_t
_IO_file_xsgetn_maybe_mmap (FILE *fp, void *data, size_t n)
{
  /* We only get here if this is the first attempt to read something.
     Decide which operations to use and then punt to the chosen one.  */

  decide_maybe_mmap (fp);
  return _IO_XSGETN (fp, data, n);
}
```

`decide_maybe_mmap` is basicaly trying to map the file, if it succeeds the `vtable` is initialized to `&_IO_file_jumps_mmap` else it's initialized to `&_IO_file_jumps`. The function is pretty easy to read, except maybe for the `S_ISREG (st.st_mode) && st.st_size != 0` that checks if it is a regular file and if its size isn't null. Here is the full code:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L658

static void
decide_maybe_mmap (FILE *fp)
{
  /* We use the file in read-only mode.  This could mean we can
     mmap the file and use it without any copying.  But not all
     file descriptors are for mmap-able objects and on 32-bit
     machines we don't want to map files which are too large since
     this would require too much virtual memory.  */
  struct __stat64_t64 st;

  if (_IO_SYSSTAT (fp, &st) == 0
      && S_ISREG (st.st_mode) && st.st_size != 0
      /* Limit the file size to 1MB for 32-bit machines.  */
      && (sizeof (ptrdiff_t) > 4 || st.st_size < 1*1024*1024)
      /* Sanity check.  */
      && (fp->_offset == _IO_pos_BAD || fp->_offset <= st.st_size))
    {
      /* Try to map the file.  */
      void *p;

      p = __mmap64 (NULL, st.st_size, PROT_READ, MAP_SHARED, fp->_fileno, 0);
      if (p != MAP_FAILED)
	{
	  /* OK, we managed to map the file.  Set the buffer up and use a
	     special jump table with simplified underflow functions which
	     never tries to read anything from the file.  */

	  if (__lseek64 (fp->_fileno, st.st_size, SEEK_SET) != st.st_size)
	    {
	      (void) __munmap (p, st.st_size);
	      fp->_offset = _IO_pos_BAD;
	    }
	  else
	    {
	      _IO_setb (fp, p, (char *) p + st.st_size, 0);

	      if (fp->_offset == _IO_pos_BAD)
		fp->_offset = 0;

	      _IO_setg (fp, p, p + fp->_offset, p + st.st_size);
	      fp->_offset = st.st_size;

	      if (fp->_mode <= 0)
		_IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps_mmap;
	      else
		_IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps_mmap;
	      fp->_wide_data->_wide_vtable = &_IO_wfile_jumps_mmap;

	      return;
	    }
	}
    }

  /* We couldn't use mmap, so revert to the vanilla file operations.  */

  if (fp->_mode <= 0)
    _IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps;
  else
    _IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps;
  fp->_wide_data->_wide_vtable = &_IO_wfile_jumps;
}
```
Two operations are very important to note in this function. First, `_IO_setb` ([take a look at this](#common-functions)) is called to initialize the begin of the  base buffer to the begin of the memory mapping of the file, the end of the base buffer is then initialized to the end of the file (`p + st.st_size`). Right after `_IO_setg` ([take a look at this](#common-functions)) is called to initialize the read buffer of the file, the base of the read buffer is initialized to the mapping of the file, the current pointer to `p + fp->_offset` and the end of the buffer to the end of the file mapping.


Then according to what `vtable` is used, the `xsgetn` is distinct:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L1457

// vtable if the file is maped
const struct _IO_jump_t _IO_file_jumps_mmap libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow_mmap),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_new_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn_mmap),
  JUMP_INIT(seekoff, _IO_file_seekoff_mmap),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, (_IO_setbuf_t) _IO_file_setbuf_mmap),
  JUMP_INIT(sync, _IO_file_sync_mmap),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close_mmap),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

// vanilla vtable
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L1432
const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_file_jumps)
```

## _IO_file_xsgetn_mmap

Let's first take a look at `_IO_file_xsgetn_mmap`:
```c
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L1364

static size_t
_IO_file_xsgetn_mmap (FILE *fp, void *data, size_t n)
{
  size_t have;
  char *read_ptr = fp->_IO_read_ptr;
  char *s = (char *) data;

  have = fp->_IO_read_end - fp->_IO_read_ptr;

  if (have < n)
    {
      if (__glibc_unlikely (_IO_in_backup (fp)))
	{
	  s = __mempcpy (s, read_ptr, have);
	  n -= have;
	  _IO_switch_to_main_get_area (fp);
	  read_ptr = fp->_IO_read_ptr;
	  have = fp->_IO_read_end - fp->_IO_read_ptr;
	}

      if (have < n)
	{
	  /* Check that we are mapping all of the file, in case it grew.  */
	  if (__glibc_unlikely (mmap_remap_check (fp)))
	    /* We punted mmap, so complete with the vanilla code.  */
	    return s - (char *) data + _IO_XSGETN (fp, data, n);

	  read_ptr = fp->_IO_read_ptr;
	  have = fp->_IO_read_end - read_ptr;
	}
    }

  if (have < n)
    fp->_flags |= _IO_EOF_SEEN;

  if (have != 0)
    {
      have = MIN (have, n);
      s = __mempcpy (s, read_ptr, have);
      fp->_IO_read_ptr = read_ptr + have;
    }

  return s - (char *) data;
}

// https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L541

/* Guts of underflow callback if we mmap the file.  This stats the file and
   updates the stream state to match.  In the normal case we return zero.
   If the file is no longer eligible for mmap, its jump tables are reset to
   the vanilla ones and we return nonzero.  */
static int
mmap_remap_check (FILE *fp)
{
  struct stat64 st;

  if (_IO_SYSSTAT (fp, &st) == 0
      && S_ISREG (st.st_mode) && st.st_size != 0
      /* Limit the file size to 1MB for 32-bit machines.  */
      && (sizeof (ptrdiff_t) > 4 || st.st_size < 1*1024*1024))
    {
      const size_t pagesize = __getpagesize ();
# define ROUNDED(x)	(((x) + pagesize - 1) & ~(pagesize - 1))
      if (ROUNDED (st.st_size) < ROUNDED (fp->_IO_buf_end
					  - fp->_IO_buf_base))
	{
	  /* We can trim off some pages past the end of the file.  */
	  (void) __munmap (fp->_IO_buf_base + ROUNDED (st.st_size),
			   ROUNDED (fp->_IO_buf_end - fp->_IO_buf_base)
			   - ROUNDED (st.st_size));
	  fp->_IO_buf_end = fp->_IO_buf_base + st.st_size;
	}
      else if (ROUNDED (st.st_size) > ROUNDED (fp->_IO_buf_end
					       - fp->_IO_buf_base))
	{
	  /* The file added some pages.  We need to remap it.  */
	  void *p;
#if _G_HAVE_MREMAP
	  p = __mremap (fp->_IO_buf_base, ROUNDED (fp->_IO_buf_end
						   - fp->_IO_buf_base),
			ROUNDED (st.st_size), MREMAP_MAYMOVE);
	  if (p == MAP_FAILED)
	    {
	      (void) __munmap (fp->_IO_buf_base,
			       fp->_IO_buf_end - fp->_IO_buf_base);
	      goto punt;
	    }
#else
	  (void) __munmap (fp->_IO_buf_base,
			   fp->_IO_buf_end - fp->_IO_buf_base);
	  p = __mmap64 (NULL, st.st_size, PROT_READ, MAP_SHARED,
			fp->_fileno, 0);
	  if (p == MAP_FAILED)
	    goto punt;
#endif
	  fp->_IO_buf_base = p;
	  fp->_IO_buf_end = fp->_IO_buf_base + st.st_size;
	}
      else
	{
	  /* The number of pages didn't change.  */
	  fp->_IO_buf_end = fp->_IO_buf_base + st.st_size;
	}
# undef ROUNDED

      fp->_offset -= fp->_IO_read_end - fp->_IO_read_ptr;
      _IO_setg (fp, fp->_IO_buf_base,
		fp->_offset < fp->_IO_buf_end - fp->_IO_buf_base
		? fp->_IO_buf_base + fp->_offset : fp->_IO_buf_end,
		fp->_IO_buf_end);

      /* If we are already positioned at or past the end of the file, don't
	 change the current offset.  If not, seek past what we have mapped,
	 mimicking the position left by a normal underflow reading into its
	 buffer until EOF.  */

      if (fp->_offset < fp->_IO_buf_end - fp->_IO_buf_base)
	{
	  if (__lseek64 (fp->_fileno, fp->_IO_buf_end - fp->_IO_buf_base,
			 SEEK_SET)
	      != fp->_IO_buf_end - fp->_IO_buf_base)
	    fp->_flags |= _IO_ERR_SEEN;
	  else
	    fp->_offset = fp->_IO_buf_end - fp->_IO_buf_base;
	}

      return 0;
    }
  else
    {
      /* Life is no longer good for mmap.  Punt it.  */
      (void) __munmap (fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
    punt:
      fp->_IO_buf_base = fp->_IO_buf_end = NULL;
      _IO_setg (fp, NULL, NULL, NULL);
      if (fp->_mode <= 0)
	_IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps;
      else
	_IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps;
      fp->_wide_data->_wide_vtable = &_IO_wfile_jumps;

      return 1;
    }
}
```
x
First is computed the amount of bytes that contains the read buffer (`have`). If we do not have the right amount of bytes within the read buffer we first try to copy data from the read buffer. Then we check we are mappng the whole file (and not only a part of it) with the use of `mmap_remap_check` (to avoid useless code I put it directly after the implementation of `_IO_file_xsgetn_mmap`), if it fails the file is unmapped and the vanilla file operations is used to read data from the file.