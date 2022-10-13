---
createdAt: 2021-12-05
title: "[TRACS 2021 - RE] Coffre"
description: "Basically, we have to crack open an electronic safe."
type: 'Writeups'
tags: ["pwn"]
---

# [TRACS 2021 - RE] Coffre

## Intro
>  Epreuve 12-3 – Coffre
>  En tant que stagiaire vous avez accès aux locaux de la NSB. Vous allez collecter des informations dans les locaux. Un coffre est présent dans les locaux en salle rideau. Il appartient à Richard Cresus de la Tune. Essayez d’ouvrir ce coffre. Quel est l’IBAN contenu dans le coffre ? Format de la réponse : IBAN sans séparateur.

Basically, we have to crack open an electronic safe. It's locked with an electromagnet and requires a pin to open, moreover it prints an id right before asking for the pin. We previously were given a link to the download page one of the safe's software update (`http://safe-locks.tracs.viarezo.fr/download`).

## Reversing the custom libcrypto.so library

The software update comes in the from of a `.maj` archive that we extracted to get two `libcrypto.so` libraries (one for x86, the other one for arm64 v7). We checked if the files were equivalent by looking at their code structure, and we finally choose to reverse the x86 library (even though the safe probably used the arm one) because it was easier.

Firstly, we looked at how the pin was checked, more specifically at the `libsafe_test_passcode` in IDA:
```c
_BOOL8 __fastcall libsafe_test_passcode(const char *a1)
{
  unsigned int v2; // eax
  int fd; // [rsp+1Ch] [rbp-64h]
  char buf[36]; // [rsp+20h] [rbp-60h] BYREF
  char s1[40]; // [rsp+50h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fd = open(".safe_db", 0);
  if ( fd < 0 )
    return 0LL;
  read(fd, buf, 0x24uLL);
  close(fd);
  v2 = strlen(a1);
  sha256sum(a1, v2, s1);
  return memcmp(s1, &buf[4], 0x20uLL) == 0;
}
```

We assume the argument is a pointer to the pin, for which we compute its `sha256sum`. And if it is equal to `buf[4:0x24]`, it means the pin correct! So we have to understand what `buf[4:0x24]` is, which is stored in the `.safe_db` file. To do so we look at the `libsafe_generate_new_passcode` function:
```c
__int64 __fastcall libsafe_generate_new_passcode(unsigned __int8 *a1)
{
  unsigned int v1; // eax
  int i; // [rsp+18h] [rbp-468h]
  int fd; // [rsp+1Ch] [rbp-464h]
  char file_content[36]; // [rsp+20h] [rbp-460h] BYREF
  char hash_rand_buf[32]; // [rsp+50h] [rbp-430h] BYREF
  char rand_buf[1032]; // [rsp+70h] [rbp-410h] BYREF
  unsigned __int64 canary; // [rsp+478h] [rbp-8h]

  canary = __readfsqword(0x28u);
  v1 = time(0LL);
  srand(v1);
  memset(file_content, 0, sizeof(file_content));
  *(_DWORD *)file_content = rand();
  for ( i = 0; i <= 1023; ++i )
    rand_buf[i] = rand();
  sha256sum(rand_buf, 1024LL, hash_rand_buf);
  _build_passcode((__int64)hash_rand_buf, 32LL, (__int64)a1, 8LL);
  sha256sum(a1, 8LL, &file_content[4]);
  fd = open(".safe_db", 577);
  if ( fd < 0 )
    return 1LL;
  write(fd, file_content, 0x24uLL);
  close(fd);
  return 0LL;
}
```
The function is very basic: 
- It takes as argument a pointer to the buffer to cipher for which we compute the hash to fill out the `.safe_db` file.
- It initializes the PRNG with `time(NULL)` passed as an argument to`srand`. It then creates an array of `1024` random bytes with the use of `rand`.
- Then, this array is hashed with `sha256sum` and its hash is given to the `_build_passcode` function. The result is stored in the `a1` argument.
- The argument is hashed again and in the target file we write at `file_content[:4]` the first `rand` value and at `file_content[4:0x24]` the hash of the previous ciphered buffer.

The core of the encryption algorithm is in the `build_passcode` function:
```c
__int64 __fastcall build_passcode(
        unsigned __int8 *hash_rand_buf,
        unsigned int length_hash,
        unsigned __int8 *out,
        unsigned int opaque_8)
{
  __int64 result; // rax
  unsigned int i; // [rsp+20h] [rbp-10h]
  unsigned int length_base; // [rsp+24h] [rbp-Ch]

  lenght_base = strlen("1234567890ABCD");
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= opaque_8 )
      break;
    out[i] = base[hash_rand_buf[i % length_hash] % length_base];
  }
  return result;
}
```

That's just basically filling out the `out` buffer with `base[hash_rand_buf[i % length_hash] % lenght_base]`.

Now we have a good understanding of the encryption algorithm, we can take a look at what exactly the `id` printed right before the pin input is. The function that generates the `id` is `libsafe_get_userid`:
```c
__int64 __fastcall libsafe_get_userid(_DWORD *id)
{
  int fd; // [rsp+1Ch] [rbp-34h]
  int buf[10]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fd = open(".safe_db", 0);
  if ( fd < 0 )
    return 1LL;
  read(fd, buf, 0x24uLL);
  close(fd);
  *id = buf[0];
  return 0LL;
}
```
The function is very basic, it opens the `.safe_db` file and initializes the `id` to the first four bytes of the file which is the first value of rand as seen in the previous functions.

## Cracking the seed

To recover the pin, we have to know what hash the hash of the pin will be compared to. To do so, we have to recover the random buffer, hash it, give it to the "core" encryption layer and hash what it outputs. That will be the final hash which will be compared to the hash of the pin we send. The main part of the challenge is so to recover the `rand` values, more specifically the seed given to `srand` to initialize the PRNG. We know the seed in the program is `time(NULL)`. Which means that this is a timestamp that can be bruteforced in a reasonable amount of time (the 2020 edition of the CTF was cancelled because of COVID so we took as range the date of the software update until today). The bruteforce is very fast because given we know the `id` which is the value for the first call to `rand`, we have just to ensure the first value of `rand` for the seed we bruteforce is equal to the `id` value.

Which gives:
```python
from tqdm import tqdm
import hashlib
from ctypes import CDLL
libc = CDLL("libc.so.6")

h = lambda x: hashlib.sha256(x).digest()

START_TIME   = 1605052800 # 2020-11-11 12:00:00 AM -> known date for the software update
CURRENT_TIME = 1638633346 # 2021-12-04  3:55:46 PM -> current time
PINCODE      = 0x4b2e2a1c

CHARSET      = b"1234567890ABCD"
CHARLEN      = len(CHARSET)

for t in tqdm(range(CURRENT_TIME - START_TIME)):
    t += START_TIME

    libc.srand(t)
    
    if PINCODE == libc.rand():

        v8 = [libc.rand() & 0xff for _ in range(1024)]
        v8 = h(bytearray(v8))

        v6 = [CHARSET[v8[i % 32] % CHARLEN] for i in range(8)]
        v6 = h(bytearray(v6))

        print(f"Timestamp: {t=}, hash: {v6.hex()}")
```

And when we found the right seed, we just have to generate, hash, cipher and hash again the right random buffer to get the right hash to which the hash of the pin will be compared to.

```Shell
$ python3 solve.py 
 94%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏       | 31691218/33580546 [01:29<00:05, 351593.81it/s]
Timestamp: t=1636749762, hash: 88c71c0cc0950acfe3835a009f8931cee0f12ab7410538f96d058184a4c90e11
100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 33580546/33580546 [01:34<00:00, 356533.87it/s]
```

## Hashcat + PROFIT

Now we know the final hash to which the hash of the pin is compared to, we can just run a mask attack using hashcat with a mask of 8 hexadecimal characters in uppercase (we tried for every length up to the right size: 8).

```
$ hashcat -a 3 -m 1400 pincode.hash ?H?H?H?H?H?H?H?H
[skip]
88c71c0cc0950acfe3835a009f8931cee0f12ab7410538f96d058184a4c90e11:4233246D

Session..........: hashcat
Status...........: Cracked
Hash.Type........: SHA2-256
Hash.Target......: 88c71c0cc0950acfe3835a009f8931cee0f12ab7410538f96d0...c90e11
Time.Started.....: Sat Dec  5 16:52:37 2021 (7 mins, 22 secs)
Time.Estimated...: Sat Dec  5 16:59:59 2021 (0 secs)
Guess.Mask.......: ?H?H?H?H?H?H?H?H [8]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7884.8 kH/s (7.30ms) @ Accel:256 Loops:64 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 3342925824/4294967296 (77.83%)
Rejected.........: 0/3342925824 (0.00%)
Restore.Point....: 816128/1048576 (77.83%)
Restore.Sub.#1...: Salt:0 Amplifier:0-64 Iteration:0-64
Candidates.#1....: 1234515D -> EBCF585D
```

The challenge was pretty funny because of the IRL part, and because we solved it together ([nasm](https://github.com/n4sm) and [Alol](https://twitter.com/yarienkiva)).

Authors: [nasm](https://github.com/n4sm) and [Alol](https://twitter.com/yarienkiva).

## Annexes

![The safe](https://ret2school.github.io/images/coffre.jpg)
