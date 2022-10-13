---
createdAt: 2022-05-29
title: "[HeroCTF v4 - crypto] How (not) to make a crypto challenge"
description: "Looks like Tiresias, the blind oracle, took a nice long holiday and his apprentice had to cover for him. She's new to the job so if she forgets anything... you'll just have to deal with it."
tags: ["Crypto"]
type: 'Writeups'
---

```
# The oracle's apprentice

Looks like Tiresias, the blind oracle, took a nice long holiday and his apprentice had to cover for him. She's new to the job so if she forgets anything... you'll just have to deal with it.

Good luck !

`Format : Hero{flag}`
`Author : Alol` (NB: that's me !)
```

# The premise

As it turns out I fucked up. The 4th edition of the HeroCTF is about to end after a weekend of everything going surprisingly well. The infrastructure didn't crash, we didn't get DDOSed, we didn't have to deal with cryptominers and everybody generally had a great time. I was the creator of the OSINT challenges and a crypto(graphy) challenge : `The oracle's apprentice`, the subject of this article.

More than just providing a write-up to the challenge this blogpost will also detail the *several* unintended ways the challenge could be solved. These "unintendeds" are actually textbook RSA vulnerabilities, which makes this article accessible to novices and my shame even greater. If you're only interested in the (intended) solution to this challenge you can jump right to `The intended way `.

```python
#!/usr/bin/env python3
from Crypto.Util.number import getStrongPrime, bytes_to_long
import random

FLAG = open('flag.txt','rb').read()

encrypt = lambda m: pow(m, e, n)
decrypt = lambda c: pow(c, d, n)

e = random.randrange(3, 65537, 2)	
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)

n = p * q
φ = (p-1) * (q-1)

d = pow(e, -1, φ)

c = encrypt(bytes_to_long(FLAG))

#print(f"{n=}")
#print(f"{e=}")
print(f"{c=}")

for _ in range(3):
     t = int(input("c="))
     print(decrypt(t)) if c != t else None
```

The following python source code is given. We can see a rather classical RSA decryption/signing oracle challenge, where a server provides an encrypted flag and decrypts/signs user inputs (the decryption and signing operations in RSA are the same). This oracle however comes with a twist : the players don't get the public key (`n` and `e`), only the encrypted flag.

# Unintended n°1 : n-th root attack (small e)

Thanks to this vulnerability the challenge was solvable in ... 0 queries. Yes that's right, you didn't even have to send a request to the server since when you connect to the server it first sends the encrypted flag.

When a very small `e` (`3`, `5` or `7` for example) is used in textbook RSA the decrypted message `m` can be recovered by taking the `e`-th root of `c`. This happens because if `m^e` is smaller than the modulus `n` the modulo operation never happens and no actual encryption takes place. The solution to this is to always pad messages (with `OAEP` for example) and to use a larger `e`. `65537` is pretty much the universal default as exponentiation with [Fermat Numbers](https://en.wikipedia.org/wiki/Fermat_number) is nice and efficient.

```python
"""
the vulnerability stems from this line of code :
	e = random.randrange(3, 65537, 2)

e can take any odd value in [3, 65537[
e being small enough for an n-th root attack (3, 5 or 7) has a probability of

							3 * ((65535-3) / 2)⁻¹ ≈ 9.15e-05

So roughly 1 over 10 thousand. It will take, on average, 5_000 requests to be able to get a small enough e. This is easily bruteforceable, even over the internet.
"""

from Crypto.Util.number import long_to_bytes
from tqdm import tqdm
from pwn import *
context.log_level = 'warning'

recv = lambda: int(r.recvline().decode().split("=")[1])

def invpow(x, n):
    """
    Taken from here : https://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer
    """
    high = 1
    while high ** n <= x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

for _ in tqdm(range(10_000)):

    r = remote('crypto.heroctf.fr', 9000)
    c = recv()                             # get c
    r.close()

    for e in [3, 5, 7]:
        m = long_to_bytes(invpow(c, e))    # calculate m^1/3,
                                           # m^1/5 and m^1/7
        if m.startswith(b"Hero{"):
            print(m)                       # print m
            input()

"""output
alol@mecha-kraken$ python3 unintended1.py
 10%|██████▏                                                       | 991/10000 [15:03<2:32:33,  1.02s/it]
b'Hero{m4ybe_le4ving_the_1nt3rn_run_th3_plac3_wasnt_a_g00d_id3a}\n'

"""
```

# Unintended n°2 : "self"-blinding

OK that was pretty cool but it took quite a while (I had to run the script above twice). Want to see a way to get the flag using a single query *instantly* ? Well we'll have to talk about blinding first.

The RSA cryptosystem is interesting because it's malleable when unpadded, ie. it's possible to transform a ciphertext into another ciphertext which decrypts to a related plaintext. This comes from the fact that exponentiation is partially homomorphic.
$$
{\displaystyle {\begin{aligned}{\mathcal {E}}(m_{1})\cdot {\mathcal {E}}(m_{2})&=m_{1}^{e}m_{2}^{e}\;{\bmod {\;}}n\\[6pt]&=(m_{1}m_{2})^{e}\;{\bmod {\;}}n\\[6pt]&={\mathcal {E}}(m_{1}\cdot m_{2})\end{aligned}}}
$$
This malleability makes blinding trivial. [Blinding, as defined by Wikipedia](https://en.wikipedia.org/wiki/Blinding_(cryptography)), is a technique by which an agent can provide a service to (i.e., compute a function for) a client in an encoded form without knowing either the real input or the real output. Blinding techniques also have applications to preventing side-channel attacks on encryption devices.
$$
\text{Alice wants Bob to sign a message m without it being revealed to Bob.}\\
\text{Alice picks a random integer r and sends Bob }m' \text{, such that }m \cdot \mathcal {E}(r) \equiv m' [n] \\
\text{Bob sends back } \mathcal {D}(m') = \mathcal {D}(m \cdot \mathcal {E}(r)) = \mathcal {D}(m) \cdot r \\
\text{Alice can now divide }\mathcal {D}(m')\text{ by r to retrieve the signed message without Bob ever knowing the value of neither m nor r.}
$$

We could try applying this principal to the challenge to retrieve the flag but we first have to encrypt `r` and we don't know `e`. *If only we had a valid message encrypted by the server wink wink wink*. That's right, the encrypted flag is a valid message ! Instead of choosing a random `r` to blind `m` we can use the encrypted flag to blind itself, this way we can take the square root of `m'` to recover `m`. 


```python
from Crypto.Util.number import long_to_bytes
from pwn import *
context.log_level = 'warning'

send = lambda m: r.sendline(str(m).encode())
recv = lambda: int(r.recvline().decode().split("=")[1])

def invpow(x, n):
    """
    Taken from here : https://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer
    [Removed for readability]
    """

r = remote('crypto.heroctf.fr', 9000)
c = recv()                             # get c

send(pow(c, 2))                        # send c^2

c = recv()                             # get m^2
print(long_to_bytes(invpow(c, 2)))     # print m

"""output
alol@mecha-kraken$ python3 unintended2.py
b'Hero{m4ybe_le4ving_the_1nt3rn_run_th3_plac3_wasnt_a_g00d_id3a}\n'
"""
```

# Unintended n°3 : modular arithmetic

We just saw that blindly trusting the user input was a great way to get pwned. Lets do it again ! It uses a simple fact :

$$
m \pm k\cdot n \equiv m [n]
$$
*Is that it ?* Yep that's it. After recovering `n` you could just add `n` to the encrypted flag, send it to the server and it would return the decrypted flag. 
$$
{\displaystyle {
	\begin{aligned}
		{\mathcal {D}}(c + n) &= c^{d}n^{d}\;{\bmod {\;}}n \\[6pt]
		&= c^{d}\;{\bmod {\;}}n \\[6pt]
		&= m
	\end{aligned}
}}
$$

```python
from Crypto.Util.number import long_to_bytes
from pwn import *
context.log_level = 'warning'

send = lambda m: r.sendline(str(m).encode())
recv = lambda: int(r.recvline().decode().split("=")[1])

r = remote('crypto.heroctf.fr', 9000)
c = recv()                             # get c

send(-1)                               # send -1

n = recv() + 1                         # get n
send(c + n)                            # send c+n

print(long_to_bytes(recv()))           # print m

"""output
alol@mecha-kraken$ python3 unintended3.py
b'Hero{m4ybe_le4ving_the_1nt3rn_run_th3_plac3_wasnt_a_g00d_id3a}\n'
"""
```

# The intended way : 

Before solving the challenge the intended way lets look into mitigations for the unintendeds.

```python
#!/usr/bin/env python3
from Crypto.Util.number import getStrongPrime, bytes_to_long
from Crypto.Util.Padding import pad
import random

FLAG = pad(open('flag.txt','rb').read(), 128) # fix unintended n°1 : pad the flag so the
                                              # decryption isn't trivial anymore

# [Removed for readability]

for _ in range(3):
     t = decrypt(int(input("c=")))   # fix unintended n°3 : make sure the output != flag
     print(t) if FLAG != t else None
```

The unintended n°2 isn't easy to patch so it's been left in. Well done W00dy, you're a pretty smart dude.

So how was the challenge meant to be solved ? TL;DR : recover n, recover e and recover the flag.

### Step 1: recover n

Can't do much modular arithmetic without a modulus right ? Retrieving n is surprisingly easy but requires a bit of thinking.
$$
{\displaystyle {\begin{aligned}
{\mathcal {D}}(-1) &= (-1)^{d} \bmod n\\[6pt]
&=(-1)^{2k+1} \bmod n\\[6pt]
&=(-1)^{2k} \cdot (-1)^{1} \bmod n\\[6pt]
&=1\cdot -1 \bmod n\\[6pt]
&=-1 \bmod n\\[6pt]
&= n -1
\end{aligned}}}
$$
Just add one and you have `n` ! But *why* ? You'll find a more in depth explanation [here](https://math.stackexchange.com/questions/1221723/why-in-rsa-the-public-exponent-e-must-be-coprime-with-phi-n) but basically :

- `p` and `q` are two large primes so they're odd numbers.
- `n`, the product of `p` and `q`, is odd and `φ`, the product of `(p - 1)` and `(q - 1)`, is even.
- Lets recall that in RSA, `ed = kφ + 1`. The right side of the equation is odd so the right side also must be odd, thus both `e` and `d` must odd.

### Step 2: recover e

Now that we have `n` we're only missing `e` to be able to encrypt with the public key. We know `e` is an odd number in the range `[3, 65537[` so we can send an arbitrary value (say `2` for example), receive `dec(2)` and bruteforce all possible values for `e`.

```python
# [...]
send(2)
two = recv()

for e in tqdm(range(3, 65537, 2)):
	if pow(two, e, n) == 2:
		break
```

### Step 3: recover the flag

Now that we can encrypt arbitrary values we can perform a blinding attack. We'll use `2` and `dec(2)` as we already have them. 

Here's the full script to retrieve the flag :

```python
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from tqdm import tqdm
from pwn import *
context.log_level = 'warning'

send = lambda m: r.sendline(str(m).encode())
recv = lambda: int(r.recvline().decode().split("=")[1])

r = remote('crypto.heroctf.fr', 9000)

c = recv()                             # get c

send(-1)                               # send c^2
n = recv() +1                          # get m^2
print('[+] Got N')

send(2)                                # use 2 as blinding value
two = recv()

for e in tqdm(range(3, 65537, 2)):     # retreive e
	if pow(two, e, n) == 2:
		break
print('[+] Got e', e)

send(c * 2)                            # blind the encrypted flag
p = (recv() * pow(two, -1, n)) % n     # unblind the flag
print('[+] Got flag', unpad(long_to_bytes(p), 128))

"""output
[+] Got N
 87%|█████████████████████████▏   | 28495/32767 [00:13<00:02, 2126.60it/s]
[+] Got e 56993
[+] Got flag b'Hero{m4ybe_le4ving_the_1nt3rn_run_th3_plac3_wasnt_a_g00d_id3a}\n'
"""
```

# To conclude

Making challenges is easy, making challenges that you think the players will find interesting is hard and making interesting challenges that won't be full of "unintendeds" is even harder. I've already coded and tested several crypto challenges for next year (HeroCTF v5 is planned for january 2023) and hopefully they won't be full of holes. Ironically, a challenge full of holes is a great way for everybody to learn.