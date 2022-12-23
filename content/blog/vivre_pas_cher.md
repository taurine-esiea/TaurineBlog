---
createdAt: 2022-11-25
title: "[DG'Hack 2022 - Forensic] Vivre pas cher"
description: "Vivre pas cher is a challenge from DG'hack CTF."
type: 'Writeups'
tags: ["Forensic"]
---

# [DG'Hack 2022] Vivre pas cher - Cheap living

> author : malon 

### Intro

> Our server has been hacked. It's obvious.
>
> They expose our source code all the time, as soon as we update it.
>
> You need to find the source of this backdoor as soon as possible.
>
> Annie Massion, Postal Services



### Initial step

We are provided with a disk image

> a **disk image** is an exact copy of a disk

```bash
ls
#cheap-life.img
```

Let's try to list the partition(s): 

```bash
fdisk -l cheap-life.img
```

> Disk cheap-life.img: 1 GiB, 1073741824 bytes, 2097152 sectors
> Units: sectors of 1 * 512 = 512 bytes
> Sector size (logical/physical): 512 bytes / 512 bytes
> I/O size (minimum/optimal): 512 bytes / 512 bytes
> Disklabel type: dos
> Disk identifier: 0x257c224f
>
> Device          Boot Start     End Sectors  Size Id Type
> cheap-life.img1 *     2048 2097151 2095104 1023M 83 Linux

> A **partition** is a section of a storage media

Now that we have all the information we need :

- size of sectors : 512 bytes
- start offset of a partition : 2048

We can mount the Linux partition we found

```bash
sudo mkdir /mnt/ez
sudo mount -o $((512*2048)) cheap-life.img /mnt/ez
```

(from now on I will give the commands being possitioned in /mnt/ez)

> **backdoor** : access kept secret from the legitimate user

To find this backdoor, I go through the different ways to apply persistence on linux systems : ssh connection, cron, service,...

### Finding the backdoor among services

```bash
tree -a etc/systemd
```

![tree](https://taurine.vercel.app/images/blog/dghack2022/image1.png)

I look a little bit randomly at each of the files until I find an interesting one

```bash
cat etc/systemd/system/systembd.service
```

![systembd.service](https://taurine.vercel.app/images/blog/dghack2022/image2.png)

so when you give "start_backdoor" as an option to groupdel, everything is normal?

It is likely that this groupdel is not the classic groupdel so we should decompile it

- focus on **main()**:

![image-20221111172509945](https://taurine.vercel.app/images/blog/dghack2022/main.png)

![image-20221111172509945](https://taurine.vercel.app/images/blog/dghack2022/back_door.png)

there is indeed a start_backdoor function, but it comes from an external library

```bash
readelf -d usr/sbin/groupdel
```

![image-20221111172856523](https://taurine.vercel.app/images/blog/dghack2022/image3.png)


We now need to find the libsysd.so file

```bash
find . -name libsysd.so 
#./lib/libsysd.so
```

We can also analyze it with ghidra

- focus on **start_backdoor()**

![image-20221111173157204](https://taurine.vercel.app/images/blog/dghack2022/image4.png)


it seems like the flag get printed but it is base64 encoded

 ```bash
 echo -n "REdIQUNLe1N5c3RlbURJc0FGcmVuY2hFeHByZXNzaW9uQWJvdXRMaXZpbmdPdXRPZlJlc291cmNlZnVsbmVzc1dpd GhMaXR0bGVNb25leX0K" | base64 -d
 #DGHACK{**...}
 ```



