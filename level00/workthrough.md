# LEVEL00
**Info level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level00/level00
```
---
```sh
level00@OverRide:~$ ls -la
total 13
dr-xr-x---+ 1 level01 level01   60 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level00 level00 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level01 users   7280 Sep 10  2016 level00
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:123

Invalid Password!
```
Welcome to ***Override***, after login, we can find one excutable file **level00**, who take standard input with passord, and check it. \
\
Check it with GDB,
```sh
   0x080484de <+74>:    call   0x80483d0 <__isoc99_scanf@plt>
   0x080484e3 <+79>:    mov    0x1c(%esp),%eax
   0x080484e7 <+83>:    cmp    $0x149c,%eax # 5276
   ...
   0x080484fa <+102>:   movl   $0x8048649,(%esp)
   0x08048501 <+109>:   call   0x80483a0 <system@plt> # /bin/sh
```
Simple exercise, we can find our input passed through scanf \
which is compared with the concrete value ```0x149c```. If matches it gives us a shell.
```sh
level00@OverRide:~$ ./level00 
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

level00 passed !