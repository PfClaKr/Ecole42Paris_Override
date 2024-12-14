# LEVEL06
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level06/level06
```
---
```sh
level06@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level06 level06   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level06 level06  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level06 level06 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level07 users   7907 Sep 10  2016 level06
-rw-r--r--+ 1 level06 level06   41 Oct 19  2016 .pass
-rw-r--r--  1 level06 level06  675 Sep 10  2016 .profile
level06@OverRide:~$ ./level06
***********************************
*               level06           *
***********************************
-> Enter Login: 42
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 42
```
We can find one excutable file **level06**, who takes 2 standard input Login and Serial. \
Check it with GDB. \
\
The program itself has some tangled algorithm, which looks horrible at first sight on machine code. \
There was ```ptrace()``` function inside ```auth()``` function, which was blocking GDB by printing "tampering detected" and immediately exited the program. \
So, we found some solution for to avoid ptrace signal catch by GDB
```sh
(gdb) catch syscall ptrace
Catchpoint 1 (syscall 'ptrace' [26])
(gdb) commands 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>set $eax=0
>continue
>end
```
With that, we can forcely jump over ptrace signal detection so we can the value of the result of the algorithm at ```auth+286```. \
```sh
(gdb) disas auth
   ...
   0x08048866 <+286>:   cmp    -0x10(%ebp),%eax # if (value == u_int)
   ...
```
The algorithm in the function ```auth()```, it calculates from our input of login, and compares it with the value of pre-calculated in ```auth()``` functions. \
We put some login, and the Serial is not important, cause ```u_int``` is our input - Serial.
So we put the breakpoint at ```auth+286``` to see what value is inside will be compared.
```sh
(gdb) b *auth+286
Breakpoint 2 at 0x8048866
(gdb) r
Starting program: /home/users/level06/level06 
***********************************
*               level06           *
***********************************
-> Enter Login: hello42  
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 4242   # can put anything                  
```
By skipping those "traps" we actually can we what value is calculated with our input ```hello42```.
```sh
Catchpoint 1 (call to syscall ptrace), 0xf7fdb440 in __kernel_vsyscall ()

Catchpoint 1 (returned from syscall ptrace), 0xf7fdb440 in __kernel_vsyscall ()

Breakpoint 2, 0x08048866 in auth ()
(gdb) x/d $ebp-0x10
0xffffd678:     6233701 # value pre-calculated
```
That's our serial that we can use together with the same login ```hello42```.
```sh
level06@OverRide:~$ ./level06 
***********************************
*               level06           *
***********************************
-> Enter Login: hello42
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6233701
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
(hidden)
```
level06 passed !


assmebly analyze
---

```sh
(gdb) disas auth
Dump of assembler code for function auth:
   0x08048748 <+0>:     push   %ebp
   0x08048749 <+1>:     mov    %esp,%ebp
   0x0804874b <+3>:     sub    $0x28,%esp # 40
   0x0804874e <+6>:     movl   $0x8048a63,0x4(%esp) # "\n"
   0x08048756 <+14>:    mov    0x8(%ebp),%eax # first parameter, str[32]
   0x08048759 <+17>:    mov    %eax,(%esp)
   0x0804875c <+20>:    call   0x8048520 <strcspn@plt> # strcspn(str[32], "\n")
   0x08048761 <+25>:    add    0x8(%ebp),%eax # str[strcspn return value] = 0
   0x08048764 <+28>:    movb   $0x0,(%eax) # 0
   0x08048767 <+31>:    movl   $0x20,0x4(%esp) # 32
   0x0804876f <+39>:    mov    0x8(%ebp),%eax # str
   0x08048772 <+42>:    mov    %eax,(%esp)
   0x08048775 <+45>:    call   0x80485d0 <strnlen@plt> # strnlen(str, 32)
   0x0804877a <+50>:    mov    %eax,-0xc(%ebp) # save return value in variable, len
   0x0804877d <+53>:    push   %eax # canary
   0x0804877e <+54>:    xor    %eax,%eax # canary
   0x08048780 <+56>:    je     0x8048785 <auth+61> # canary
   0x08048782 <+58>:    add    $0x4,%esp # canary
   0x08048785 <+61>:    pop    %eax # canary
   0x08048786 <+62>:    cmpl   $0x5,-0xc(%ebp) # if (len <= 5)
   0x0804878a <+66>:    jg     0x8048796 <auth+78>
   0x0804878c <+68>:    mov    $0x1,%eax # return (1)
   0x08048791 <+73>:    jmp    0x8048877 <auth+303>
   0x08048796 <+78>:    movl   $0x0,0xc(%esp)
   0x0804879e <+86>:    movl   $0x1,0x8(%esp)
   0x080487a6 <+94>:    movl   $0x0,0x4(%esp)
   0x080487ae <+102>:   movl   $0x0,(%esp)
   0x080487b5 <+109>:   call   0x80485f0 <ptrace@plt> # ptrace(0, 0, 1, 0)
   0x080487ba <+114>:   cmp    $0xffffffff,%eax # if (ptrace() == -1)
   0x080487bd <+117>:   jne    0x80487ed <auth+165> # tampering detected block
   0x080487bf <+119>:   movl   $0x8048a68,(%esp) #  "\033[32m.", '-' <repeats 27 times>, "."
   0x080487c6 <+126>:   call   0x8048590 <puts@plt>
   0x080487cb <+131>:   movl   $0x8048a8c,(%esp) # "\033[31m| !! TAMPERING DETECTED !!  |"
   0x080487d2 <+138>:   call   0x8048590 <puts@plt>
   0x080487d7 <+143>:   movl   $0x8048ab0,(%esp) #  "\033[32m'", '-' <repeats 27 times>, "'"
   0x080487de <+150>:   call   0x8048590 <puts@plt>
   0x080487e3 <+155>:   mov    $0x1,%eax #  return (1)
   0x080487e8 <+160>:   jmp    0x8048877 <auth+303>
   0x080487ed <+165>:   mov    0x8(%ebp),%eax # str
   0x080487f0 <+168>:   add    $0x3,%eax # str[3]
   0x080487f3 <+171>:   movzbl (%eax),%eax # str[3]
   0x080487f6 <+174>:   movsbl %al,%eax # %al = str[3]
   0x080487f9 <+177>:   xor    $0x1337,%eax # str[3] ^ 4919
   0x080487fe <+182>:   add    $0x5eeded,%eax # str[3] ^ 4919 + 6221293
   0x08048803 <+187>:   mov    %eax,-0x10(%ebp) # save the value = str[3] ^ 4919 + 6221293
   0x08048806 <+190>:   movl   $0x0,-0x14(%ebp) # int i = 0
   0x0804880d <+197>:   jmp    0x804885b <auth+275> # loop
   0x0804880f <+199>:   mov    -0x14(%ebp),%eax # i
   0x08048812 <+202>:   add    0x8(%ebp),%eax # str[i]
   0x08048815 <+205>:   movzbl (%eax),%eax
   0x08048818 <+208>:   cmp    $0x1f,%al # if 
   0x0804881a <+210>:   jg     0x8048823 <auth+219>
   0x0804881c <+212>:   mov    $0x1,%eax # return (1)
   0x08048821 <+217>:   jmp    0x8048877 <auth+303>
   0x08048823 <+219>:   mov    -0x14(%ebp),%eax # int i
   0x08048826 <+222>:   add    0x8(%ebp),%eax # str[i]
   0x08048829 <+225>:   movzbl (%eax),%eax # 0000000000000000_00000000ffffffff
   0x0804882c <+228>:   movsbl %al,%eax # 0x7f || 0xff # type casting from char to u_int
   0x0804882f <+231>:   mov    %eax,%ecx # (unsigned int)str[i]
   0x08048831 <+233>:   xor    -0x10(%ebp),%ecx # value ^ (unsigned int)str[i]
   0x08048834 <+236>:   mov    $0x88233b2b,%edx # 2284010283
   0x08048839 <+241>:   mov    %ecx,%eax # (unsigned int)str[i]
   0x0804883b <+243>:   mul    %edx # eax lower 32; edx upper 32
   0x0804883d <+245>:   mov    %ecx,%eax # truncate lower 32 bit; (unsigned int)str[i]
   0x0804883f <+247>:   sub    %edx,%eax # upper 32 bit - value ^ (unsigned int)str[i]
   0x08048841 <+249>:   shr    %eax # upper 32 bit - value ^ (unsigned int)str[i] / 2
   0x08048843 <+251>:   add    %edx,%eax # upper 32 bit + (upper 32 bit - value ^ (unsigned int)str[i] / 2)
   0x08048845 <+253>:   shr    $0xa,%eax # / 1024 //same as bit shifting 10 to right
   0x08048848 <+256>:   imul   $0x539,%eax,%eax # * 1337
   0x0804884e <+262>:   mov    %ecx,%edx # (unsigned int)str[i]
   0x08048850 <+264>:   sub    %eax,%edx # result of line+256 - (unsigned int)str[i]
   0x08048852 <+266>:   mov    %edx,%eax
   0x08048854 <+268>:   add    %eax,-0x10(%ebp) # value + result of eax
   0x08048857 <+271>:   addl   $0x1,-0x14(%ebp) # i++
   0x0804885b <+275>:   mov    -0x14(%ebp),%eax # int i
   0x0804885e <+278>:   cmp    -0xc(%ebp),%eax # i < len
   0x08048861 <+281>:   jl     0x804880f <auth+199>
   0x08048863 <+283>:   mov    0xc(%ebp),%eax # second parameter u_int
   0x08048866 <+286>:   cmp    -0x10(%ebp),%eax # if (value == u_int)
   0x08048869 <+289>:   je     0x8048872 <auth+298>
   0x0804886b <+291>:   mov    $0x1,%eax # return (1)
   0x08048870 <+296>:   jmp    0x8048877 <auth+303>
   0x08048872 <+298>:   mov    $0x0,%eax # return (0)
   0x08048877 <+303>:   leave  
   0x08048878 <+304>:   ret    
End of assembler dump.
(gdb) disas main
Dump of assembler code for function main:
   0x08048879 <+0>:     push   %ebp
   0x0804887a <+1>:     mov    %esp,%ebp
   0x0804887c <+3>:     and    $0xfffffff0,%esp
   0x0804887f <+6>:     sub    $0x50,%esp # 80
   0x08048882 <+9>:     mov    0xc(%ebp),%eax # argv
   0x08048885 <+12>:    mov    %eax,0x1c(%esp) # str[28]
   0x08048889 <+16>:    mov    %gs:0x14,%eax # stack canary
   0x0804888f <+22>:    mov    %eax,0x4c(%esp)
   0x08048893 <+26>:    xor    %eax,%eax
   0x08048895 <+28>:    push   %eax
   0x08048896 <+29>:    xor    %eax,%eax
   0x08048898 <+31>:    je     0x804889d <main+36>
   0x0804889a <+33>:    add    $0x4,%esp # end stack canary
   0x0804889d <+36>:    pop    %eax
   0x0804889e <+37>:    movl   $0x8048ad4,(%esp) # '*' <repeats 35 times> 
   0x080488a5 <+44>:    call   0x8048590 <puts@plt>
   0x080488aa <+49>:    movl   $0x8048af8,(%esp) # "*\t\tlevel06\t\t  *"
   0x080488b1 <+56>:    call   0x8048590 <puts@plt>
   0x080488b6 <+61>:    movl   $0x8048ad4,(%esp) # "-> Enter Login: "
   0x080488bd <+68>:    call   0x8048590 <puts@plt>
   0x080488c2 <+73>:    mov    $0x8048b08,%eax # "-> Enter Login: "
   0x080488c7 <+78>:    mov    %eax,(%esp)
   0x080488ca <+81>:    call   0x8048510 <printf@plt>
   0x080488cf <+86>:    mov    0x804a060,%eax # stdin
   0x080488d4 <+91>:    mov    %eax,0x8(%esp)
   0x080488d8 <+95>:    movl   $0x20,0x4(%esp) # 32
   0x080488e0 <+103>:   lea    0x2c(%esp),%eax # str[32]
   0x080488e4 <+107>:   mov    %eax,(%esp)
   0x080488e7 <+110>:   call   0x8048550 <fgets@plt> # fgets(str[32], 32, stdin)
   0x080488ec <+115>:   movl   $0x8048ad4,(%esp) # '*' <repeats 35 times>
   0x080488f3 <+122>:   call   0x8048590 <puts@plt>
   0x080488f8 <+127>:   movl   $0x8048b1c,(%esp) # "***** NEW ACCOUNT DETECTED ********"
   0x080488ff <+134>:   call   0x8048590 <puts@plt>
   0x08048904 <+139>:   movl   $0x8048ad4,(%esp) # '*' <repeats 35 times>
   0x0804890b <+146>:   call   0x8048590 <puts@plt>
   0x08048910 <+151>:   mov    $0x8048b40,%eax # "-> Enter Serial: "
   0x08048915 <+156>:   mov    %eax,(%esp)
   0x08048918 <+159>:   call   0x8048510 <printf@plt>
   0x0804891d <+164>:   mov    $0x8048a60,%eax
   0x08048922 <+169>:   lea    0x28(%esp),%edx # var u_int # 4
   0x08048926 <+173>:   mov    %edx,0x4(%esp)
   0x0804892a <+177>:   mov    %eax,(%esp)
   0x0804892d <+180>:   call   0x80485e0 <__isoc99_scanf@plt> # scanf("%u", &var u_int)
   0x08048932 <+185>:   mov    0x28(%esp),%eax # var u_int
   0x08048936 <+189>:   mov    %eax,0x4(%esp)
   0x0804893a <+193>:   lea    0x2c(%esp),%eax # str[32]
   0x0804893e <+197>:   mov    %eax,(%esp)
   0x08048941 <+200>:   call   0x8048748 <auth> # auth(str[32], u_int)
   0x08048946 <+205>:   test   %eax,%eax
   0x08048948 <+207>:   jne    0x8048969 <main+240>
   0x0804894a <+209>:   movl   $0x8048b52,(%esp) # "Authenticated!"
   0x08048951 <+216>:   call   0x8048590 <puts@plt>
   0x08048956 <+221>:   movl   $0x8048b61,(%esp) # "/bin/sh"
   0x0804895d <+228>:   call   0x80485a0 <system@plt> # system("/bin/sh")
   0x08048962 <+233>:   mov    $0x0,%eax # return (0)
   0x08048967 <+238>:   jmp    0x804896e <main+245>
   0x08048969 <+240>:   mov    $0x1,%eax # return (1)
   0x0804896e <+245>:   mov    0x4c(%esp),%edx # stack canary
   0x08048972 <+249>:   xor    %gs:0x14,%edx
   0x08048979 <+256>:   je     0x8048980 <main+263>
   0x0804897b <+258>:   call   0x8048580 <__stack_chk_fail@plt> # stack canary check
   0x08048980 <+263>:   leave  
   0x08048981 <+264>:   ret    
End of assembler dump.
```
