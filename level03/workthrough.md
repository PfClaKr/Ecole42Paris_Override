# LEVEL03
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level03/level03
```
---
```sh
level03@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level03 level03   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level03 level03  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level03 level03 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level04 users   7677 Sep 10  2016 level03
-rw-r--r--+ 1 level03 level03   41 Oct 19  2016 .pass
-rw-r--r--  1 level03 level03  675 Sep 10  2016 .profile
level03@OverRide:~$ ./level03
***********************************
*               level03         **
***********************************
Password:42

Invalid Password
```
We can find one excutable file **level03**, who take standard input with Password. \
\
Check it with GDB,
```sh
(gdb) info functions
...
0x08048660  decrypt
0x08048747  test
0x0804885a  main
...
```
Let's start with analyzing the code. \
We can see that a variable of type int, let's name it password, is taking our only input, then it will be later compared with some predefined constant number ```322424845```, then it will be passed to function ```test```.
```sh
   0x080488c6 <+108>:   mov    0x1c(%esp),%eax
   0x080488ca <+112>:   movl   $0x1337d00d,0x4(%esp) # 322424845
   0x080488d2 <+120>:   mov    %eax,(%esp)
   0x080488d5 <+123>:   call   0x8048747 <test> # test(var int, 322424845)
```
In this function we can find switch statement. It has 1~9 16~21 cases and we can verify them by looking at the jump table
```sh
0x0804876c <+37>:    add    $0x80489f0,%eax
...
(gdb) x/30x 0x80489f0
				default			1				2				3
0x80489f0:      0x0804884a      0x08048775      0x08048785      0x08048795
				4				5				6				7
0x8048a00:      0x080487a5      0x080487b5      0x080487c5      0x080487d5
				8				9				10(default)		11(default)
0x8048a10:      0x080487e2      0x080487ef      0x0804884a      0x0804884a
				12(default)		13(default)		14(default)		15(default)
0x8048a20:      0x0804884a      0x0804884a      0x0804884a      0x0804884a
				16				17				18				19
0x8048a30:      0x080487fc      0x08048809      0x08048816      0x08048823
				20				21				end
0x8048a40:      0x08048830      0x0804883d      0x2a2a2a2a      0x2a2a2a2a
0x8048a50:      0x2a2a2a2a      0x2a2a2a2a      0x2a2a2a2a      0x2a2a2a2a
```
So it does mean that constant number ```322424845``` substract our password is the case we are going in, to the function ```decrypt```. \
So we try to get inside of every case by "brute forcing" it. \
To achive this we simply substract offset from the number ```322424845```. \
We can make it easier by writing a python script and find all results.
Found at 18. By giving input ```322424827``` will give us a ```/bin/sh```. \
Now we can find our flag
```sh
level03@OverRide:~$ ./level03 
***********************************
*               level03         **
***********************************
Password:322424827
$ cat /home/users/level04/.pass
(hidden)
$ 
level03@OverRide:~$ su level04
Password: 
```
level03 passed !

assmebly analyze
---

```sh
(gdb) disas decrypt
Dump of assembler code for function decrypt:
   0x08048660 <+0>:     push   %ebp
   0x08048661 <+1>:     mov    %esp,%ebp
   0x08048663 <+3>:     push   %edi
   0x08048664 <+4>:     push   %esi
   0x08048665 <+5>:     sub    $0x40,%esp # 64
   0x08048668 <+8>:     mov    %gs:0x14,%eax # gs: segment register for check canary stack.
   0x0804866e <+14>:    mov    %eax,-0xc(%ebp) # save stack canary
   0x08048671 <+17>:    xor    %eax,%eax # reset eax
   0x08048673 <+19>:    movl   $0x757c7d51,-0x1d(%ebp) # "u|}Q"
   0x0804867a <+26>:    movl   $0x67667360,-0x19(%ebp) # "gfs`"
   0x08048681 <+33>:    movl   $0x7b66737e,-0x15(%ebp) # "{fs~"
   0x08048688 <+40>:    movl   $0x33617c7d,-0x11(%ebp) # "3a|}"
   0x0804868f <+47>:    movb   $0x0,-0xd(%ebp) # 0 # var str = "Q}|u`sfg~sf{}|a3" # strcpy(str, "Q}|u`sfg~sf{}|a3")
   0x08048693 <+51>:    push   %eax
   0x08048694 <+52>:    xor    %eax,%eax
   0x08048696 <+54>:    je     0x804869b <decrypt+59>
   0x08048698 <+56>:    add    $0x4,%esp
   0x0804869b <+59>:    pop    %eax
   0x0804869c <+60>:    lea    -0x1d(%ebp),%eax
   0x0804869f <+63>:    movl   $0xffffffff,-0x2c(%ebp)
   0x080486a6 <+70>:    mov    %eax,%edx
   0x080486a8 <+72>:    mov    $0x0,%eax
   0x080486ad <+77>:    mov    -0x2c(%ebp),%ecx
   0x080486b0 <+80>:    mov    %edx,%edi
   0x080486b2 <+82>:    repnz scas %es:(%edi),%al # strlen("Q}|u`sfg~sf{}|a3")
   0x080486b4 <+84>:    mov    %ecx,%eax # result of strlen
   0x080486b6 <+86>:    not    %eax
   0x080486b8 <+88>:    sub    $0x1,%eax
   0x080486bb <+91>:    mov    %eax,-0x24(%ebp) # save retrun of strlen
   0x080486be <+94>:    movl   $0x0,-0x28(%ebp) # 0 for (i = 0; i < strlen("Q}|u`sfg~sf{}|a3"); i++)
   0x080486c5 <+101>:   jmp    0x80486e5 <decrypt+133>
   0x080486c7 <+103>:   lea    -0x1d(%ebp),%eax # beginning of loop
   0x080486ca <+106>:   add    -0x28(%ebp),%eax # str[i]
   0x080486cd <+109>:   movzbl (%eax),%eax
   0x080486d0 <+112>:   mov    %eax,%edx # *str + i
   0x080486d2 <+114>:   mov    0x8(%ebp),%eax # first parameter
   0x080486d5 <+117>:   xor    %edx,%eax # str[i] ^= first parameter
   0x080486d7 <+119>:   mov    %eax,%edx
   0x080486d9 <+121>:   lea    -0x1d(%ebp),%eax # ^= ? 0x1d is str and add 40?
   0x080486dc <+124>:   add    -0x28(%ebp),%eax # who is this
   0x080486df <+127>:   mov    %dl,(%eax)
   0x080486e1 <+129>:   addl   $0x1,-0x28(%ebp) # i++
   0x080486e5 <+133>:   mov    -0x28(%ebp),%eax
   0x080486e8 <+136>:   cmp    -0x24(%ebp),%eax # strlen("Q}|u`sfg~sf{}|a3", i)
   0x080486eb <+139>:   jb     0x80486c7 <decrypt+103> # <
   0x080486ed <+141>:   lea    -0x1d(%ebp),%eax # var str
   0x080486f0 <+144>:   mov    %eax,%edx
   0x080486f2 <+146>:   mov    $0x80489c3,%eax # "Congratulations!"
   0x080486f7 <+151>:   mov    $0x11,%ecx
   0x080486fc <+156>:   mov    %edx,%esi
   0x080486fe <+158>:   mov    %eax,%edi
   0x08048700 <+160>:   repz cmpsb %es:(%edi),%ds:(%esi) # strcmp(var str, "Congratulations!")
   0x08048702 <+162>:   seta   %dl
   0x08048705 <+165>:   setb   %al
   0x08048708 <+168>:   mov    %edx,%ecx
   0x0804870a <+170>:   sub    %al,%cl
   0x0804870c <+172>:   mov    %ecx,%eax
   0x0804870e <+174>:   movsbl %al,%eax
   0x08048711 <+177>:   test   %eax,%eax # if (strcmp(var str, "Congratulations!") == 0)
   0x08048713 <+179>:   jne    0x8048723 <decrypt+195>
   0x08048715 <+181>:   movl   $0x80489d4,(%esp) #  "/bin/sh"
   0x0804871c <+188>:   call   0x80484e0 <system@plt>
   0x08048721 <+193>:   jmp    0x804872f <decrypt+207>
   0x08048723 <+195>:   movl   $0x80489dc,(%esp) # "\nInvalid Password"
   0x0804872a <+202>:   call   0x80484d0 <puts@plt>
   0x0804872f <+207>:   mov    -0xc(%ebp),%esi
   0x08048732 <+210>:   xor    %gs:0x14,%esi # canary value check
   0x08048739 <+217>:   je     0x8048740 <decrypt+224>
   0x0804873b <+219>:   call   0x80484c0 <__stack_chk_fail@plt> # canary stack check
   0x08048740 <+224>:   add    $0x40,%esp # restore stack frame
   0x08048743 <+227>:   pop    %esi
   0x08048744 <+228>:   pop    %edi
   0x08048745 <+229>:   pop    %ebp
   0x08048746 <+230>:   ret    
End of assembler dump.
```
```sh
(gdb) disas test
Dump of assembler code for function test:
   0x08048747 <+0>:     push   %ebp
   0x08048748 <+1>:     mov    %esp,%ebp
   0x0804874a <+3>:     sub    $0x28,%esp
   0x0804874d <+6>:     mov    0x8(%ebp),%eax # first parameter # var int
   0x08048750 <+9>:     mov    0xc(%ebp),%edx # second parameter# 322424845
   0x08048753 <+12>:    mov    %edx,%ecx
   0x08048755 <+14>:    sub    %eax,%ecx # 322424845 - var int
   0x08048757 <+16>:    mov    %ecx,%eax
   0x08048759 <+18>:    mov    %eax,-0xc(%ebp) # switch(var int - 322424845)
   0x0804875c <+21>:    cmpl   $0x15,-0xc(%ebp) # maximum case == 21
   0x08048760 <+25>:    ja     0x804884a <test+259> # go to default
   0x08048766 <+31>:    mov    -0xc(%ebp),%eax
   0x08048769 <+34>:    shl    $0x2,%eax # (p2 - p1) << 2
   0x0804876c <+37>:    add    $0x80489f0,%eax # address of switch table
   0x08048771 <+42>:    mov    (%eax),%eax
   0x08048773 <+44>:    jmp    *%eax
   0x08048775 <+46>:    mov    -0xc(%ebp),%eax
   0x08048778 <+49>:    mov    %eax,(%esp)
   0x0804877b <+52>:    call   0x8048660 <decrypt>
   0x08048780 <+57>:    jmp    0x8048858 <test+273>
   0x08048785 <+62>:    mov    -0xc(%ebp),%eax
   0x08048788 <+65>:    mov    %eax,(%esp)
   0x0804878b <+68>:    call   0x8048660 <decrypt>
   0x08048790 <+73>:    jmp    0x8048858 <test+273>
   0x08048795 <+78>:    mov    -0xc(%ebp),%eax
   0x08048798 <+81>:    mov    %eax,(%esp)
   0x0804879b <+84>:    call   0x8048660 <decrypt>
   0x080487a0 <+89>:    jmp    0x8048858 <test+273>
   0x080487a5 <+94>:    mov    -0xc(%ebp),%eax
   0x080487a8 <+97>:    mov    %eax,(%esp)
   0x080487ab <+100>:   call   0x8048660 <decrypt>
   0x080487b0 <+105>:   jmp    0x8048858 <test+273>
   0x080487b5 <+110>:   mov    -0xc(%ebp),%eax
   0x080487b8 <+113>:   mov    %eax,(%esp)
   0x080487bb <+116>:   call   0x8048660 <decrypt>
   0x080487c0 <+121>:   jmp    0x8048858 <test+273>
   0x080487c5 <+126>:   mov    -0xc(%ebp),%eax
   0x080487c8 <+129>:   mov    %eax,(%esp)
   0x080487cb <+132>:   call   0x8048660 <decrypt>
   0x080487d0 <+137>:   jmp    0x8048858 <test+273>
   0x080487d5 <+142>:   mov    -0xc(%ebp),%eax
   0x080487d8 <+145>:   mov    %eax,(%esp)
   0x080487db <+148>:   call   0x8048660 <decrypt>
   0x080487e0 <+153>:   jmp    0x8048858 <test+273>
   0x080487e2 <+155>:   mov    -0xc(%ebp),%eax
   0x080487e5 <+158>:   mov    %eax,(%esp)
   0x080487e8 <+161>:   call   0x8048660 <decrypt>
   0x080487ed <+166>:   jmp    0x8048858 <test+273>
   0x080487ef <+168>:   mov    -0xc(%ebp),%eax
   0x080487f2 <+171>:   mov    %eax,(%esp)
   0x080487f5 <+174>:   call   0x8048660 <decrypt>
   0x080487fa <+179>:   jmp    0x8048858 <test+273>
   0x080487fc <+181>:   mov    -0xc(%ebp),%eax
   0x080487ff <+184>:   mov    %eax,(%esp)
   0x08048802 <+187>:   call   0x8048660 <decrypt>
   0x08048807 <+192>:   jmp    0x8048858 <test+273>
   0x08048809 <+194>:   mov    -0xc(%ebp),%eax
   0x0804880c <+197>:   mov    %eax,(%esp)
   0x0804880f <+200>:   call   0x8048660 <decrypt>
   0x08048814 <+205>:   jmp    0x8048858 <test+273>
   0x08048816 <+207>:   mov    -0xc(%ebp),%eax
   0x08048819 <+210>:   mov    %eax,(%esp)
   0x0804881c <+213>:   call   0x8048660 <decrypt>
   0x08048821 <+218>:   jmp    0x8048858 <test+273>
   0x08048823 <+220>:   mov    -0xc(%ebp),%eax
   0x08048826 <+223>:   mov    %eax,(%esp)
   0x08048829 <+226>:   call   0x8048660 <decrypt>
   0x0804882e <+231>:   jmp    0x8048858 <test+273>
   0x08048830 <+233>:   mov    -0xc(%ebp),%eax
   0x08048833 <+236>:   mov    %eax,(%esp)
   0x08048836 <+239>:   call   0x8048660 <decrypt>
   0x0804883b <+244>:   jmp    0x8048858 <test+273>
   0x0804883d <+246>:   mov    -0xc(%ebp),%eax
   0x08048840 <+249>:   mov    %eax,(%esp)
   0x08048843 <+252>:   call   0x8048660 <decrypt>
   0x08048848 <+257>:   jmp    0x8048858 <test+273>
   0x0804884a <+259>:   call   0x8048520 <rand@plt> # default:
   0x0804884f <+264>:   mov    %eax,(%esp)
   0x08048852 <+267>:   call   0x8048660 <decrypt>
   0x08048857 <+272>:   nop
   0x08048858 <+273>:   leave  
   0x08048859 <+274>:   ret    
End of assembler dump.
```
```sh
(gdb) disas main
Dump of assembler code for function main:
   0x0804885a <+0>:     push   %ebp
   0x0804885b <+1>:     mov    %esp,%ebp
   0x0804885d <+3>:     and    $0xfffffff0,%esp
   0x08048860 <+6>:     sub    $0x20,%esp # 32
   0x08048863 <+9>:     push   %eax
   0x08048864 <+10>:    xor    %eax,%eax
   0x08048866 <+12>:    je     0x804886b <main+17>
   0x08048868 <+14>:    add    $0x4,%esp # 28
   0x0804886b <+17>:    pop    %eax
   0x0804886c <+18>:    movl   $0x0,(%esp)
   0x08048873 <+25>:    call   0x80484b0 <time@plt> # time(0)
   0x08048878 <+30>:    mov    %eax,(%esp)
   0x0804887b <+33>:    call   0x8048500 <srand@plt> # srand(time(0))
   0x08048880 <+38>:    movl   $0x8048a48,(%esp) # '*' <repeats 35 times>
   0x08048887 <+45>:    call   0x80484d0 <puts@plt>
   0x0804888c <+50>:    movl   $0x8048a6c,(%esp) #  "*\t\tlevel03\t\t**"
   0x08048893 <+57>:    call   0x80484d0 <puts@plt>
   0x08048898 <+62>:    movl   $0x8048a48,(%esp) # '*' <repeats 35 times>
   0x0804889f <+69>:    call   0x80484d0 <puts@plt>
   0x080488a4 <+74>:    mov    $0x8048a7b,%eax #  "Password:"
   0x080488a9 <+79>:    mov    %eax,(%esp)
   0x080488ac <+82>:    call   0x8048480 <printf@plt>
   0x080488b1 <+87>:    mov    $0x8048a85,%eax # "%d"
   0x080488b6 <+92>:    lea    0x1c(%esp),%edx # variable int
   0x080488ba <+96>:    mov    %edx,0x4(%esp)
   0x080488be <+100>:   mov    %eax,(%esp)
   0x080488c1 <+103>:   call   0x8048530 <__isoc99_scanf@plt> # scanf("%d", variable int)
   0x080488c6 <+108>:   mov    0x1c(%esp),%eax
   0x080488ca <+112>:   movl   $0x1337d00d,0x4(%esp) # 322424845
   0x080488d2 <+120>:   mov    %eax,(%esp)
   0x080488d5 <+123>:   call   0x8048747 <test> # test(var int, 322424845)
   0x080488da <+128>:   mov    $0x0,%eax
   0x080488df <+133>:   leave  
   0x080488e0 <+134>:   ret    
End of assembler dump.
```
