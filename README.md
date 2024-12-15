# Ecole42Paris_Override
We have to run RainFall.iso file in VM, and connect with ssh with ip which is displayed in the VM.
```bash
$> ssh level0@[ip] -p 4242
```
```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level00/level00
```
With this text, you are succeed of login. 


Flags
---
#### GCC stack protector 
- the logic of protect of stack buffer overflow.
- usually insert Canary value in the return stack address.
- if there was attempt of attack stack, we can check Canary value it was corrupted.

#### Strict user copy checks
- strict user copy checks (also know as CONFIG_DEBUG_STRICT_USER_COPY_CHECKS) isn't implemented on x86_64 
[Ref.](https://lore.kernel.org/lkml/1306865673-20560-1-git-send-email-sboyd@codeaurora.org/T/)

#### Restrict /dev/mem /dev/kmem Access
- in the linux, /dev/mem and /dev/kmem is **physical memory** address.
- the role of access physical memory.

#### grsecurity / Pax
- both of them is some patch security of linux.
- protect vulnerability of kernel, protect memory, protect attack of permission.

#### Kernel Heap Hardening
- with reinforce of kernel heap memory, can protect memory vulnerability like heap buffer over flow.

#### System-wide ASLR (kernel.randomize_va_space)
- ASLR(Addrerss Space Layout Randomization), by this, its hard to attack the binary file like exploit(especially return-to-libarary).
[Ref.](https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/)

#### Security configuration of binary file
|Name|Description|
|-----|---|
|RELRO|Relocation Read-only, option of memory protect while running.|
|Stack canary|Option of protect of buffer overflow.|
|NX|Non-Executable, Option of memory protect.|
|PIE|Position Independent Executable, fix library address position.|
|Rpath / Runpath|Path of runtime library.|

Reference
---
- [Register usage](https://stackoverflow.com/questions/18024672/what-registers-are-preserved-through-a-linux-x86-64-function-call)
- [Calling convention](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html#:~:text=call%20%3Clabel%3E%0Aret-,Calling%20Convention,-To%20allow%20separate)
- [Why always back eip address when function calling](https://stackoverflow.com/questions/66092133/memory-stack-sub-20-from-esp)
- [Jump flags](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)
- [What is plt and got](https://ir0nstone.gitbook.io/notes/binexp/stack/aslr/plt_and_got)
