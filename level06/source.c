#include <sys/ptrace.h>
#include <stdio.h>
#include <stdint.h>


int auth(char *login_str, unsigned int serial) // ebp + 0x8 ; ebp + 0xc
{
	size_t login_len; // EBP - 0xc

	login_str[strcspn(login_str, "\n")] = 0;
	login_len = strnlen(login_str, 32);
	
	if (login_len <= 5) {
		return 1;
	}
	if (ptrace(0, 0, 1, 0) == -1) {
		puts("\e[32m.---------------------------.");
		puts("\e[31m| !! TAMPERING DETECTED !!  |");
		puts("\e[32m.---------------------------.");
		return 1;
	}
	
	int hash; // EBP - 0x10
	hash = ((int) (login_str[3])) ^ 0x1337 + 0x5eeded; 

	for (int i = 0; i < login_len; i++) { // i at EBP - 0x14
		if (login_str[i] <= 31)	// '1'
			return 1;
		
		// Algorythm translated to code
		int tmp1 = login_str[i] ^ hash;
        int tmp2 = 0x88233b2b * tmp1;
		int tmp3 = (tmp1 - tmp2) / 2;
        int tmp4 = (tmp3 + tmp2) / 1024 * 0x539; // /1024 is same as SHR 10
        hash += tmp1 - tmp4;
	}
	
	if (hash == serial)
		return 0;
	else
		return 1;
}


int auth(char *str, int u_int)
{
	int i;
	int value;
	int len;

	str[strcspn(str, "\n")] = 0;
	len = strnlen(str, 32);
	if (len <= 5)
		return (1);
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
	{
		puts("\x1B[32m.---------------------------.");
		puts("\x1B[31m| !! TAMPERING DETECTED !!  |");
		puts("\x1B[32m'---------------------------'");
		return 1;
	}
	else
	{
		value = (str[3] ^ 4919) + 6221293;
		for (i = 0; i < len; ++i)
		{
			if (str[i] <= 0x31) // 49
				return (1);
			int n1 = (unsigned int)str[i];
			int n2 = n1 ^ value;
			uint64_t n3 = n2 * 2284010283U;
			int n4 = (int)(n3 >> 32);
			n2 -= n4 * 1337;
			value += n2;
		}
		if (value == u_int)
			return (0);
		return (1);
	}
}

int main(void)
{
	unsigned int u_int;
	char str[32];

	puts("***********************************");
	puts("*\t\tlevel06\t\t  *");
	puts("***********************************");
	printf("-> Enter Login: ");
	fgets(str, 32, stdin);
	puts("***********************************");
	puts("***** NEW ACCOUNT DETECTED ********");
	puts("***********************************");
	printf("-> Enter Serial: ");
	scanf("%u", &u_int);
	if (auth(str, u_int))
		return (1);
	puts("Authenticated!");
	system("/bin/sh");
	return (0);
}