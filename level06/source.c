#include <sys/ptrace.h>
#include <stdio.h>
#include <stdint.h>

int auth(char *str, unsigned int u_int)
{
	unsigned int len;

	str[strcspn(str, "\n")] = 0;
	len = strnlen(str, 32);
	if (len <= 5)
	{
		return (1);
	}
	if (ptrace(0, 0, 1, 0) == -1)
	{
		puts("\e[32m.---------------------------.");
		puts("\e[31m| !! TAMPERING DETECTED !!  |");
		puts("\e[32m.---------------------------.");
		return (1);
	}
	int secret = ((int)(str[3])) ^ 0x1337 + 0x5eeded; 

	for (int i = 0; i < len; i++)
	{
		if (str[i] <= 31)	// 49 '1'
		{
			return (1);
		}
		int n1 = str[i] ^ secret;
        int n2 = 0x88233b2b * n1;
		int n3 = (n1 - n2) / 2;
        int n4 = (n3 + n2) / 1024 * 0x539;
        secret += n1 - n4;
	}
	if (secret == u_int)
	{
		return (0);
	}
	else
	{
		return (1);
	}
}

int main()
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
	{
		return (1);
	}
	puts("Authenticated!");
	system("/bin/sh");
	return (0);
}
