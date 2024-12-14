#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void clear_stdin()
{
	char byte = 0;

	while (1)
	{
		byte = getchar();
		if (byte == '\n' || byte == -1)
			break;
	}
}

unsigned int get_unum()
{
	unsigned int nb;

	fflush(stdout);
	scanf("%u", &nb);
	clear_stdin();
	return (nb);
}

int store_number(char *str)
{
	unsigned int nb = 0;
	unsigned int nb1 = 0;

	printf(" Number: ");
	nb = get_unum();
	printf(" Index: ");
	nb1 = get_unum();
	if (nb1 % 3 == 0 || (nb >> 24) == 0xb7)
	{
		puts(" *** ERROR! ***");
		puts("   This index is reserved for wil!");
		puts(" *** ERROR! ***");
		return (1);
	}
	*(unsigned int *)(str + nb1 * 4) = nb;
	return (0);
}

int read_number(char *str)
{
	unsigned int nb;

	printf(" Index: ");
	nb = get_unum();
	printf(" Number at data[%u] is %u\n", nb, *(unsigned int *)(str + nb * 4));
	return (0);
}

int main(int ac, char **av, char **env)
{
	char str[400];
	char str2[20] = {0};
	int ret = 0;

	memset(str, 0, 400);
	while (*av)
	{
		memset(*av, 0, strlen(*av));
		av++;
	}
	while (*env)
	{
		memset(*env, 0, strlen(*env));
		env++;
	}
	puts("----------------------------------------------------\n  Welcome to wil's crappy number storage service!   \n----------------------------------------------------\n Commands:                                          \n    store - store a number into the data storage    \n    read  - read a number from the data storage     \n    quit  - exit the program                        \n----------------------------------------------------\n   wil has reserved some storage :>                 \n----------------------------------------------------\n");
	while (1)
	{
		printf("Input command: ");
		ret = 1;
		fgets(str2, 20, stdin);
		str2[strlen(str2) - 1] = 0;
		if (strncmp(str2, "store", 5) == 0)
			ret = store_number(str);
		else if (strncmp(str2, "read", 4) == 0)
			ret = read_number(str);
		else if (strncmp(str2, "quit", 4) == 0)
			break;
		if (ret == 0)
			printf(" Completed %s command successfully\n", str2);
		else
			printf(" Failed to do %s command\n", str2);
	}
	return (0);
}