#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char a_user_name[100];

int verify_user_name(void)
{
	puts("verifying username....\n");
	return memcmp(a_user_name, "dat_wil", 7);
}

int verify_user_pass(void *str)
{
	return memcmp(str, "admin", 5);
}

int main(void)
{
	char buffer[64];
	int ret;

	memset(&buffer, 0, sizeof(buffer));
	puts("********* ADMIN LOGIN PROMPT ***…");
	printf("Enter Username: ");
	fgets(&a_user_name, 256, stdin);
	if (verify_user_name() != 0)
	{
		puts("nope, incorrect username...\n");
		return (1);
	}
	else
	{
		puts("Enter Password: ");
		fgets(&buffer, 100, stdin);
		int result = verify_user_pass(&buffer);
		if (result == 0)
		{
			puts("nope, incorrect password...\n");
			return (1);
		}
		if (result == 0)
		{
			return (0);
		}
	}
	return (0);
}