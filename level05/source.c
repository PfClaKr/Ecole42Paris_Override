#include <unistd.h>
#include <stdio.h>

int main()
{
	char str[100];
	int i;

	i = 0;
	fgets(str, 100, stdin);
	for (i = 0; i < strlen(str); i++)
	{
		if (str[i] > 64 && str[i] <= 90)
			str[i] ^= 32;
	}
	printf(str);
	exit(0);
}