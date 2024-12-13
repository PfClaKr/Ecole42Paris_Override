#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void decrypt(char parameter)
{
	unsigned int i;
	char str[16];

	strcpy(str, "Q}|u`sfg~sf{}|a3");
	for (i = 0; i < strlen(str); i++)
		str[i] ^= parameter;
	if (strcmp(str, "Congratulations!") == 0)
	{
		puts("\nInvalid Password");
		return;
	}
	else
	{
		system("/bin/sh");
		return;
	}
}

void test(int a1, int a2)
{
	switch (a2 - a1)
	{
	case 1:
		decrypt(a2 - a1);
		break;
	case 2:
		decrypt(a2 - a1);
		break;
	case 3:
		decrypt(a2 - a1);
		break;
	case 4:
		decrypt(a2 - a1);
		break;
	case 5:
		decrypt(a2 - a1);
		break;
	case 6:
		decrypt(a2 - a1);
		break;
	case 7:
		decrypt(a2 - a1);
		break;
	case 8:
		decrypt(a2 - a1);
		break;
	case 9:
		decrypt(a2 - a1);
		break;
	case 16:
		decrypt(a2 - a1);
		break;
	case 17:
		decrypt(a2 - a1);
		break;
	case 18:
		decrypt(a2 - a1);
		break;
	case 19:
		decrypt(a2 - a1);
		break;
	case 20:
		decrypt(a2 - a1);
		break;
	case 21:
		decrypt(a2 - a1);
		break;
	default:
		decrypt(rand());
		break;
	}
	return;
}

int main(void)
{
	int nb;

	srand(time(0));
	puts("***********************************");
	puts("*\t\tlevel03\t\t**");
	puts("***********************************");
	printf("Password:");
	scanf("%d", &nb);
	test(nb, 322424845);
	return (0);
}