#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char username[96];
	char file_buffer[48];
	char password[96];
	FILE *stream;
	int ret;

	memset(username, 0, 96);
	memset(file_buffer, 0, 40);
	memset(password, 0, 96);
	stream = fopen("/home/users/level03/.pass", "r");
	if (!stream)
	{
		fwrite("ERROR: failed to open password file\n", 1, 36, stderr);
		exit(1);
	}
	ret = fread(file_buffer, 1, 41, stream);
	file_buffer[strcspn(file_buffer, "\n")] = 0;
	if (ret != 41)
	{
		fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
		fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
		exit(1);
	}
	fclose(stream);
	puts("===== [ Secure Access System v1.0 ] =====");
	puts("/***************************************\\");
	puts("| You must login to access this system. |");
	puts("\\**************************************/");
	printf("--[ Username: ");
	fgets(username, 100, stdin);
	username[strcspn(username, "\n")] = 0;
	printf("--[ Password: ");
	fgets(password, 100, stdin);
	password[strcspn(password, "\n")] = 0;
	puts("*****************************************");
	if (strncmp(file_buffer, password, 40))
	{
		printf(username);
		puts(" does not have access!");
		exit(1);
	}
	printf("Greetings, %s!\n", username);
	system("/bin/sh");
	return (0);
}