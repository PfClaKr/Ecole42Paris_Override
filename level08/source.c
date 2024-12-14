#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

void log_wrapper(FILE *stream, char *msg, char *file)
{
	char buffer[0x100];

	strcpy(buffer, msg);
	snprintf(buffer + strlen(buffer), 0xfe - strlen(buffer), file);
	buffer[strcspn(buffer, "\n")] = 0;
	fprintf(stream, "LOG: %s\n", buffer);
}

int main(int ac, char **av)
{
	char buffer[0x60];
	FILE *ret;
	FILE *ret2;
	int fd = -1;
	char c = -1;

	if (ac != 2)
		printf("Usage: %s filename\n", *av);
	ret = fopen("./backups/.log", "w");
	if (ret == 0)
	{
		printf("ERROR: Failed to open %s\n", "./backups/.log");
		exit(1);
	}
	log_wrapper(ret, "Starting back up: ", av[1]);
	ret2 = fopen(av[1], "r");
	if (ret2 == 0)
	{
		printf("ERROR: Failed to open %s\n", av[1]);
		exit(1);
	}

	char *str = memcpy(buffer, "./backups/", 10);
	strncat(str, av[1], 99 - strlen(str));

	if ((fd = open(str, O_WRONLY | O_CREAT | O_EXCL, 0660)) == 0)
	{
		printf("ERROR: Failed to open %s%s\n", "./backups/", av[1]);
		exit(1);
	}
	do
	{
		write(fd, &c, 1);
		c = fgetc(ret2);
	}
	while (c != -1);
	log_wrapper(ret, "Finished back up ", av[1]);
	fclose(ret2);
	close(fd);
	return (0);
}