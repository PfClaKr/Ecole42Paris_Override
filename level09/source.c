#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s_mail
{
	char msg[140];
	char username[40];
	int msg_len;
};

void secret_backdoor(void)
{
	char buffer[128];

	fgets(buffer, 128, stdin);
	system(buffer);
}

void set_msg(struct s_mail *mail)
{
	char buffer[1024];

	memset(buffer, 0, 1024);
	puts(">: Msg @Unix-Dude"); // 0x 55 55 55 55 48 8c
	printf(">>: ");
	fgets(buffer, buffer, stdin);
	strncpy(mail->msg, buffer, mail->msg_len);
}

void set_username(struct s_mail *mail)
{
	int len;
	char name[128];

	memset(name, 0, 128);
	puts(">: Enter your username");
	printf(">>: ");
	fgets(name, 128, stdin);
	len = 0;
	while (len <= 40 && name[len])
	{
		mail->username[len] = name[len];
		len += 1;
	}
	printf(">: Welcome, %s", mail->username);
}

void handle_msg(void)
{
	struct s_mail mail;

	memset(mail.username, 0, sizeof(mail.username));
	mail.msg_len = 140;
	set_username(&mail);
	set_msg(&mail);

	puts(">: Msg sent!");
}

int main(void)
{
	puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n--------------------------------------------\n");
	handle_msg();
	return (0);
}