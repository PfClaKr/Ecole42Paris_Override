#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
	pid_t pid = fork();
	char str[128];
	memset(&str, 0, 128);
	int nb = 0;
	if (pid == 0)
	{
		prctl(PR_SET_PDEATHSIG, 1);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		puts("Give me some shellcode, k");
		gets(&str);
	}
	else
	{
		while (1)
		{
			wait(&nb);
			if (((nb & 0x7f) != 0 && (((nb & 0x7f) + 1) >> 1) <= 0))
			{
				if (ptrace(PTRACE_PEEKUSER, pid, 44, 0) == 11)
				{
					puts("no exec() for you");
					kill(pid, 9);
					break ;
				}
				continue ;
			}
			puts("child is exiting...");
			break ;
		}
	}
	return (0);
}