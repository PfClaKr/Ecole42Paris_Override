#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int nb;

    puts("***********************************"); 
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &nb);
    if (nb != 5276)
	{
        puts("\nInvalid Password!");
		return (1);
    }
    else
	{
        puts("\nAuthenticated!");
        system("/bin/sh");
    }
    return (0);
}