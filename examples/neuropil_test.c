#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

int* i = NULL;

int main(int argc, char **argv)
{
	i = calloc(1,sizeof(int));
	int j;
	for (j = 0; j < 10; j++) {
		if (fork() == 0) {
			sleep(j);
			*i = *i + 1;
			printf("pid: %d mem: %p i: %d\n", getpid(), i, *i);
			*i = *i + 1;
			printf("pid: %d mem: %p i: %d\n", getpid(), i, *i);
			break;
		}
	}
	sleep(j+1);

	return 0;
}
