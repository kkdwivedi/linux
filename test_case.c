// Compile: cc -o test test_case.c -lpthread
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>

static inline int expose_cs(void)
{
	return syscall(450);
}

static inline int switch_cs(void)
{
	return syscall(451);
}

#define ERR_PTR ((void *)-1)

void *expose_thrd(void *p)
{
	unsigned long cpu = (unsigned long)p;

	cpu_set_t cpus;
	CPU_ZERO(&cpus);
	CPU_SET(cpu, &cpus);

	if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus))
		return ERR_PTR;
	if (expose_cs())
		return ERR_PTR;
	return NULL;
}

void *switch_thrd(void *p)
{
	unsigned long cpu = (unsigned long)p;

	cpu_set_t cpus;
	CPU_ZERO(&cpus);
	CPU_SET(cpu, &cpus);

	if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus))
		return ERR_PTR;
	if (switch_cs())
		return ERR_PTR;
	return NULL;
}

int main(void)
{
	pthread_t ex_t, sw_t;
	void *ex_r, *sw_r;

	if (pthread_create(&ex_t, NULL, expose_thrd, (void *)0)) {
		puts("Failed to launch expose thread");
		return 1;
	}

	if (pthread_create(&sw_t, NULL, switch_thrd, (void *)2)) {
		puts("Failed to launch switch thread");
		goto kill_ex_t;
	}

	pthread_join(ex_t, &ex_r);
	pthread_join(sw_t, &sw_r);

	printf("[%s] : Expose thread\n", !ex_r ? "P" : "F");
	printf("[%s] : Switch thread\n", !sw_r ? "P" : "F");
	return (!ex_r && !sw_r) ? 0 : 1;

kill_ex_t:
	pthread_kill(ex_t, SIGKILL);
	return 1;
}
