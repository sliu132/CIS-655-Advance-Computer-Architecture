#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

//define signal,hard coded
//SIGRTMIN is different in user and in kernel space

#define SIG_TEST 44

void receiveSignal(int n , siginfo_t *info,void *unused)
{
	printf("received value %i\n",info->si_int);
}
int main(int argc,char **argv)
{
	int configFd;
	char buf[10];

	//Setup sighandler
	struct sigaction sig;
	sig.sa_sigaction = receiveSignal;
	sig.sa_flags = SA_SIGINFO;
	sigaction(SIG_TEST,&sig,NULL);

	configFd = open ("/sys/kernel/debug/signalconfpid",O_WRONLY);
	if(configFd <0){
		perror("open");
		return -1;
	}
	sprintf(buf,"%i",getpid());
	if(write(configFd,buf,strlen(buf)+1) <0){
		perror("fwrite");
		return -1;
	}
	return 0;
}