#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <assert.h>

#define DEBUG

void encrypt(char password[],int key)
{
    unsigned int i;
    for(i=0;i<strlen(password);++i)
    {
        password[i] = password[i] - key;
    }
}
 
void decrypt(char password[],int key)
{
    unsigned int i;
    for(i=0;i<strlen(password);++i)
    {
        password[i] = password[i] + key;
    }
}

int serversock(int UDPorTCP, int portN, int qlen, char user[], char psd[]) {
    struct sockaddr_in svr_addr; 
    int sock; 
 
    if (portN < 0 || portN > 65535 || qlen < 0) 
        return -2;
 
    bzero((char *) &svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;
 
    /* Set destination port number */
    svr_addr.sin_port = htons(portN);
 
    /* Allocate a socket */
    sock = socket(PF_INET, UDPorTCP, 0);
    if (sock < 0)
        return -3;
 
    /* Bind the socket */
    if (bind(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) < 0)
        return -4;
 
    if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
        return -5;
    return sock;
}
int serverTCPsock(int portN, int qlen, char user[], char psd[]) {
    return serversock(SOCK_STREAM, portN, 0, user, psd);
}
 
inline int serverUDPsock(int portN) {
    return serversock(SOCK_DGRAM, portN, 0,"", "");
}
void usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "* %s\n", msg);
	exit(1);

}

void reaper(int signum)
{
	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0);
}

int RemoteShellD(int sock)
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;

#ifdef DEBUG
	printf("* RemoteShellD(sock=%d) called\n", sock);
#endif

	while ((cc = read(sock, cmd, BUFSZ)) > 0)	/* received something */
	{	
		
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("* RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("* cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */
          printf("stream Succesful"); 
		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("* sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		fclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
}

int main(int argc, char *argv[]) {
    int msock;                   /* master server socket */
    int ssock;                   /* slave server socket */
    int portN;                   /* port number to listen */
    char *server_user;
    char *server_psw;
    char s_uid[20];
    char s_phash[50];
    char uid[20];
    char phash[50];
    struct sockaddr_in fromAddr;            /* the from address of a client */
    unsigned int fromAddrLen;              /* from-address length          */
    int prefixL, r;
    if (argc == 3) {
        portN = atoi(argv[1]);
        char buf[100];
        
        FILE *ptr_file = fopen(argv[2], "r");
        if (!ptr_file)
            return 1;
        int mcr = 0;
        while (fgets(buf, 1000, ptr_file) != NULL)
            fclose(ptr_file);
        
        server_user = strtok(buf, ";");
        server_psw = strtok(NULL, ";");
        
	strcpy(s_uid,server_user);
	strcpy(s_phash,server_psw);

    } else
        usage(argv[0]);

    /*
    printf("User_ID: %s\n", server_user);
    printf("Password_Hash: %s\n", server_psw);*/
 
    msock = serverTCPsock(portN, 5, server_user, server_psw);

    printf("Waiting for client to connect....\n");
 
    (void) signal(SIGCHLD, reaper);
 
    while (1) {
        fromAddrLen = sizeof(fromAddr);
 
        ssock = accept(msock, (struct sockaddr *) &fromAddr, &fromAddrLen);
        if (ssock < 0) {
            if (errno == EINTR)
                continue;
            errmesg("accept errorn");
        }

        read(ssock, uid, 20);
	decrypt(uid, 0xFACA);
	read(ssock, phash, 50);

        if((strcmp(s_uid, uid) != 0) || (strcmp(s_phash, phash) != 0)) {
            printf("Failed to authenticate!\n");
            printf("Connection to client '%s' closed!\n\n", uid);
            close(ssock);
        }
        else
            printf("Connection to client '%s' successful!\n\n", uid);
 
        switch (fork()) {
 
        case 0: /* child */
            close(msock);
            r = RemoteShellD(ssock);
            close(ssock);
            exit(r);
 
        default: /* parent */
            (void) close(ssock);
            break;
        case -1:
            errmesg("fork errorn");
        }
    }
    close(msock);
}
