#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <openssl/sha.h>
//#define DEBUG

int clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}

int clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}


inline int clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}

#define	LINELEN		128
#define resultSz	4096

void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

int TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}

int RemoteShell(char *destination, int portN, char *user_ID, char *password_hash)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/
	int n;



	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

    printf("Pinged Server....\n");

    //printf("Sending %s and %s\n", user_ID, password_hash);

    //encrypt(user_ID, 0xFACA);
	
    //printf("Sending %s and %s\n", user_ID, password_hash);

    write(sock, user_ID, strlen(user_ID));
    write(sock, password_hash, 50);

while (fgets(buf, sizeof(buf), stdin)) {
        printf("***** Buf sent is %s length is %ld\n", buf, sizeof(buf));
 
        buf[LINELEN] = ' '; /* insure line null-terminated */
        outchars = strlen(buf);
        printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s\n",
                        destination, portN, n, outchars, buf);
        if ((n = write(sock, buf, outchars)) != outchars) /* send error */
        {
#ifdef DEBUG
            printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s\n",
                    destination, portN, n, outchars, buf);
#endif /* DEBUG */
            close(sock);
            return -1;
        }
#ifdef DEBUG
        printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`n",
                destination, portN, n, buf);
#endif /* DEBUG */
 
        /* Get the result */
 
        if ((inchars = recv(sock, result, resultSz, 0)) > 0) /* got some result */
        {
            result[inchars] = 0;
            fputs(result, stdout);
        }
        if (inchars < 0)
            errmesg("socket read failedn");
    }
 
    close(sock);
    return 0;
}

/* * main  *------------------------------------------------------------------------&*/

int main(int argc, char *argv[]) {
    char *destination;
    int portN;
    char *c_username;
    char *c_password;
 
    if (argc == 5) {
        destination = argv[1];
        portN = atoi(argv[2]);
        c_username = argv[3];
        c_password = argv[4];
        //printf("SHA1 password: %s \n", c_password);
    } else
        usage(argv[0]);
    //conver password to sha1 format
    int i = 0;
    unsigned char temp[SHA_DIGEST_LENGTH];
    char buf[SHA_DIGEST_LENGTH * 2];
 
    memset(buf, 0x0, SHA_DIGEST_LENGTH * 2);
    memset(temp, 0x0, SHA_DIGEST_LENGTH);
 
    SHA1((unsigned char *) argv[4], strlen(argv[4]), temp);
 
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*) &(buf[i * 2]), "%02x", temp[i]);
    }
    //printf("SHA1 of %s is %s\n", argv[4], buf);
 
 
    RemoteShell(destination, portN, c_username, buf);
 
    exit(0);
}
