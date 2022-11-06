#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>

#define BUFFER_SIZE 1024

#define HEADER_SIZE 12

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
    {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
    else
    {
	    return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
}

int main(int argc, char** argv)
{
	int sockfd, numbytes;  
	char buf[BUFFER_SIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 3)
    {
	    fprintf(stderr, "Usage: client hostname port\n");

	    exit(1);
	}

    setbuf(stdout, NULL);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));

		return 1;
	}

	// loop through all the results and connect to the first we can
    std::cout << "Connecting... ";

	for (p = servinfo; p != NULL; p = p->ai_next)
    {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
			perror("socket");

			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
			perror("connect");
			close(sockfd);

			continue;
		}

		break;
	}

	if (p == NULL)
    {
		return 2;
	}

    std::cout << "Connected." << std::endl;

	// inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
	// printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

    std::cout << "reading... ";

	if ((numbytes = recv(sockfd, buf, HEADER_SIZE, 0)) == -1)
    {
	    perror("recv");

	    exit(1);
	}

    std::cout << "read." << std::endl;

	buf[numbytes] = '\0';

	printf("client: received '%d' bytes: '%s'\n", numbytes, buf);

	close(sockfd);
}

