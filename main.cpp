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

#define PACKET_START "@ABCD"

#define PACKET_START_SIZE 5
#define PACKET_TYPE_SIZE 1
#define PACKET_LENGTH_SIZE 2
#define PACKET_NUMBER_SIZE 4

#define PACKET_EVENT_CODE_SIZE 4
#define PACKET_EVENT_SENDING_NODE_SIZE 4
#define PACKET_EVENT_LENGTH_SIZE 4

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


void read_dsi_packet(int sockfd, char *buf, int numbytes)
{
    std::cout << "reading header... ";

    int read_numbytes;

	if ((read_numbytes = recv(sockfd, buf, numbytes, 0)) == -1)
    {
	    perror("recv");

	    exit(1);
	}

    std::cout << "read " << read_numbytes << " bytes." << std::endl;

	buf[read_numbytes] = '\0';
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

    read_dsi_packet(sockfd, buf, PACKET_START_SIZE);

    if (strcmp(buf, PACKET_START) != 0)
    {
        std::cout << "Packet header does not match!(" << buf << ")" << std::endl;

        exit(-1);
    }

    read_dsi_packet(sockfd, buf, PACKET_TYPE_SIZE);

    unsigned int packet_type = (unsigned int) buf[0];

    std::cout << "Packet type: " << packet_type << std::endl;

    read_dsi_packet(sockfd, buf, PACKET_LENGTH_SIZE);

    unsigned int packet_size = (unsigned int) buf[1] + ((unsigned int) buf[0] << 8);

    if (packet_size > BUFFER_SIZE)
    {
        std::cout << "Packet is too big!" << std::endl;

        exit(-1);
    }

    std::cout << "Packet[0]: " << (unsigned int) buf[0] << std::endl;
    std::cout << "Packet[1]: " << (unsigned int) buf[1] << std::endl;
    std::cout << "Packet size: " << packet_size << std::endl;

    read_dsi_packet(sockfd, buf, PACKET_NUMBER_SIZE);

    unsigned int packet_number = (unsigned int) buf[3] +
                                 ((unsigned int) buf[2] << 8) +
                                 ((unsigned int) buf[1] << 16) +
                                 ((unsigned int) buf[0] << 24);

    std::cout << "Packet[0]: " << (unsigned int) buf[0] << std::endl;
    std::cout << "Packet[1]: " << (unsigned int) buf[1] << std::endl;
    std::cout << "Packet[2]: " << (unsigned int) buf[2] << std::endl;
    std::cout << "Packet[3]: " << (unsigned int) buf[3] << std::endl;

    std::cout << "Packet number: " << packet_number << std::endl;

    read_dsi_packet(sockfd, buf, packet_size);


    unsigned int offset = 0;

    unsigned int event_code = (unsigned int) buf[3] +
                              ((unsigned int) buf[2] << 8) +
                              ((unsigned int) buf[1] << 16) +
                              ((unsigned int) buf[0] << 24);

    std::cout << "Event code: " << event_code << std::endl;

    offset += PACKET_EVENT_CODE_SIZE;

    unsigned int sending_node = (unsigned int) buf[3 + offset] +
                                ((unsigned int) buf[2 + offset] << 8) +
                                ((unsigned int) buf[1 + offset] << 16) +
                                ((unsigned int) buf[0 + offset] << 24);

    std::cout << "Sending node: " << sending_node << std::endl;

    offset += PACKET_EVENT_SENDING_NODE_SIZE;

    unsigned int message_length = (unsigned int) buf[3 + offset] +
                                  ((unsigned int) buf[2 + offset] << 8) +
                                  ((unsigned int) buf[1 + offset] << 16) +
                                  ((unsigned int) buf[0 + offset] << 24);

    std::cout << "Message length: " << message_length << std::endl;

    offset += PACKET_EVENT_LENGTH_SIZE;
    buf[offset + message_length] = '\0';

    std::cout << "Message: " << &buf[offset] << std::endl;





























	close(sockfd);
}

