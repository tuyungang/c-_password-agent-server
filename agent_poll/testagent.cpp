#include <stdlib.h>
#include <cstdio>
#include <iostream>
#include <string.h>
#include <exception>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cassert>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

int main(int argc, char **argv)
{

    struct sockaddr_in address;
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, "127.0.0.1", &address.sin_addr );
    address.sin_port = htons( 12345 );
    int m_sockfd = -1;
    m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
    printf( "connectting main password server\n" );
    if( m_sockfd < 0 )
    {
        //Log("");
        close(m_sockfd);
        return -1;
    }

    /*
    reuse = 1, on = 1;
    setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    */

    if (  connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
    {
        printf( "build connection successfully\n");
    }

    /*
    send(m_sockfd, "604505646=2478cbd7fe8f4f22810664407e01f437", strlen("604505646=2478cbd7fe8f4f22810664407e01f437"), 0);

    char buf[128] = {0};
    recv(m_sockfd, buf, 128, 0);
    printf("get password: %s\n", buf);
    */
    sleep(5);
    close(m_sockfd);

    return 0;
}
