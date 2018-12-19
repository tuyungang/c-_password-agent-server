#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>


int main(int argc, char **argv)
{
    int listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt( listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof( tmp ) );

    int ret = 0;
    struct sockaddr_in address;
    //bzero( &address, sizeof( address ) );
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    inet_pton( AF_INET, "127.0.0.1", &address.sin_addr );
    address.sin_port = htons( 12345 );

    ret = bind( listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( listenfd, 5 );
    assert( ret >= 0 );


    int user_count = 0;
    struct pollfd fds[100];
    int i;
    for (i=1; i <= 100; ++i)
    {
        fds[i].fd = -1;
        fds[i].events = 0;
    }

    fds[0].fd = listenfd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while (1)
    {
        int ret = poll(fds, user_count + 1, -1);
        int i;
        for (i =0; i < user_count + 1; ++i)
        {
            if ((fds[i].fd == listenfd) && (fds[i].revents & POLLIN)) {
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );

                user_count++;
                fds[user_count].fd = connfd;
                fds[user_count].events = POLLIN;
                fds[user_count].revents = 0;
                //cout << "new client come" << endl;
                printf("new client come\n");
            }
        }

    }

    return 0;
}
