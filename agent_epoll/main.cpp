#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <cassert>
#include <sys/epoll.h>
#include <sys/time.h>

#include "main.h"
#include "locker.h"
#include "threadpool.h"
#include "req_conn.h"

void ReadConf()
{

}

void addsig( int sig, void( handler )(int), bool restart)
{
    struct sigaction sa;
    memset( &sa, '\0', sizeof( sa ) );
    sa.sa_handler = handler;
    if( restart )
    {
        sa.sa_flags |= SA_RESTART;
    }
    sigfillset( &sa.sa_mask );
    assert( sigaction( sig, &sa, NULL ) != -1 );
}

void show_error( int connfd, const char* info )
{
    printf( "%s", info );
    send( connfd, info, strlen( info ), 0 );
    close( connfd );
}

int setnonblocking( int fd )
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void addfd( int epollfd, int fd, bool one_shot )
{
    epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    if( one_shot )
    {
        event.events |= EPOLLONESHOT;
    }
    epoll_ctl( epollfd, EPOLL_CTL_ADD, fd, &event );
    setnonblocking( fd );
}

void removefd( int epollfd, int fd )
{
    epoll_ctl( epollfd, EPOLL_CTL_DEL, fd, 0 );
    close( fd );
}

void modfd( int epollfd, int fd, int ev )
{
    epoll_event event;
    event.data.fd = fd;
    event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    epoll_ctl( epollfd, EPOLL_CTL_MOD, fd, &event );
}


int main( int argc, char* argv[] )
{
    if( argc <= 2 )
    {
        printf( "usage: %s remote_main_ip_address remote_standby_ip_port_number\n", basename( argv[0] ) );
        return 1;
    }

    const char *main_ip = argv[1];
    const char *standby_ip = argv[1];

    const char* local_ip = "127.0.0.1";
    int port = atoi( "12345" );

    addsig( SIGPIPE, SIG_IGN );

    threadpool< req_conn >* pool = NULL;
    try
    {
        pool = new threadpool< req_conn >(main_ip, standby_ip);
    }
    catch( ... )
    {
        return 1;
    }

    bool bRet;
    struct timespec ts;
    struct timeval  tp;
    gettimeofday(&tp, NULL);
    ts.tv_sec = tp.tv_sec + 2;
    ts.tv_nsec = tp.tv_usec * 1000;
    while (1) {
        int ret = pool->PthreadCondTimedwait(ts);
        if (ret == 0) {
            /*
            bRet = pool->UpdateLocalPswCache();
            if (!bRet) 
                //log();
            else
                //log();
            */
            break;
        }
        bRet = pool->LoadPswFromLocalCacheFile();
        if (!bRet) {
            pool->Log("读取本地密码缓存文件失败");
            return 1; 
        }
        break;
    }

    req_conn* users = new req_conn[ MAX_FD ];
    assert( users );
    int user_count = 0;

    int listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt( listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof( tmp ) );

    int ret = 0;
    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, local_ip, &address.sin_addr );
    address.sin_port = htons( port );

    ret = bind( listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( listenfd, 5 );
    assert( ret >= 0 );

    epoll_event events[ MAX_EVENT_NUMBER ];
    int epollfd = epoll_create( 5 );
    assert( epollfd != -1 );
    addfd( epollfd, listenfd, false );

    while( true )
    {
        int number = epoll_wait( epollfd, events, MAX_EVENT_NUMBER, -1 );
        if ( ( number < 0 ) && ( errno != EINTR ) )
        {
            pool->Log("epoll failure");
            break;
        }

        for ( int i = 0; i < number; i++ )
        {
            int sockfd = events[i].data.fd;
            if( sockfd == listenfd )
            {
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
                if ( connfd < 0 )
                {
                    printf( "errno is: %d\n", errno );
                    continue;
                }
                /*
                if( req_conn::m_user_count >= MAX_FD )
                {
                    show_error( connfd, "Internal server busy" );
                    continue;
                }
                */
                
                users[connfd].Init( epollfd, connfd, client_address, pool );
            }
            else if( events[i].events & ( EPOLLRDHUP | EPOLLHUP | EPOLLERR ) )
            {
                users[sockfd].close_conn();
            }
            else if( events[i].events & EPOLLIN )
            {
                if( users[sockfd].ReceiveRequest() )
                {
                    pool->append( users + sockfd );
                }
                else
                {
                    users[sockfd].close_conn();
                }
            }
            else if( events[i].events & EPOLLOUT )
            {
                /*
                if( !users[sockfd].write() )
                {
                    users[sockfd].close_conn();
                }
                */
            }
            else
            {}
        }
    }

    close( epollfd );
    close( listenfd );
    delete [] users;
    delete pool;
    return 0;
}
