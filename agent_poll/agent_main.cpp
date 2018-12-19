#include "agent_main.h"
//#include "thread_pool.h"

AgentMain* AgentMain::pInstance = NULL;

AgentMain::AgentMain()
{
    user_counter = 0;
}

AgentMain::AgentMain(int threadNum)
{

}

AgentMain::~AgentMain()
{
    //close( epollfd );
    close( m_listenfd );
    delete [] users;
    delete m_pool;
}

AgentMain* AgentMain::GetInstance()
{
    locker m_lock;
    if (pInstance == NULL) {
        m_lock.lock();
        if (pInstance == NULL) {
            pInstance = new AgentMain();
        }
        m_lock.unlock();
    }
    return pInstance;
}

void AgentMain::run()
{
    users = new req_conn[ MAX_FD ];
    assert( users );

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

    struct sockaddr_in client_address;
    socklen_t client_addrlength = sizeof( client_address );
    int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
    printf("a client come\n");

    /*
    int user_count = 0;
    struct pollfd fds[100];
    for (int i=1; i <= 100; ++i)
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
        for (int i =0; i < user_count + 1; ++i)
        {
            if ((fds[i].fd == listenfd) && (fds[i].revents & POLLIN)) {
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );

                user_count++;
                fds[user_count].fd = connfd;
                fds[user_count].events = POLLIN;
                fds[user_count].revents = 0;
                printf("a client come\n");
            }
        }

    }
*/
}

void AgentMain::Startup()
{
    const char *main_ip = "192.168.2.3";
    const char *standby_ip = "192.168.2.3";

    //const char* local_ip = "127.0.0.1";
    //int port = atoi( "12345" );

    //addsig( SIGPIPE, SIG_IGN );
    CheckIsDirExist();

    /*
    threadpool< req_conn >* pool = NULL;
    try
    {
        pool = new threadpool< req_conn >(main_ip, standby_ip);
    }
    catch( ... )
    {
        //return 1;
    }

    printf("%s %d\n", __func__, __LINE__);
    bool bRet;
    struct timespec ts;
    struct timeval  tp;
    gettimeofday(&tp, NULL);
    ts.tv_sec = tp.tv_sec + 10;
    ts.tv_nsec = tp.tv_usec * 1000;
    while (1) {
    printf("%s %d\n", __func__, __LINE__);
        int ret = pool->PthreadCondTimedwait(ts);
        if (ret == 0) {
            printf("main thread updating\n");
            sleep(1);
            bRet = pool->UpdateLocalPswCache();
            //if (!bRet) 
                //log();
            //else
                //log();
            break;
        }
        break;
    }
    */

    //req_conn* users = new req_conn[ MAX_FD ];
    users = new req_conn[ MAX_FD ];
    assert( users );
    //int user_count = 0;
    //m_pool = pool;

    SetupPollListen();
}

void AgentMain::CheckIsDirExist()
{
    char g_CurAbsolutePath[256];
    char g_LogAbsolutePath[256];
    char g_CacheFileAbsolutePath[256];

    memset(g_CurAbsolutePath, '\0', 256);
    memset(g_LogAbsolutePath, '\0', 256);
    memset(g_CacheFileAbsolutePath, '\0', 256);
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    sprintf(g_LogAbsolutePath, "%s/%s",g_CurAbsolutePath, "log");
    if (opendir(g_LogAbsolutePath) == NULL) {
        mkdir((const char*)g_LogAbsolutePath, S_IRWXU|S_IRWXG|S_IRWXO);
    }
    sprintf(g_CacheFileAbsolutePath, "%s/%s",g_CurAbsolutePath, "PSWCache");
    if (opendir(g_CacheFileAbsolutePath) == NULL) {
        mkdir((const char*)g_CacheFileAbsolutePath, S_IRWXU|S_IRWXG|S_IRWXO);
    }
}

void AgentMain::SetupPollListen()
{
    const char* local_ip = "127.0.0.1";
    int port = atoi( "12345" );
    m_listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( m_listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt( m_listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof( tmp ) );

    int ret = 0;
    struct sockaddr_in address;
    //bzero( &address, sizeof( address ) );
    memset( &address, 0, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, local_ip, &address.sin_addr );
    address.sin_port = htons( port );

    ret = bind( m_listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( m_listenfd, 5 );
    assert( ret >= 0 );

    //int user_counter = 0;
    //struct pollfd m_pollfds[USER_LIMIT+1];
    for (int i = 1; i <= USER_LIMIT; ++i) {
        m_pollfds[i].fd = -1;
        m_pollfds[i].events = 0;

    }
    m_pollfds[0].fd = m_listenfd;
    m_pollfds[0].events = POLLIN | POLLERR | POLLHUP;
    m_pollfds[0].revents = 0;

    RunPoll();

}

int AgentMain::SetNonBlocking(int fd)
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void AgentMain::RunPoll()
{
    m_stop = false;
    while (!m_stop)
    {
        int ret = poll(m_pollfds, user_counter + 1, -1);
        printf("poll no wait\n");
        if (ret < 0) {
            printf("poll failure\n");
            //Log();
            m_stop = true;
            break;
        }
        for (int i = 0; i < user_counter + 1; ++i)
        {
            int sockfd = m_pollfds[i].fd;
            if ((m_pollfds[i].fd == m_listenfd) && ((m_pollfds[i].revents & POLLIN) == POLLIN)) {
                printf("%s %d\n", __func__, __LINE__);
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                //socklen_t addrlen = 0;
                //int connfd = accept( m_listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
                printf("%s %d\n", __func__, __LINE__);
                int connfd = accept( m_listenfd, ( struct sockaddr* )NULL, &client_addrlength );
                if ( connfd < 0 )
                {
                    printf( "errno is: %d\n", errno );
                    continue;
                }
                printf("%s %d\n", __func__, __LINE__);

                if( user_counter >= MAX_FD )
                {
                    close(sockfd);
                    send(sockfd, "Internal server busy", strlen("Internal server busy"), 0);
                    //show_error( connfd, "Internal server busy" );
                    continue;
                }
                printf("%s %d\n", __func__, __LINE__);
                
                /*
                //SetNonBlocking(connfd);
                user_counter++;
                //addfd(m_pollfds[user_counter], connfd);
                m_pollfds[user_counter].fd = connfd;
                m_pollfds[user_counter].events = POLLIN | POLLERR | POLLHUP;
                m_pollfds[user_counter].revents = 0;
                printf("%s %d\n", __func__, __LINE__);
                users[connfd].Init(m_pollfds[user_counter], connfd, client_address, m_pool);
                */
                printf("a client come\n");
                break;
            }
            /*
            else if (m_pollfds[i].revents & POLLERR) {
                printf("get an error from %d\n", m_pollfds[i].fd);
                char errors[100];
                memset(errors, '\0', 100);
                socklen_t length = sizeof(errors);
                if (getsockopt(m_pollfds[i].fd, SOL_SOCKET, SO_ERROR, &errors, &length) < 0) {
                    printf("get socket option failed\n");
                }
                continue;
            }
            else if (m_pollfds[i].revents & POLLHUP) {
                users[m_pollfds[i].fd] = users[m_pollfds[user_counter].fd];
                close(m_pollfds[i].fd);
                m_pollfds[i] = m_pollfds[user_counter];
                i--;
                user_counter--;
                printf("a client left\n");
            }
            else if (m_pollfds[i].revents & POLLIN) {
                printf("%s %d\n", __func__, __LINE__);
                if( users[sockfd].ReceiveRequest() )
                {
                    //m_pool->append( users + sockfd );
                }
                else
                {
                    //users[sockfd].close_conn();
                    users[m_pollfds[i].fd] = users[m_pollfds[user_counter].fd];
                    close(m_pollfds[i].fd);
                    m_pollfds[i] = m_pollfds[user_counter];
                    i--;
                    user_counter--;
                }
            }
            else if (m_pollfds[i].revents & POLLOUT) {
            }
            */

        }
    }
}

