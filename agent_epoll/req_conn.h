#ifndef REQUEST_CONNECTION_H
#define REQUEST_CONNECTION_H

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <errno.h>
#include "locker.h"
#include "threadpool.h"

class req_conn
{
public:
    static const int FILENAME_LEN = 200;
    static const int READ_BUFFER_SIZE = 4096;

public:
    req_conn();
    ~req_conn();

public:
    void Init( int sockfd, const sockaddr_in& addr );
    void Init( int epollfd, int sockfd, const sockaddr_in& addr, void *arg );
    void Init(bool needupdate = false);
    void close_conn( bool real_close = true );
    bool ProcessRequest();
    bool ReceiveRequest();
    void SetMainEpollfd(int fd) { m_main_epollfd = fd; }
    void SetMinorEpollfd(int fd) { m_minor_epollfd = fd; }
    unsigned int GetNetworkState() { return m_pool->GetNetworkState(); }
    void SetSockfdUpstream(int sockfd) { m_sockfd_upstream = sockfd; }
    bool GetUpdateCacheFlag() { return m_ActiveUpdateCacheFlag; }
    void ProcessNewPswFromUpstream(char *buf);

//private:
    //void Init(bool needupdate = false);
    bool ProcessPswInfoFromUpstream();
    bool SendRequestToUpstream(char *valueID);
    void EncodeSendInfo();
    bool SendDataToServer(int* pnSocket, char* pszSendData, int nSendLen);
    void SendDataToDownstream(char *pswSendData);
    void SetAppID(char *appID)
    {
        memcpy(m_lAppID, appID, strlen(appID));
    }
    void SetValueID(char *valueID)
    {
        memcpy(m_valueID, valueID, strlen(valueID));
    }
    char* GetAppID() { return m_lAppID; }
    char* GetValueID() { return m_valueID; }

public:
    int m_main_epollfd;
    int m_minor_epollfd;
    threadpool<req_conn> *m_pool;
    bool m_ActiveUpdateCacheFlag;
    char *m_lAppID;
    char *m_valueID;
    char *m_SeqNumber;

private:
    int m_sockfd_downstream;
    int m_sockfd_upstream;
    sockaddr_in m_address_downstream;

    char m_downstream_buf[ READ_BUFFER_SIZE ];
    char m_upstream_buf[ READ_BUFFER_SIZE ];
    int m_downstream_idx;
    char *m_sendbuf_upstream;
    char *m_sendbuf_downstream;
    sockaddr_in m_address;

    //bool m_linger;

};

#endif
