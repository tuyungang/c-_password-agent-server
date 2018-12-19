#ifndef _AGENTMAIN_H_
#define _AGENTMAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cassert>
#include <sys/poll.h>
#include <signal.h>
#include "locker.h"
#include "req_conn.h"
#include "thread_pool.h"

class AgentMain
{
    public:
        static const int USER_LIMIT = 1000;
        static const int MAX_FD = 1000;
    private:
        AgentMain();
        AgentMain(int threadNum);
        ~AgentMain();
        //AgentMain(const AgentMain &);
        //AgentMain & operator = (const AgentMain &);

    private:
        static AgentMain *pInstance;
        threadpool< req_conn > *m_pool;
        //void *m_pool;
        struct pollfd m_pollfds[USER_LIMIT+1];
        req_conn *users;
    public:
        static AgentMain *GetInstance();
        class FreeInstance
        {
            public:
                ~FreeInstance()
                {
                    if (AgentMain::pInstance)
                        delete AgentMain::pInstance;
               }
        };
        static FreeInstance _instance;

        void run();
        void Startup();
        void SetupPollListen();
        void RunPoll();
        void CheckIsDirExist();
        int SetNonBlocking(int fd);

    private:
        //static locker *m_lock;
        int m_listenfd;
        //int m_pollfd;
        int user_counter;
        bool m_stop;

};

#endif
