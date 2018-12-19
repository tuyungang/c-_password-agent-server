#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <list>
#include <cstdio>
#include <exception>
#include <pthread.h>
#include <sys/epoll.h>
#include <cassert>
#include <fcntl.h>
#include <vector>
#include <map>
#include "main.h"
#include "locker.h"

typedef struct _sLocalPswCacheInfo
{
    long        lAppID;
    char        szPassword[64];
    char        szVaultID[128];
    time_t      tmChange;

}sLocalPswCacheInfo, *psLocalPswCacheInfo;

typedef struct _sGetPswInfo
{
    long            lAppID;
    char            szVaultID[33];
    char            szPassword[64];
    time_t          tmChange;
}sGetPswInfo, *psGetPswInfo;
//struct sGetPswInfo  g_sGetPswInfo[10000];

typedef struct _sPswInfoFromFile
{
    long    lAppID;
    char    szPassword[64];
}sPswInfoFromFile,*psPswInfoFromFile;
//struct sPswInfoFromFile g_sPswInfoFromFile[10000];

//#define GETPSWREQINFO_NUMBER    1000
typedef struct _sGetPswReqInfo
{
    pthread_mutex_t threadMutex;
    pthread_cond_t  threadCond;
    char            szPassword[64];
    char            szVaultID[128];
    char            szAppID[64];
    time_t          tmStart;
}sGetPswReqInfo, *psGetPswReqInfo;
//struct sGetPswReqInfo*  g_sGetPswReqInfo[GETPSWREQINFO_NUMBER];

template< typename T >
class threadpool
{
public:
    threadpool( const char *remote_mainIP, const char *remote_standbyIP, int thread_number = 8, int max_requests = 10000 );
    ~threadpool();
    bool append( T* request );
    pthread_t* get_threads(){ return m_threads; }

public:
    static const int RETRY_CONNECT_MAX_COUNT = 3;
    std::map<long, sLocalPswCacheInfo> m_LocalPswCacheMap;

    locker m_LocalPswCacheMapLocker;
    locker m_NetworkStateLocker;
    locker m_OnceConnectLocker;
    locker m_FirstUpdateFlagLocker;
    locker m_FirstCheckIsUpdateFlagLocker;

    cond m_UpdateCacheCond;

private:
    //static void* worker( void* arg );
    void Run(int epollfd, int sockfd);
    //void RunSavecache();
    bool LoginPvaServer(const char *mainIP, const char *standbyIP, int *sockfd);
    bool SetupEpollListen(int *epollfd, int sockfd);
    void ReadPvaEpoll(int *needrelogin, int epollfd, void *arg = NULL);

public:
    static void* WorkerThread( void* arg );
    static void* WorkerSaveCacheFileThread( void* arg );
    static void* WorkerWriteLogFileThread( void* arg );
    unsigned int GetNetworkState() 
    { 
        unsigned int state;
        m_NetworkStateLocker.lock();
        state = m_network_state ; 
        m_NetworkStateLocker.unlock();
        return state; 
    }
    bool GetPvaFromLocal(char *appID, char *valueID, char *pswbuf);
    bool UpdateLocalPswCache();
    int PthreadCondTimedwait(struct timespec ts);
    bool LoadPswFromLocalCacheFile();
    void SavePswToLocalCacheFile();
    bool CheckIsNeedUpdate();
    bool ActiveUpgradeLocalPswCache(char *buf, void *arg);
    bool ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo);
    bool GetOnePswFromLocalCache(char *appID, char *pswReturn);
    void ReActiveUpdateLocalCache(char *buf);
    bool ParseRecvInfo(char *appID, char *valueID, char *pswReturn, char *pswIn, int type = 0, char *seqNumber = NULL);
    bool ParseDownstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen);
    bool ParseUpstreamXmlInfo(int *appID, int *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut);
    bool VerifyLogin(int sockfd, char *szLocalIP);
    int EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType);
    bool SendDataToServer2(int* pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
    bool GetDataFromServer(int* pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
    bool ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen);
    void Log(const char* ms, ... );  
    void ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen);
    void RunWriteLogFileThread();  
    void RunSaveCacheFileThread();
    void ChangeVariableNetworkState();
    bool NotifyUpdaeCache();

private:
    int m_thread_number;
    int m_max_requests;
    pthread_t* m_threads;
    std::list< T* > m_workqueue;
    //std::list<sLocalPswCacheInfo> m_workcachequeue;
    std::list< int > m_workcachequeue;
    std::list< char* > m_worklogqueue;
    locker m_queuelocker;
    //locker m_cachelocker;
    locker m_loglocker;
    sem m_queuestat;
    sem m_cachestat;
    sem m_logstat;
    bool m_stop;
    const char *m_mainIP;
    const char *m_standbyIP;
    epoll_event events[MAX_EVENT_NUMBER];
    unsigned int m_network_state;
    int m_read_upstream_idx;
    int m_read_upstream_len;
    char m_buffer_upstream[4096];
    char m_buffer_downstream[4096];
    bool m_first_update_flag;
    bool m_first_checkisupdate_flag;
};

include "threadpool.cpp"

#endif
