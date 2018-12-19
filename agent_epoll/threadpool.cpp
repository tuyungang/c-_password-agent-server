#include "threadpool.h"
#include "cryptdatafunc.h"
#include "req_conn.h"

#include "libxml/parser.h"
#include "libxml/parser.h"
//#include "/mnt/hgfs/linux_study/agent/include/libxml/tree.h"
//#include "/mnt/hgfs/linux_study/agent/include/libxml/tree.h"

template< typename T >
threadpool< T >::threadpool( const char *remote_mainIP, const char *remote_standbyIP, int thread_number, int max_requests ) : 
        m_thread_number( thread_number ), m_max_requests( max_requests ), m_stop( false ), m_threads( NULL )
{
    m_mainIP = remote_mainIP;
    m_standbyIP = remote_standbyIP;
    m_LocalPswCacheMap.clear();
    if( ( thread_number <= 0 ) || ( max_requests <= 0 ) )
    {
        throw std::exception();
    }

    pthread_t saveThr, logThr;
    if( pthread_create( &saveThr, NULL, WorkerSaveCacheFileThread, this ) != 0 )
    {
        throw std::exception();
    }
    if( pthread_detach( saveThr ) )
    {
        throw std::exception();
    }

    if( pthread_create( &logThr, NULL, WorkerWriteLogFileThread, this ) != 0 )
    {
        throw std::exception();
    }
    if( pthread_detach( logThr ) )
    {
        throw std::exception();
    }
    m_threads = new pthread_t[ m_thread_number ];
    if( ! m_threads )
    {
        throw std::exception();
    }

    for ( int i = 0; i < thread_number; ++i )
    {
        printf( "create the %dth thread\n", i );
        if( pthread_create( m_threads + i, NULL, WorkerThread, this ) != 0 )
        {
            delete [] m_threads;
            throw std::exception();
        }
        /*
        if( pthread_detach( m_threads[i] ) )
        {
            delete [] m_threads;
            throw std::exception();
        }
        */
    }
}

template< typename T >
threadpool< T >::~threadpool()
{
    delete [] m_threads;
    m_stop = true;
}

template< typename T >
bool threadpool< T >::append( T* request )
{
    m_queuelocker.lock();
    if ( m_workqueue.size() > m_max_requests )
    {
        m_queuelocker.unlock();
        return false;
    }
    m_workqueue.push_back( request );
    m_queuelocker.unlock();
    m_queuestat.post();
    return true;
}

template< typename T >
void* threadpool< T >::WorkerWriteLogFileThread( void* arg )
{
    threadpool *pool = (threadpool*)arg;
    pool->RunWriteLogFileThread();
    return pool;
}

template< typename T >
void threadpool< T >::RunWriteLogFileThread()  
{
    while (1) 
    {
        m_logstat.wait();
        m_loglocker.lock();
        if ( m_worklogqueue.empty() )
        {
            m_loglocker.unlock();
            continue;
        }
        char* mLog = m_worklogqueue.front();
        m_worklogqueue.pop_front();
        m_loglocker.unlock();
        if ( ! mLog )
        {
            continue;
        }

REWRITE:
        FILE* pFile = fopen("pvadll.log","a+");
        if (pFile == NULL)
            return ;
        int nInfoLen = strlen(mLog);
        int nRetCode = fwrite(mLog, sizeof(char), nInfoLen, pFile);
        if (nRetCode != nInfoLen)
            goto REWRITE;
        else
        {
            fflush(pFile);
        }
    }
}

template< typename T >
void threadpool< T >::Log(const char* format, ... )  
{
    char wzLog[1024] = {0};
    char szBuffer[1024] = {0};
    va_list args;
    va_start(args, format);
    vsprintf(wzLog, format, args);
    va_end(args);

    time_t now;
    time(&now);
    struct tm *local;
    local = localtime(&now);
    sprintf(szBuffer,"%04d-%02d-%02d %02d:%02d:%02d (%s %d) %s\n", local->tm_year+1900, local->tm_mon,local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec, __FILE__, __LINE__, wzLog);
    //int nLen = strlen(szBuffer);
    printf("%s", szBuffer);

    m_loglocker.lock();
    /*
    if ( m_worklogqueue.size() > m_max_log )
    {
        m_loglocker.unlock();
        return ;
    }
    */
    m_worklogqueue.push_back( szBuffer );
    m_loglocker.unlock();
    m_logstat.post();

    return ;
}

template< typename T >
void* threadpool< T >::WorkerSaveCacheFileThread( void* arg )
{
    threadpool *pool = (threadpool*)arg;

    pool->RunSaveCacheFileThread();
    /*

    m_cachelocker.lock();
    if ( m_workcachequeue.empty() )
    {
        m_cachelocker.unlock();
        continue;
    }
    //T* request = m_workqueue.front();
    m_workcachequeue.pop_front();
    m_cachelocker.unlock();
    if ( ! request )
    {
        continue;
    }
    */
    return pool;
}

template< typename T >
void threadpool< T >::RunSaveCacheFileThread()
{
    while (1) 
    {
        m_cachestat.wait();
        SavePswToLocalCacheFile();
    }
}

template< typename T >
void threadpool< T >::ChangeVariableNetworkState()
{
    m_NetworkStateLocker.lock();
    m_network_state++ ; 
    m_NetworkStateLocker.unlock();
}

template< typename T >
void* threadpool< T >::WorkerThread( void* arg )
{
    //bool bOnceConnect = false;
    int err = pthread_detach( pthread_self() );
    threadpool* pool = ( threadpool* )arg;
    if( err != 0 )
    {
        delete [] (pool->get_threads());
        throw std::exception();
    }

    int sockfd;
    bool ret = pool->LoginPvaServer(pool->m_mainIP, pool->m_standbyIP, &sockfd);
    if (!ret) {
        Log("");
        pool->ChangeVariableNetworkState();
        return NULL;
    }

    pool->UpdateLocalPswCache();

    pool->NotifyUpdaeCache();
    /*
    ret = m_OnceConnectLocker.trylock();
    if (ret) {
        if (!bOnceConnect) {
            m_UpdateCacheCond.signal();
            bOnceConnect = true;
        }
        m_OnceConnectLocker.unlock();
    }
    */

    int epollfd;
    pool->SetupEpollListen(&epollfd, sockfd);
    pool->Run(epollfd, sockfd);
    return pool;
}

template< typename T>
bool threadpool< T >::NotifyUpdaeCache()
{
    bool bOnceConnect = false;
    bool ret = m_OnceConnectLocker.trylock();
    if (ret) {
        if (!bOnceConnect) {
            m_UpdateCacheCond.signal();
            bOnceConnect = true;
        }
        m_OnceConnectLocker.unlock();
    }
    return ret;
}

template< typename T>
bool threadpool< T >::SetupEpollListen(int *epollfd, int sockfd)
{
    *epollfd = epoll_create(5);
    assert(*epollfd != -1);
    addfd(*epollfd,sockfd, false);
}

template< typename T>
bool threadpool< T >::LoginPvaServer(const char *mainIP, const char *standbyIP, int *sockfd)
{
    struct sockaddr_in address;
    int reuse, on, n = 0;
    int m_tryconnect_count = 0;
    int m_sockfd;
    char *pszLocalIP = NULL;

RETRY:
    { /*connect remote main ip*/
        bzero( &address, sizeof( address ) );
        address.sin_family = AF_INET;
        inet_pton( AF_INET, mainIP, &address.sin_addr );
        address.sin_port = htons( 9934 );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting main password server\n" );
        if( m_sockfd < 0 )
        {
            Log("");
            close(m_sockfd);
            goto RETRY;
        }

        reuse = 1, on = 1;
        setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

        if (  connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
        {
            printf( "build connection successfully\n");
            //addfd( m_epollfd, m_sockfd, false);
            goto SUCCESS;
        }
        Log("");
        close(m_sockfd);
    }

    { /*connect remote standby ip*/
        bzero( &address, sizeof( address ) );
        address.sin_family = AF_INET;
        inet_pton( AF_INET, standbyIP, &address.sin_addr );
        address.sin_port = htons( 9934 );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting standby password server\n" );
        if( m_sockfd < 0 )
        {
            Log("");
            close(m_sockfd);
            goto RETRY;
        }

        reuse = 1, on = 1;
        setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(m_sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

        if (  connect( m_sockfd, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
        {
            printf( "build connection successfully\n");
            //addfd( m_epollfd, m_sockfd, false);
            goto SUCCESS;
        }
        Log("");
        close(m_sockfd);
    }
    m_tryconnect_count += 1;
    n += 1000;
    if (m_tryconnect_count != RETRY_CONNECT_MAX_COUNT) {
        sleep(1000 + n * m_tryconnect_count);
        goto RETRY;
    }
    Log("");
    return false;

SUCCESS:
    *sockfd = m_sockfd;
    int m = 0;
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    getsockname(m_sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
    char szLocalIP[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &clientAddr.sin_addr, szLocalIP, INET_ADDRSTRLEN);
    if (strlen(szLocalIP) > 0)
    {
        memcpy(pszLocalIP, szLocalIP, strlen(szLocalIP));
    }

VERIFICATION:
    bool bRet = VerifyLogin(m_sockfd, pszLocalIP);
    if (!bRet) {
        if (m >= 2)  {
            Log("");
            return false;
        }
        m++;
        goto VERIFICATION;
    }
    return true;
}

template< typename T >
bool threadpool< T >::VerifyLogin(int sockfd, char *szLocalIP)
{
    char szSendData[8192] = { 0 };
    int nDataLen = 0;
    nDataLen = strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"");
    memcpy(szSendData, "<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"", nDataLen);
    memcpy(szSendData + nDataLen, "aimuser", strlen("aimuser"));
    nDataLen += strlen("aimuser");
    memcpy(szSendData + nDataLen, "\" pass=\"", strlen("\" pass=\""));
    nDataLen += strlen("\" pass=\"");
    memcpy(szSendData + nDataLen, "", strlen("")/*g_szPassword, strlen(g_szPassword)*/);
    nDataLen += strlen(""/*g_szPassword*/);
    memcpy(szSendData + nDataLen, "\" role=\"", strlen("\" role=\""));
    nDataLen += strlen("\" role=\"");
    memcpy(szSendData + nDataLen, "huawei@aim", strlen("huawei@aim"));
    nDataLen += strlen("huawei@aim");
    memcpy(szSendData + nDataLen, "\" ip=\"", strlen("\" ip=\""));
    nDataLen += strlen("\" ip=\"");
    if (strlen(szLocalIP) > 0)
    {
        memcpy(szSendData + nDataLen, szLocalIP, strlen(szLocalIP));
        nDataLen += strlen(szLocalIP);
    }
    /*
    else
    {
        memcpy(szSendData + nDataLen, g_szIPAddress, strlen(g_szIPAddress));
        nDataLen += strlen(g_szIPAddress);
    }
    */

    memcpy(szSendData + nDataLen, "\" md5=\"", strlen("\" md5=\""));
    nDataLen += strlen("\" md5=\"");
    memcpy(szSendData + nDataLen, "null", strlen("null")/*g_szExeKey, strlen(g_szExeKey)*/);
    nDataLen += strlen("null"/*g_szExeKey*/);
    memcpy(szSendData + nDataLen, "\" seq=\"", strlen("\" seq=\""));
    nDataLen += strlen("\" seq=\"");

    time_t tmCurrent = time(0);
    char szSeqNumber[32] = { 0 };
    snprintf(szSeqNumber, 32, "%ld", tmCurrent);
    memcpy(szSendData + nDataLen, szSeqNumber, strlen(szSeqNumber));
    nDataLen += strlen(szSeqNumber);
    memcpy(szSendData + nDataLen, "\"></req>", strlen("\"></req>"));
    nDataLen += strlen("\"></req>");

    char szEncodeXml[8192] = { 0 };
    int* pHeader = (int*)szEncodeXml;
    *pHeader = htonl(0x1100);
    pHeader += 1;

    int nEncodeLen = 0;
    nEncodeLen = EnCodeSendInfo(szSendData, nDataLen, szEncodeXml + sizeof(int) * 2, 1);
    nEncodeLen += sizeof(int) * 2;
    *pHeader = htonl(nEncodeLen);

    int nRecvDataLen = 0;
    char szRecvData[8192] = {0};
    char pszErrorInfo[1024] = {0};
    bool bRetCode = SendDataToServer2(sockfd, szEncodeXml, nEncodeLen, szRecvData, &nRecvDataLen, pszErrorInfo);
    if (!bRetCode) {
        Log("");
        return false;
    }

    char szDecodeData[8192] = {0};
    int  nDecodeData = 0;
    char *appID = NULL, *valueID = NULL, *pswReturn = NULL, *pswIn = NULL;
    bRetCode =  ParseRecvInfo(appID, valueID, pswReturn,pswIn, 1, szSeqNumber);
    if (!bRetCode)
    {
        if (sockfd != -1)
        {
            close(sockfd);
        }
        return false;
    }

    return true;
}

template< typename T >
bool threadpool< T >::ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    char szSeqNumber[256] = {0};
    char* pszXmlName = (char*)pXmlSeq;
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlSeq);  

    char szCode[100] = {0};
    pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
    if (pXmlCode == NULL)
    {
        Log("get code element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    pszXmlName = (char*)pXmlCode;
    memcpy(szCode, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlCode);
    xmlFreeDoc(doc); 

    /*
    bool bSeqNumberValid = false;
    if (memcmp(pszSeqNumber, szSeqNumber, strlen(szSeqNumber)) == 0 &&
    memcmp(szSeqNumber, pszSeqNumber, strlen(pszSeqNumber)) == 0)
    bSeqNumberValid = true;

    if (!bSeqNumberValid)
    {
        Log("get seq number is not same to send seq number");
        return false;
    }
    */

    int nCode = atol(szCode);
    if (nCode > 0)
    {
        Log("get password error,please check the send data");     
        return false;
    }
    return true;
}

template< typename T >
bool threadpool< T >::SendDataToServer2(int* pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{
    while (nSendLen > 0)
    {
        int nRealSend = send(*pnSocket, pszSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (*pnSocket != -1)
            {
                close(*pnSocket);
                *pnSocket = -1;
            }
            Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }

    return GetDataFromServer(pnSocket, pszRecvData, pRecvDataLen, pszErrorInfo);
}

template< typename T >
bool threadpool< T >::GetDataFromServer(int* pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{ 
    char szRecvBuffer[4096] = {0};
    int nRecvLen = recv(*pSockClient, szRecvBuffer, 4096, 0);
    if (nRecvLen == -1 || nRecvLen == 0)
    {
        close(*pSockClient);
        *pSockClient = -1;

        Log("recv data from remote server failed!");
        return false;
    }

    memcpy(pszRecvData, szRecvBuffer, nRecvLen);
    *pRecvDataLen = nRecvLen;
    return true;
}

template< typename T >
int threadpool< T >::EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType)
{
    if (nEncodeType == 0) 
    {
        memcpy(pszOutEncodeData, pszInSendData, nInSendDataLen);
        return nInSendDataLen;
    }
    else if (nEncodeType == 1) 
    {
        int nRetCode = 0, nRandValue = 0;
        srand((unsigned int)time(0));
        unsigned char uszKey[16] = { 0 };
        int nIndex = 0;
        for (nIndex = 0; nIndex < 16; nIndex++) 
        {
            nRandValue = rand();
            nRetCode = nRandValue % 3;
            if (nRetCode == 0)
            {
                uszKey[nIndex] = (0x0f) & (nRandValue >> 2);
            }
            else if (nRetCode == 1)
            {
                uszKey[nIndex] = (0x1f) & (nRandValue >> 3);
            }
            else
            {
                uszKey[nIndex] = (0x3f) & (nRandValue >> 4);
            }
        }

        int nEncodeLen = 0;
        unsigned char uszEncodeData[10240] = { 0 };
        bool bRetCode = AES_CryptDataEVP((unsigned char*)pszInSendData, nInSendDataLen, uszKey, uszEncodeData, &nEncodeLen);

        memcpy(pszOutEncodeData, uszEncodeData, nEncodeLen);
        pszOutEncodeData += nEncodeLen;

        unsigned char szSingleKey[8] = { 0 }, szDoubleKey[8] = { 0 };
        for (nIndex = 0; nIndex < 8; nIndex++)
        {
            szSingleKey[nIndex] = uszKey[nIndex * 2];
            szDoubleKey[nIndex] = uszKey[nIndex * 2 + 1];
        }

        unsigned char szEndData[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01 };
        int nRandRemaind = rand() % 8;

        memcpy(pszOutEncodeData, szSingleKey, 8);
        pszOutEncodeData += 8;

        memcpy(pszOutEncodeData, &(szEndData[nRandRemaind]), 8);
        pszOutEncodeData += 8;

        memcpy(pszOutEncodeData, szDoubleKey, 8);
        pszOutEncodeData += 8;

        int t = 0;
        for (t = 0; t < nRandRemaind; t++)
        {
            *pszOutEncodeData = szEndData[t];
            pszOutEncodeData++;
        }

        int k = 0;
        for (k = nRandRemaind + 8; k < 16; k++)
        {
            *pszOutEncodeData = szEndData[k];
            pszOutEncodeData++;
        }

        int nXmlLen = nEncodeLen + 32;
        return nXmlLen;
    }
    else if (nEncodeType == 2)
    {
        int nLen = nInSendDataLen;
        int nRemainder = nLen % 2;
        int nSingleLen = 0, nDoubleLen = 0;
        if (nRemainder > 0)
            nSingleLen = (nLen - 1) / 2 + 1;
        else
            nSingleLen = nLen / 2;

        nDoubleLen = nLen - nSingleLen;

        int nIndex = 0;
        for (nIndex = 0; nIndex < nSingleLen; nIndex++)
        {
            *pszOutEncodeData = pszInSendData[nIndex * 2];
            pszOutEncodeData++;
        }

        int k = 0;
        for (k = 0; k < nDoubleLen; k++)
        {
            *pszOutEncodeData = pszInSendData[k * 2 + 1];
            pszOutEncodeData++;
        }
        return nLen;
    }
    else
    {
        memcpy(pszOutEncodeData, pszInSendData, nInSendDataLen);
        return nInSendDataLen;
    }
    return 0;
}

template< typename T >
void threadpool< T >::Run(int epollfd, int sockfd)
{
    int m_NeedRetryConnect = 0;
    bool bRet;
    while ( ! m_stop )
    {
        T* request = NULL;
        if (m_NeedRetryConnect) {
            m_NetworkStateLocker.lock();
            m_network_state++; 
            m_NetworkStateLocker.unlock();
            bool err = LoginPvaServer(m_mainIP, m_standbyIP, &sockfd);
            if (!err) {
                Log("");
                m_stop = true;
                break;
            }
            m_NetworkStateLocker.lock();
            m_network_state--; 
            m_NetworkStateLocker.unlock();
            addfd(epollfd, sockfd, false);
            m_NeedRetryConnect = 0;
        }
        //m_queuestat.wait();
        int ret = m_queuestat.try_wait();
        if (ret < 0) {
            if (errno == EAGAIN) {
                goto NOREQUEST;
            }
            else {
                Log("");
                continue;
                //m_stop = true;
                //break;
            }
        }

        m_queuelocker.lock();
        if ( m_workqueue.empty() )
        {
            m_queuelocker.unlock();
            continue;
        }
        request = m_workqueue.front();
        m_workqueue.pop_front();
        m_queuelocker.unlock();
        if ( ! request )
        {
            continue;
        }
        request->SetMinorEpollfd(epollfd);
        request->SetSockfdUpstream(sockfd);
        bRet = request->ProcessRequest();
        if (!bRet) {
            m_NeedRetryConnect = 1;
            continue;
        }

NOREQUEST:
        ReadPvaEpoll(&m_NeedRetryConnect, epollfd, request);
    }
}
 
template< typename T >
void threadpool< T >::ReadPvaEpoll(int *needrelogin, int epollfd, void *arg)
{
    bool m_read_upstream_flag = false;
    int number = 0;
    int ret = -1;
    number = epoll_wait( epollfd, events, MAX_EVENT_NUMBER, 5000 );
    if ( ( number < 0 ) && ( errno != EINTR ) )
    {
        Log("epoll failure");
        //break;
    }

    for ( int i = 0; i < number; i++ )
    {
        int sockfd = events[i].data.fd;
        //if ((sockfd == m_sockfd) && (events[i].events & EPOLLIN) ) 
        if (events[i].events & EPOLLIN ) {
            while (1) {
                int ret = recv( sockfd,m_buffer_upstream + m_read_upstream_idx, 4096, 0 );
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        m_read_upstream_flag = true;
                        break;
                    } else {
                        Log("");
                        removefd(epollfd, sockfd);
                        *needrelogin = 1;
                        break;
                    }
                } else if (ret == 0) {
                    Log("");
                    removefd(epollfd, sockfd);
                    *needrelogin = 1;
                    break;
                } else if (ret > 0) {
                    m_read_upstream_idx += ret;
                    m_read_upstream_len = m_read_upstream_idx;
                    printf("read upstream buffer:%s  len:%d\n", m_buffer_upstream, m_read_upstream_idx);
                }
            }
            if (m_read_upstream_flag) {
                m_read_upstream_flag = false;
                if (arg == NULL) {
                    ReActiveUpdateLocalCache(m_buffer_upstream);
                }
                else {
                    req_conn *req = (req_conn*)arg;
                    bool bRet = req->GetUpdateCacheFlag();
                    if (bRet)
                        ActiveUpgradeLocalPswCache(m_buffer_upstream, (void*)req);
                    else
                       req->ProcessNewPswFromUpstream(m_buffer_upstream);
                }
            }
        }
        //else if ((sockfd == m_sockfd) && (events[i].events & EPOLLOUT) ) 
        else if (events[i].events & EPOLLOUT ) {
            /*
            if () {
                write_nbytes(m_sockfd_downstream, m_buffer_upstream, m_read_upstream_len);
            }
            else {
                write_nbytes(m_sockfd_downstream, m_buffer_upstream, m_read_upstream_len);
            }
            */
        }
        else if(events[i].events & ( EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
            Log("");
            removefd(epollfd, sockfd);
        }
        else
        {
            continue;
        }
    m_read_upstream_idx = 0;
    memset(m_buffer_upstream, 0, 4096);
    memset(m_buffer_downstream, 0, 4096);
    }
}

template< typename T >
bool threadpool< T >::ParseRecvInfo(char *appID, char *valueID, char *pswReturn,char *pswIn, int type, char *seqNumber)
{
    int* pIdentifer = (int*)pswIn;
    long lIdentifer = *pIdentifer;
    lIdentifer = ntohl(lIdentifer);

    if (lIdentifer != 0x1000 && lIdentifer != 0x1100 && lIdentifer != 0x1110)
    {
        Log("recv data head identifer is wrong!");
        return false;
    }

    int nIdentiferType = 0;
    if (lIdentifer == 0x1000)
    nIdentiferType = 0;
    else if (lIdentifer == 0x1100)
    nIdentiferType = 1;
    else
    nIdentiferType = 2;

    int* pPacketLen = (int*)(pswIn + 4);
    int nPacketLen = ntohl(*pPacketLen);
    if (nPacketLen < 8)
    {
        Log("recv data len is wrong!");
        return false;
    }

    char szEnCodeData[4096] = { 0 };
    char pszDecodeData[8192] = {};
    int nPacketDataLen = nPacketLen - 8;
    if (nPacketDataLen > 4096)
    {
        Log("recv data is too big!");
        return false;
    }

    //if (lIdentifer == 0x1000)
    if (lIdentifer == 0x2000)
    {   
        memcpy(szEnCodeData, pswIn + 8, nPacketDataLen);
        memcpy(pszDecodeData, szEnCodeData, nPacketDataLen);
        //*pDecodeDataLen = nPacketDataLen;
        ParseDownstreamInfo(appID, valueID, pszDecodeData, strlen(pszDecodeData));
        //ParseDownstreamInfo(appID, valueID, pszDecodeData, nPacketDataLen);
        //ParseDownstreamXmlInfo(appID, valueID, pszDecodeData, nPacketDataLen);
    }
    else if (lIdentifer == 0x1100)
    {
        nPacketDataLen = nPacketLen - 40;//header + nLen = 8, encode key = 16, random = 16

        unsigned char uszTailData[32] = { 0 };
        memcpy(uszTailData, pswIn + nPacketDataLen + 8, 32);
        unsigned char uszKey[16] = { 0 }, uszSingle[8] = { 0 }, uszDouble[8] = { 0 };
        int nIndex = 0;
        for ( nIndex = 0; nIndex < 8; nIndex++)
        {
            uszSingle[nIndex] = uszTailData[nIndex];
        }

        int i = 0;
        for (i = 0; i < 8; i++)
        {
            uszDouble[i] = uszTailData[i + 16];
        }

        int nKeyIndex = 0, k = 0;
        for (k = 0; k < 8; k++)
        {
            uszKey[nKeyIndex++] = uszSingle[k];
            uszKey[nKeyIndex++] = uszDouble[k];
        }

        int nDecodeLen = 0;
        unsigned char szDeCodeBuffer[5120] = { 0 };
        AES_DecryptDataEVP((unsigned char*)(pswIn + 8), nPacketDataLen, uszKey, szDeCodeBuffer, &nDecodeLen);
        if (nDecodeLen == 0)
        {
            return false;
        }
        memcpy(szEnCodeData, szDeCodeBuffer, nDecodeLen);  
        memcpy(pszDecodeData, szEnCodeData, nDecodeLen);
        //*pDecodeDataLen = nDecodeLen;

        if (type == 0) 
            ParseUpstreamXmlInfo(appID, valueID, pszDecodeData, nDecodeLen, pswReturn);
        else 
            ParseLoginReqXmlData(seqNumber, pszDecodeData, nDecodeLen);

    }
    else if (lIdentifer == 0x1110)
    {
        char szSingleData[5120] = { 0 }, szDoubleData[5120] = { 0 };
        int nRemaider = nPacketDataLen % 2;
        int nSingleLen = 0, nDoubleLen = 0;
        if (nRemaider > 0)
            nSingleLen = (nPacketDataLen - 1) / 2 + 1;
        else
            nSingleLen = nPacketDataLen / 2;
        nDoubleLen = nPacketDataLen - nSingleLen;

        memcpy(szSingleData, pswIn + 8, nSingleLen);
        memcpy(szDoubleData, pswIn + 8 + nSingleLen, nDoubleLen);

        int nEncodeLenIndex = 0, nIndex = 0;
        for (nIndex = 0; nIndex < nDoubleLen; nIndex++)
        {
            szEnCodeData[nEncodeLenIndex++] = szSingleData[nIndex];
            szEnCodeData[nEncodeLenIndex++] = szDoubleData[nIndex];
        }

        if (nRemaider > 0)
        {
            szEnCodeData[nEncodeLenIndex++] = szSingleData[nSingleLen - 1];
        }

        memcpy(pszDecodeData, szEnCodeData, nPacketDataLen);
        //*pDecodeDataLen = nPacketDataLen;
    }
    return true;
}

template< typename T >
void threadpool< T >::ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen)
{
    char *m_vID = NULL;
    m_vID = strpbrk(pszDecodeData,"=");
    if (!m_vID) {
        Log("");
        return;
    }
    *m_vID++ = '\0';
    valueID = m_vID;
    appID = pszDecodeData;
    return;
}

template< typename T >
bool threadpool< T >::ParseDownstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    char szSeqNumber[256] = {0};
    char* pszXmlName = (char*)pXmlSeq;
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlSeq);  

    char szCode[100] = {0};
    pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
    if (pXmlCode == NULL)
    {
        Log("get code element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    pszXmlName = (char*)pXmlCode;
    memcpy(szCode, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlCode);

    xmlNodePtr nodeChild;
    nodeChild = xmlRoot->children;
    if (nodeChild == NULL)
    {
        Log("get child element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(nodeChild->name, (const xmlChar*)"appid") != 0) {
        xmlFreeDoc(doc);
        return false;
    }
    xmlChar* pXmlAppID = NULL;
    pXmlAppID = xmlNodeGetContent(nodeChild);
    if (pXmlAppID == NULL) {
        xmlFreeDoc(doc);
        return false;
    }
    char szAppID[64] = {0};
    char* pXmlAppIDInfo = (char*)pXmlAppID;
    int nAppIDLen = strlen(pXmlAppIDInfo);
    if (nAppIDLen >= 64) 
        memcpy(szAppID, pXmlAppIDInfo, 63);
    else
        memcpy(szAppID, pXmlAppIDInfo, nAppIDLen);
    xmlFree(pXmlAppID);

    xmlNodePtr pValueIDNode = xmlRoot->children->next;
    if (pValueIDNode == NULL) {
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(pValueIDNode->name, (const xmlChar*)"valutid") != 0) {
        xmlFreeDoc(doc);
        return false;
    }
    xmlChar* pXmlValueID = NULL;
    pXmlValueID = xmlNodeGetContent(pValueIDNode);
    if (pXmlValueID == NULL) {
        xmlFreeDoc(doc);
        return false;
    }
    char szValueID[128] = {0};
    char* pXmlValueInfo = (char*)pXmlValueID;
    int nValueLen = strlen(pXmlValueInfo);
    if (nValueLen >= 128)
        memcpy(szValueID, pXmlValueInfo, 128);
    else
        memcpy(szValueID, pXmlValueInfo, nValueLen);

    memcpy(valueID, szValueID, strlen(szValueID));
    memcpy(appID, szAppID, strlen(szAppID));

    xmlFree(pXmlValueID);
    xmlFreeDoc(doc);

    /*
    bool bSeqNumberValid = false;
    if (memcmp(pszSeqNumber, szSeqNumber, strlen(szSeqNumber)) == 0 &&
    memcmp(szSeqNumber, pszSeqNumber, strlen(pszSeqNumber)) == 0)
        bSeqNumberValid = true;

    if (!bSeqNumberValid)
    {
        //memcpy(pszErrorInfo, "get seq number is not same to send seq number", strlen("get seq number is not same to send seq number"));
        return false;
    }

    int nCode = atol(szCode);
    if (nCode > 0)
    {
        *pnErrorCode = nCode;
        //memcpy(pszErrorInfo, "get password error,please check the send data", strlen("get password error,please check the send data"));       
        return false;
    }
    */
    return true;
}

template< typename T >
bool threadpool< T >::ParseUpstreamXmlInfo(int *appID, int *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        Log("get seq element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    char szSeqNumber[256] = {0};
    char* pszXmlName = (char*)pXmlSeq;
    memcpy(szSeqNumber, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlSeq);  

    char szCode[100] = {0};
    pXmlCode = xmlGetProp(xmlRoot, BAD_CAST("code"));
    if (pXmlCode == NULL)
    {
        Log("get code element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    pszXmlName = (char*)pXmlCode;
    memcpy(szCode, pszXmlName, strlen(pszXmlName));
    xmlFree(pXmlCode);

    xmlNodePtr nodeChild;
    nodeChild = xmlRoot->children;
    if (nodeChild == NULL)
    {
        Log("get child element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlPassword = NULL;   
    pXmlPassword = xmlNodeGetContent(nodeChild);
    if (pXmlPassword == NULL)
    {
        Log("get password element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    char* pszPassword = (char*)pXmlPassword;
    int nPswInfoLen = strlen(pszPassword);
    if (nPswInfoLen > 200)
        memcpy(pswOut, pszPassword, 200);
    else
        memcpy(pswOut, pszPassword, nPswInfoLen);

    xmlFree(pXmlPassword);
    xmlFreeDoc(doc); 

    /*
    bool bSeqNumberValid = false;
    if (memcmp(m_SeqNumber, szSeqNumber, strlen(szSeqNumber)) == 0 &&
    memcmp(szSeqNumber, m_SeqNumber, strlen(m_SeqNumber)) == 0)
        bSeqNumberValid = true;

    if (!bSeqNumberValid)
    {
        Log("get seq number is not same to send seq number");
        return false;
    }

    int nCode = atol(szCode);
    if (nCode > 0)
    {
        Log("get password error,please check the send data");       
        return false;
    }
    */
    return true;

}

template< typename T >
void threadpool< T >::ReActiveUpdateLocalCache(char *buf)
{
    char *appID = NULL, *valueID = NULL, *pswSendData = NULL;
    ParseRecvInfo(appID, valueID, pswSendData, buf);
    ReplaceLocalPswCache(appID, valueID, pswSendData);
}

template< typename T >
bool threadpool< T >::ActiveUpgradeLocalPswCache(char *buf, void *arg)
{
    char *appID = NULL, *valueID = NULL, *pswSendData = NULL;
    req_conn *req = (req_conn*)arg;
    ParseRecvInfo(appID, valueID, pswSendData, buf);
    appID = req->GetAppID();
    valueID = req->GetValueID();
    ReplaceLocalPswCache(appID, valueID, pswSendData);
}

template< typename T >
bool threadpool< T >::ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo)
{
    long lAppID = atol(appID);

    sLocalPswCacheInfo ps;
    ps.lAppID = lAppID;
    if (valueID != NULL) {
        memcpy(ps.szVaultID, valueID, strlen(valueID));
    }
    else {
        memcpy(ps.szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
    }
    memcpy(ps.szPassword, pswInfo, strlen(pswInfo));
    ps.tmChange = time(0);

    m_LocalPswCacheMapLocker.lock();
    m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo>::value_type(lAppID, ps));
    m_LocalPswCacheMapLocker.unlock();
    m_cachestat.post();
}

template< typename T >
bool threadpool< T >::GetPvaFromLocal(char *appID, char *valueID, char *pswbuf)
{
    assert(appID != NULL);
    m_LocalPswCacheMapLocker.lock();
    if ( m_LocalPswCacheMap.empty()) {
        Log("无密码缓存");
        m_LocalPswCacheMapLocker.unlock();
        return false;
    }
    std::map<long, sLocalPswCacheInfo>::iterator It = m_LocalPswCacheMap.begin();
    It = m_LocalPswCacheMap.find(atol(appID));
    if (It != m_LocalPswCacheMap.end()) {
        memcpy(pswbuf, (*It).second.szPassword, strlen((*It).second.szPassword));
        m_LocalPswCacheMapLocker.unlock();
        return true;
    }
    else {
        m_LocalPswCacheMapLocker.unlock();
        return false;
    }
}

template< typename T >
bool threadpool< T >::UpdateLocalPswCache()
{
    bool bRet;
    bRet = m_FirstUpdateFlagLocker.trylock();
    if (bRet) {
        bool bFirstUpdateFlag = m_first_update_flag;
        m_FirstUpdateFlagLocker.unlock();
        if (!bFirstUpdateFlag) {
            bRet = LoadPswFromLocalCacheFile();
            if (!bRet) {
                Log("加载本地密码缓存失败");
                return false;
            }
        }
    }
    bRet = m_FirstCheckIsUpdateFlagLocker.trylock();
    if (bRet) {
        bool bFirstCheckIsUpdateFlag = m_first_checkisupdate_flag;
        m_FirstCheckIsUpdateFlagLocker.unlock();
        if (!bFirstCheckIsUpdateFlag) {
            bRet = CheckIsNeedUpdate();
            if (!bRet) {
                return false;
            }
        }
    }
    return true;
}

template< typename T >
bool threadpool< T >::GetOnePswFromLocalCache(char *appID, char *pswReturn)
{
    m_LocalPswCacheMapLocker.lock();
    if (m_LocalPswCacheMap.empty()) {
        m_LocalPswCacheMapLocker.unlock();
        return false;
    }
    std::map<long, sLocalPswCacheInfo>::iterator It = m_LocalPswCacheMap.begin();
    It = m_LocalPswCacheMap.find(atol(appID));
    if (It != m_LocalPswCacheMap.end()) {
        memcpy(pswReturn, (*It).second.szPassword, strlen((*It).second.szPassword));
        m_LocalPswCacheMapLocker.unlock();
        return true;
    }
    else {
        m_LocalPswCacheMapLocker.unlock();
        return false;
    }
}

template< typename T >
bool threadpool< T >::CheckIsNeedUpdate()
{
    int n = 0;
    time_t tmCurrent = time(0);
    m_LocalPswCacheMapLocker.lock();
    std::map<long, sLocalPswCacheInfo>::iterator It = m_LocalPswCacheMap.begin();
    while (It != m_LocalPswCacheMap.end())
    {
        if ((*It).second.tmChange + 60 < tmCurrent) {
            req_conn user;
            user.Init(true);
            char appID[128] = {0};
            sprintf(appID, "%ld", (*It).first);
            user.SetAppID(appID);
            user.SetValueID((*It).second.szVaultID);
            append(&user);
            n++;
            memset(appID, 0, 128);
        }
        It++;
    }
    m_LocalPswCacheMapLocker.unlock();
    bool bRet = m_FirstCheckIsUpdateFlagLocker.trylock();
    if (bRet) {
        m_first_checkisupdate_flag = true;
        m_FirstCheckIsUpdateFlagLocker.unlock();
    }
    if (n == 0)
        return false;
    return true;
}

template< typename T >
bool threadpool< T >::LoadPswFromLocalCacheFile()
{
    char* pszPvaFile = "pvabuffer.bin";
    FILE* pFile = NULL;
    pFile = fopen(pszPvaFile, "rb");
    if (pFile == NULL)
    {
        Log("open password file failed");
        return false;
    }

    fseek(pFile, 0, SEEK_END);
    long lFileSize = ftell(pFile);
    if (lFileSize == 0)
    {
        Log("get password file size failed");
        fclose(pFile);
        remove(pszPvaFile);
        return false;
    }
    rewind(pFile);

    long nFileType = 0;
    fread(&nFileType, sizeof(long), 1, pFile);
    if (ntohl(nFileType) != 0x1100) //file type identify
    {
        Log("get password file head type failed");    
        fclose(pFile);
        return false;
    }

    lFileSize -= sizeof(long);
    char* pszDataBuffer= (char*)malloc(lFileSize + 1);
    if (pszDataBuffer == NULL)
    {
        Log("malloc save file buffer failed");
        fclose(pFile);
        return false;
    }

    memset(pszDataBuffer, 0, lFileSize + 1);
    long nDataLen = 0;
    while (nDataLen < lFileSize)
    {
        char szBuffer[40960] = {0};
        int nReadLen = fread(szBuffer, sizeof(char), 40960, pFile);
        if (nReadLen > 0)
        {
            memcpy(pszDataBuffer, szBuffer, nReadLen);
            nDataLen += nReadLen;
        }
        else
            break;
    }
    fclose(pFile);

    if (nDataLen < lFileSize)
    {
        Log("read password file buffer failed");
        free(pszDataBuffer);
        return false;
    }

    char* pszDecodeData = (char*)malloc(lFileSize * 2);
    if (pszDecodeData == NULL)
    {
        Log("malloc decode buffer failed");
        free(pszDataBuffer);
        return false;
    }
    memset(pszDecodeData, 0, lFileSize * 2);

    unsigned char szEncodeKey[16] = {0};
    unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
    int nIndex = 0;
    for (nIndex = 0; nIndex < 16; nIndex++)
    {
        if (nIndex % 3 == 0)
        {
            szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
        }
        else if (nIndex % 3 == 1)
        {
            szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
        }
        else
        {
            szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
        }
    }
    int nDecodeLen = 0;
    AES_DecryptDataEVP((unsigned char*)pszDataBuffer, lFileSize, szEncodeKey, pszDecodeData, &nDecodeLen);
    if (nDecodeLen == 0)
    {
        Log("decode file buffer failed");

        free(pszDataBuffer);
        free(pszDecodeData);
        return false;
    }
    free(pszDataBuffer);

    char szPassword[64];
    nDataLen = 0;
    long lAppID = 0;
    int nBufferLen = 0;
    time_t tmTimeChange;
    while (nDataLen < nDecodeLen)
    {
        memcpy(&lAppID, pszDecodeData + nDataLen, sizeof(long));
        nDataLen += sizeof(long);

        memcpy(&nBufferLen, pszDecodeData + nDataLen, sizeof(int));
        nDataLen += sizeof(int);

        memset(szPassword, 0, sizeof(szPassword));
        if (nBufferLen > 63)    //password buffer size is 64;
            break;

        memcpy(szPassword, pszDecodeData + nDataLen, nBufferLen);
        nDataLen += nBufferLen;

        memcpy(&tmTimeChange, pszDecodeData + nDataLen, sizeof(time_t));
        nDataLen += sizeof(time_t);

        sLocalPswCacheInfo ps;
        ps.lAppID = lAppID;
        memcpy(ps.szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        memcpy(ps.szPassword, szPassword, nBufferLen);
        ps.tmChange = tmTimeChange;
        m_LocalPswCacheMapLocker.lock();
        m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo>::value_type(lAppID, ps));
        m_LocalPswCacheMapLocker.unlock();

    }
    bool bRet = m_FirstUpdateFlagLocker.trylock();
    if (bRet) {
        m_first_update_flag = true;
        m_FirstUpdateFlagLocker.unlock();
    }
    free(pszDecodeData);
    return true;
}

template< typename T >
void threadpool< T >::SavePswToLocalCacheFile()
{
    char* pszPvaFile = "pvabuffer.bin";
    remove(pszPvaFile);

    FILE* pFile = NULL;
    pFile = fopen(pszPvaFile, "wb");
    if (pFile == NULL)
        return;

    long lFileType = htonl(0x1100);
    fwrite(&lFileType, sizeof(long), 1, pFile);

    unsigned char szEncodeKey[16] = {0};
    unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
    int nIndex = 0;
    for (nIndex = 0; nIndex < 16; nIndex++)
    {
        if (nIndex % 3 == 0)
        {
            szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
        }
        else if (nIndex % 3 == 1)
        {
            szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
        }
        else
        {
            szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
        }
    }

    int  nBufferIndex = 0, nPasswordLen = 0;
    char szBuffer[81920] = {0};
    int i = 0;

    m_LocalPswCacheMapLocker.lock();
    if (m_LocalPswCacheMap.empty()) {
        Log("");
        return;
    }
    std::map<long, sLocalPswCacheInfo>::iterator It = m_LocalPswCacheMap.begin();
    while (It != m_LocalPswCacheMap.end())
    {
        memcpy(szBuffer + nBufferIndex, &((*It).first), sizeof(long));
        nBufferIndex += sizeof(long);
        nPasswordLen = strlen((*It).second.szPassword);
        memcpy(szBuffer + nBufferIndex, &nPasswordLen, sizeof(int));
        nBufferIndex += sizeof(int);
        memcpy(szBuffer + nBufferIndex, (*It).second.szPassword, nPasswordLen);
        nBufferIndex += nPasswordLen;
        memcpy(szBuffer + nBufferIndex, &((*It).second.tmChange), sizeof(time_t));
        nBufferIndex += sizeof(time_t);
        It++;
    }
    m_LocalPswCacheMapLocker.unlock();

    char uszEncodeData[102400] = {0};
    int nEncodeLen = 0;
    AES_CryptDataEVP((unsigned char*)szBuffer, nBufferIndex, szEncodeKey, uszEncodeData, &nEncodeLen);

    int nDataLen = 0;
    while (nEncodeLen > 0)
    {
        int nWriteLen = fwrite(uszEncodeData + nDataLen, sizeof(char), nEncodeLen, pFile);
        if (nWriteLen <= 0)
            break;
        nEncodeLen -= nWriteLen;
        nDataLen += nWriteLen;
    }
    //memset(szBuffer, 0, sizeof(szBuffer));

    fclose(pFile);
}

template< typename T >
int threadpool< T >::PthreadCondTimedwait(struct timespec ts)
{
    int ret = m_UpdateCacheCond.timedwait(ts);
    if (ret == 0) {
        return 0;
    }
    Log("");
    return -1;
}

