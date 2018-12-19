#ifndef _THREAD_POOL_H
#define _THREAD_POOL_H

#include <list>
#include <cstdio>
#include <exception>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <cassert>
#include <fcntl.h>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include <map>
#include "locker.h"
#include "thread_pool.h"
#include "cryptdatafunc.h"
#include "req_conn.h"
#include "libxml/parser.h"
#include "libxml/parser.h"

typedef struct _sLocalPswCacheInfo
{
    long        lAppID;
    char        szPassword[64];
    char        szVaultID[128];
    time_t      tmChange;

}sLocalPswCacheInfo, *psLocalPswCacheInfo;

typedef struct _sPthreadFdInfo
{
    pthread_t fd;
    int isOnline;
}sPthreadFdInfo, *psPthreadFdInfo;

class req_conn;

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
        std::map<long, sLocalPswCacheInfo*> m_LocalPswCacheMap;
        std::list<sLocalPswCacheInfo*> m_UpdateDatFileList;

        locker m_UpdateDatFileListLocker;
        locker m_PthreadFdLocker;
        locker m_LocalPswCacheMapLocker;
        locker m_NetworkStateLocker;
        locker m_OnceConnectLocker;
        locker m_FirstUpdateFlagLocker;
        locker m_FirstCheckIsUpdateFlagLocker;

        cond m_UpdateCacheCond;

    private:
        //static void* worker( void* arg );
        void Run(struct pollfd &pfd, int sockfd);
        bool LoginPvaServer(char *mainIP, char *standbyIP, int &sockfd);
        bool SetupPollListen(struct pollfd &pfd, int sockfd);
        void ReadPvaPoll(struct pollfd &pfd, int &needrelogin, void *arg = NULL);
        bool LoadRawPswCacheFromBinFile();
        bool LoadPswCachedFromDatFile(char *pszErrorInfo);

    public:
        static void* WorkerThread( void* arg );
        static void* WorkerSaveCacheDatFileThread( void* arg );
        static void* WorkerWriteLogFileThread( void* arg );
        bool GetNetworkState() 
        { 
            unsigned int nState;
            m_NetworkStateLocker.lock();
            nState = m_network_state ; 
            printf("network state count: %d\n", nState);
            m_NetworkStateLocker.unlock();
            if (nState == m_pfd_count)
                return false; 
            else 
                return true;
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
        bool ParseRecvInfo2(char *appID, char *valueID, char *pswReturn, char *pswIn, int type = 0, char *seqNumber = NULL);
        bool ParseDownstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen);
        bool ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut);
        bool VerifyLogin(int sockfd, char *szLocalIP);
        int EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType);
        bool SendDataToServer2(int pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
        bool GetDataFromServer(int pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo);
        bool ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen);
        void Log(const char* ms, ... );  
        //void ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen);
        void RunWriteLogFileThread();  
        void RunSaveCacheFileThread();
        void ChangeVariableNetworkState(pthread_t pfd, bool isOnline = true);
        bool NotifyUpdaeCache();
        void RunSaveCacheDatFileThread();
        void SavePswToLocalCacheDatFile(psLocalPswCacheInfo pswNew);
        void ChangePollFdCount();
        char* GetMainIP() { return m_mainIP; }
        char* GetStandbyIP() { return m_standbyIP; }
        int SetNonBlocking(int fd);
        void SetLoclaIPAddress();

    private:
        sPthreadFdInfo pfds[8];
        int m_pfd_count;

        char m_LocalIP[128];
        int m_thread_number;
        int m_max_requests;
        pthread_t* m_threads;
        std::list< T* > m_workqueue;
        //std::list<sLocalPswCacheInfo*> m_workcachequeue;
        std::list< int > m_workcachequeue;
        std::list< char* > m_worklogqueue;
        locker m_queuelocker;
        //locker m_cachelocker;
        locker m_loglocker;
        sem m_queuestat;
        sem m_cachestat;
        sem m_logstat;
        bool m_stop;
        char m_mainIP[80];
        char m_standbyIP[80];
        unsigned int m_network_state;
        int m_read_upstream_idx;
        int m_read_upstream_len;
        char m_buffer_upstream[4096];
        char m_buffer_downstream[4096];
        bool m_first_update_flag;
        bool m_first_checkisupdate_flag;
        bool bOnceConnect;

};

template< typename T >
threadpool< T >::threadpool( const char *remote_mainIP, const char *remote_standbyIP, int thread_number, int max_requests ) : 
        m_thread_number( thread_number ), m_max_requests( max_requests ), m_stop( false ), m_threads( NULL )
{
    memset(m_mainIP, 0, 80);
    memset(m_standbyIP, 0, 80);
    memcpy(m_mainIP, const_cast<char*>(remote_mainIP), strlen(const_cast<char*>(remote_mainIP)));
    memcpy(m_standbyIP, const_cast<char*>(remote_standbyIP), strlen(const_cast<char*>(remote_standbyIP)));
    //m_LocalPswCacheMap.clear();
    if( ( thread_number <= 0 ) || ( max_requests <= 0 ) )
    {
        throw std::exception();
    }

    pthread_t saveThr, logThr;
    if( pthread_create( &saveThr, NULL, WorkerSaveCacheDatFileThread, this ) != 0 )
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
    SetLoclaIPAddress();

    bool bRet;
    static unsigned int nReLoadCount = 0;
    char *sError = NULL;
RELOADFROMBIN:
        bRet = LoadRawPswCacheFromBinFile();
    if (!bRet) {
        //Log("(%s %d) load bin file fail try num: %u", __func__, __LINE__, nReLoadCount + 1);
        nReLoadCount++;
        if (nReLoadCount >= 2){
            nReLoadCount = 0;
            goto RELOADFROMDAT;
        }
        goto RELOADFROMBIN;
    }

RELOADFROMDAT:
    bRet =  LoadPswCachedFromDatFile(sError);
    if (!bRet) {
        //Log("(%s %d) %s", __func__, __LINE__, "load dat file fail");
    }
}

template< typename T >
threadpool< T >::~threadpool()
{
    delete [] m_threads;
    m_stop = true;
}

template< typename T >
bool threadpool< T >::LoadRawPswCacheFromBinFile()
{
    char* pszPvaFile = "pvabuffer.bin";
    FILE* pFile = NULL;
    pFile = fopen(pszPvaFile, "rb");
    if (pFile == NULL)
    {
		//memcpy(pszErrorInfo, "open password file failed", strlen("open password file failed"));
		return false;
    }
	
    fseek(pFile, 0, SEEK_END);
    long lFileSize = ftell(pFile);
    if (lFileSize == 0)
    {
		//memcpy(pszErrorInfo, "get password file size failed", strlen("get password file size failed"));
        //Log("(%s %d) %s", __func__, __LINE__, "get password file size failed");
		fclose(pFile);
		remove(pszPvaFile);
        return false;
    }
    rewind(pFile);
	
    long nFileType = 0;
    fread(&nFileType, sizeof(long), 1, pFile);
    if (ntohl(nFileType) != 0x1100) //file type identify
    {
		//memcpy(pszErrorInfo, "get password file head type failed", strlen("get password file head type failed"));	
		fclose(pFile);
		return false;
    }

    lFileSize -= sizeof(long);
    char* pszDataBuffer= (char*)malloc(lFileSize + 1);
    if (pszDataBuffer == NULL)
    {
		//memcpy(pszErrorInfo, "malloc save file buffer failed", strlen("malloc save file buffer failed"));
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
		//memcpy(pszErrorInfo, "read password file buffer failed", strlen("read password file buffer failed"));
		free(pszDataBuffer);
		return false;
	}
	
	char* pszDecodeData = (char*)malloc(lFileSize * 2);
	if (pszDecodeData == NULL)
	{
		//memcpy(pszErrorInfo, "malloc decode buffer failed", strlen("malloc decode buffer failed"));
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
	//AES_DecryptDataEVP((unsigned char*)pszDataBuffer, lFileSize, szEncodeKey, pszDecodeData, &nDecodeLen);
	AES_DecryptDataEVP(reinterpret_cast<unsigned char*>(pszDataBuffer), lFileSize, szEncodeKey, reinterpret_cast<unsigned char*>(pszDecodeData), &nDecodeLen);
	if (nDecodeLen == 0)
	{
		//memcpy(pszErrorInfo, "decode file buffer failed", strlen("decode file buffer failed"));
		
		free(pszDataBuffer);
		free(pszDecodeData);
		return false;
	}
	free(pszDataBuffer);
	
	char szPassword[64];
	nDataLen = 0;
	long lAppID = 0;
	int nBufferLen = 0;
	while (nDataLen < nDecodeLen)
	{
		memcpy(&lAppID, pszDecodeData + nDataLen, sizeof(long));
		nDataLen += sizeof(long);
		
		memcpy(&nBufferLen, pszDecodeData + nDataLen, sizeof(int));
		nDataLen += sizeof(int);
		
		memset(szPassword, 0, sizeof(szPassword));
		if (nBufferLen > 63)	//password buffer size is 64;
			break;
		
		memcpy(szPassword, pszDecodeData + nDataLen, nBufferLen);
		nDataLen += nBufferLen;

		sLocalPswCacheInfo *ps;
        ps->lAppID = lAppID;
        memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        memcpy(ps->szPassword, szPassword, nBufferLen);
        ps->tmChange = (time_t)0;
        m_LocalPswCacheMapLocker.lock();
        m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo*>::value_type(lAppID, ps));
        m_LocalPswCacheMapLocker.unlock();

	}

	free(pszDecodeData);
    return true;

}

template< typename T >
bool threadpool< T >::LoadPswCachedFromDatFile(char *pszErrorInfo)
{
    DIR *dirp;
    struct dirent *direntp;
    char g_CurAbsolutePath[256];
    char g_CacheFileAbsolutePath[256];

    memset(g_CurAbsolutePath, '\0', 256);
    memset(g_CacheFileAbsolutePath, '\0', 256);
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    sprintf(g_CacheFileAbsolutePath, "%s/%s",g_CurAbsolutePath, "PSWCache");

    if ((dirp = opendir(g_CacheFileAbsolutePath)) == NULL) {
        //memcpy(pszErrorInfo, "get password cache dat file failed", strlen("get password cache dat file failed"));
        //Log("(%s %d) %s", __func__, __LINE__, "get password cache dat file failed");
        return false;
    }

    char tempDatPath[256] = {0};
    while ((direntp = readdir(dirp)) != NULL) {
        if (strstr(direntp->d_name, ".dat") != NULL) {
            memset(tempDatPath, '\0', 256);
            sprintf(tempDatPath, "%s/%s", g_CacheFileAbsolutePath, direntp->d_name);
            FILE* pFile = NULL;
            pFile = fopen(tempDatPath, "rb");
            if (pFile == NULL)
            { 
                //memcpy(pszErrorInfo, "open password file failed", strlen("open password file failed"));
                return false;
            }
            
            fseek(pFile, 0, SEEK_END);
            long lFileSize = ftell(pFile);
            if (lFileSize == 0)
            {
                //Log("(%s %d) read %s", __func__, __LINE__, direntp->d_name);
                //memcpy(pszErrorInfo, "get password file size failed", strlen("get password file size failed"));
                fclose(pFile);
                remove(direntp->d_name);
                return false;
            }
            rewind(pFile);
            
            long nFileType = 0;
            fread(&nFileType, sizeof(long), 1, pFile);
            if (ntohl(nFileType) != 0x1100) //file type identify
            {
                //Log("(%s %d) read %s %s", __func__, __LINE__, direntp->d_name, "read head type failed");
                //memcpy(pszErrorInfo, "get password file head type failed", strlen("get password file head type failed"));	
                fclose(pFile);
                return false;
            }

            lFileSize -= sizeof(long);
            char* pszDataBuffer= (char*)malloc(lFileSize + 1);
            if (pszDataBuffer == NULL)
            {
                //Log("(%s %d) %s", __func__, __LINE__, "malloc save file buffer failed");
                //memcpy(pszErrorInfo, "malloc save file buffer failed", strlen("malloc save file buffer failed"));
                fclose(pFile);
                return false;
            }
            
            memset(pszDataBuffer, 0, lFileSize + 1);
            long nDataLen = 0;
            while (nDataLen < lFileSize)
            {
                char szBuffer[1024] = {0};
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
                //Log("(%s %d) %s", __func__, __LINE__, "read password file buffer failed");
                //memcpy(pszErrorInfo, "read password file buffer failed", strlen("read password file buffer failed"));
                free(pszDataBuffer);
                return false;
            }
            
            char* pszDecodeData = (char*)malloc(lFileSize * 2);
            if (pszDecodeData == NULL)
            {
                //Log("(%s %d) %s", __func__, __LINE__, "malloc decode buffer failed");
                //memcpy(pszErrorInfo, "malloc decode buffer failed", strlen("malloc decode buffer failed"));
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
            //AES_DecryptDataEVP((unsigned char*)pszDataBuffer, lFileSize, szEncodeKey, pszDecodeData, &nDecodeLen);
            AES_DecryptDataEVP(reinterpret_cast<unsigned char*>(pszDataBuffer), lFileSize, szEncodeKey, reinterpret_cast<unsigned char*>(pszDecodeData), &nDecodeLen);
            if (nDecodeLen == 0)
            {
                //Log("(%s %d) %s", __func__, __LINE__, "decode file buffer failed");
                //memcpy(pszErrorInfo, "decode file buffer failed", strlen("decode file buffer failed"));
                
                free(pszDataBuffer);
                free(pszDecodeData);
                return false;
            }
            free(pszDataBuffer);
            
            char szPassword[64];
            nDataLen = 0;
            long lAppID = 0;
            int nBufferLen = 0;
            time_t tmTimeChange = 0;
            while (nDataLen < nDecodeLen)
            {
                memcpy(&lAppID, pszDecodeData + nDataLen, sizeof(long));
                nDataLen += sizeof(long);
                
                memcpy(&nBufferLen, pszDecodeData + nDataLen, sizeof(int));
                nDataLen += sizeof(int);
                
                memset(szPassword, 0, sizeof(szPassword));
                if (nBufferLen > 63)	//password buffer size is 64;
                    break;
                
                memcpy(szPassword, pszDecodeData + nDataLen, nBufferLen);
                nDataLen += nBufferLen;
                memcpy(&tmTimeChange, pszDecodeData + nDataLen, sizeof(time_t));
                nDataLen += sizeof(time_t);

                sLocalPswCacheInfo *ps;
                ps->lAppID = lAppID;
                memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
                memcpy(ps->szPassword, szPassword, nBufferLen);
                ps->tmChange = tmTimeChange;

                if (!m_LocalPswCacheMap.empty()) {
                    m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo*>::value_type(lAppID, ps));
                }
                else {
                    std::map<long, sLocalPswCacheInfo*>::iterator It = m_LocalPswCacheMap.begin();
                    It = m_LocalPswCacheMap.find(lAppID);
                    if (It != m_LocalPswCacheMap.end()) {
                        if (strcmp((*It).second->szPassword, szPassword) == 0) {
                            (*It).second->tmChange = tmTimeChange;
                        }
                        else {
                            memset((*It).second->szPassword, 0, sizeof((*It).second->szPassword));
                            memcpy((*It).second->szPassword, szPassword, strlen(szPassword));
                            (*It).second->tmChange = tmTimeChange;
                        }
                    }
                    else {
                        m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo*>::value_type(lAppID, ps));
                    }
                }
            }
            free(pszDecodeData);
        }
    }
    if (direntp == NULL) {
        if (m_LocalPswCacheMap.empty()) 
            goto END;
    }

END:
    closedir(dirp);
    return true;

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
    FILE* pFile = fopen("pvadll.log","a+");
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
        //FILE* pFile = fopen("pvadll.log","a+");
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
void* threadpool< T >::WorkerSaveCacheDatFileThread( void* arg )
{
    threadpool *pool = (threadpool*)arg;

    pool->RunSaveCacheDatFileThread();
    return pool;
}

template< typename T >
void threadpool< T >::RunSaveCacheDatFileThread()
{
    while (1) 
    {
        m_cachestat.wait();

        m_UpdateDatFileListLocker.lock();
        if (m_UpdateDatFileList.empty()) {
            m_UpdateDatFileListLocker.unlock();
            continue;
        }
        sLocalPswCacheInfo *spsw = m_UpdateDatFileList.front();
        m_UpdateDatFileList.pop_front();
        m_UpdateDatFileListLocker.unlock();
        if (! spsw)
            continue;

        SavePswToLocalCacheDatFile(spsw);
        //SavePswToLocalCacheFile();
    }
}

template< typename T >
void threadpool< T >::SavePswToLocalCacheDatFile(sLocalPswCacheInfo *pswNew)
{
    if (!pswNew)
        return;

    char g_CurAbsolutePath[256];
    char g_CacheFileAbsolutePath[256];

    memset(g_CurAbsolutePath, '\0', 256);
    memset(g_CacheFileAbsolutePath, '\0', 256);
    if (NULL == getcwd(g_CurAbsolutePath, 256)) {
    }
    sprintf(g_CacheFileAbsolutePath, "%s/%s/%ld.dat",g_CurAbsolutePath, "PSWCache", pswNew->lAppID);
    if (access(g_CacheFileAbsolutePath, F_OK) == 0)
        remove(g_CacheFileAbsolutePath);

    FILE* pFile = NULL;
    pFile = fopen(g_CacheFileAbsolutePath, "wb");
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
    char szBuffer[2048] = {0};
    int i = 0;

    memcpy(szBuffer + nBufferIndex, &(pswNew->lAppID), sizeof(long));
    nBufferIndex += sizeof(long);
    nPasswordLen = strlen(pswNew->szPassword);
    memcpy(szBuffer + nBufferIndex, &nPasswordLen, sizeof(int));
    nBufferIndex += sizeof(int);
    memcpy(szBuffer + nBufferIndex, pswNew->szPassword, nPasswordLen);
    nBufferIndex += nPasswordLen;
    memcpy(szBuffer + nBufferIndex, &(pswNew->tmChange), sizeof(time_t));
    nBufferIndex += sizeof(time_t);

    char uszEncodeData[4096] = {0};
    int nEncodeLen = 0;
    AES_CryptDataEVP(reinterpret_cast<unsigned char*>(szBuffer), nBufferIndex, szEncodeKey, reinterpret_cast<unsigned char*>(uszEncodeData), &nEncodeLen);
    //AES_DecryptDataEVP(reinterpret_cast<unsigned char*>(pszDataBuffer), lFileSize, szEncodeKey, reinterpret_cast<unsigned char*>(pszDecodeData), &nDecodeLen);

    int nDataLen = 0;
    while (nEncodeLen > 0)
    {
        int nWriteLen = fwrite(uszEncodeData + nDataLen, sizeof(char), nEncodeLen, pFile);
        if (nWriteLen <= 0)
            break;
        nEncodeLen -= nWriteLen;
        nDataLen += nWriteLen;
    }

    fclose(pFile);
}

template< typename T >
void threadpool< T >::ChangeVariableNetworkState(pthread_t pfd, bool isOnline)
{
    int i;
    m_PthreadFdLocker.lock();
    for (i = 0; i < m_pfd_count; i++) {
        if (pfds[i].fd == pfd && pfds[i].isOnline == 1) {
            if (isOnline) {
                m_NetworkStateLocker.lock();
                m_network_state-- ; 
                pfds[i].isOnline = 0;
                m_NetworkStateLocker.unlock();
            }
            break;
        }
        else if (pfds[i].fd == pfd && pfds[i].isOnline == -1) {
            if (!isOnline) {
                m_NetworkStateLocker.lock();
                m_network_state++ ; 
                pfds[i].isOnline= 1;
                m_NetworkStateLocker.unlock();
            }
            break;
        }
        else if (pfds[i].fd == pfd && pfds[i].isOnline == 0) {
            if (!isOnline) {
                m_NetworkStateLocker.lock();
                m_network_state++ ; 
                pfds[i].isOnline = 1;
                m_NetworkStateLocker.unlock();
            }
            break;
        }
    }
    m_PthreadFdLocker.unlock();
}

template< typename T >
void threadpool< T >::ChangePollFdCount()
{
    m_PthreadFdLocker.lock();
    pfds[m_pfd_count].fd = pthread_self();
    pfds[m_pfd_count].isOnline = -1;
    m_pfd_count++;
    m_PthreadFdLocker.unlock();
}

template< typename T >
void* threadpool< T >::WorkerThread( void* arg )
{
    //bool bOnceConnect = false;
    int err = pthread_detach( pthread_self() );

    threadpool* pool = ( threadpool* )arg;
    pool->ChangePollFdCount();
    if( err != 0 )
    {
        delete [] (pool->get_threads());
        throw std::exception();
    }

    int sockfd;

RELOGIN:
    bool ret = pool->LoginPvaServer(pool->GetMainIP(), pool->GetStandbyIP(), sockfd);
    if (!ret) {
        //Log("");
        pool->ChangeVariableNetworkState(pthread_self(), false);
        return NULL;
        //goto RELOGIN;
        
    }
    pool->ChangeVariableNetworkState(pthread_self());

    //pool->UpdateLocalPswCache();

    pool->NotifyUpdaeCache();

    struct pollfd spfd;
    pool->SetupPollListen(spfd, sockfd);
    pool->Run(spfd, sockfd);
    return pool;

}

template< typename T>
bool threadpool< T >::NotifyUpdaeCache()
{
    //bool bOnceConnect = false;
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
bool threadpool< T >::SetupPollListen(struct pollfd &pfd, int sockfd)
{
    pfd.fd = sockfd;
    pfd.events = POLLIN | POLLERR | POLLHUP;
    pfd.revents = 0;
    //addfd();

}

template< typename T>
bool threadpool< T >::LoginPvaServer(char *mainIP, char *standbyIP, int &sockfd)
{
    struct sockaddr_in address;
    int reuse, on, n = 0;
    int m_tryconnect_count = 0;
    int m_sockfd;

RETRY:
    { /*connect remote main ip*/
        //bzero( &address, sizeof( address ) );
        memset( &address, 0, sizeof( address ) );
        address.sin_family = AF_INET;
        inet_pton( AF_INET, mainIP, &address.sin_addr );
        address.sin_port = htons( 9933 );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting main password server\n" );
        if( m_sockfd < 0 )
        {
            //Log("");
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
        //Log("");
        close(m_sockfd);
    }

    { /*connect remote standby ip*/
        //bzero( &address, sizeof( address ) );
        memset( &address, 0, sizeof( address ) );
        address.sin_family = AF_INET;
        inet_pton( AF_INET, standbyIP, &address.sin_addr );
        address.sin_port = htons( 9933 );
        m_sockfd = -1;
        m_sockfd = socket( PF_INET, SOCK_STREAM, 0 );
        printf( "connectting standby password server\n" );
        if( m_sockfd < 0 )
        {
            //Log("");
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
        //Log("");
        close(m_sockfd);
    }
    m_tryconnect_count += 1;
    n += 1000;
    if (m_tryconnect_count != RETRY_CONNECT_MAX_COUNT) {
        usleep(100000 + n * m_tryconnect_count);
        goto RETRY;
    }
    //Log("");
    return false;

SUCCESS:
    printf("%s %d\n", __func__, __LINE__);
    //SetNonBlocking(m_sockfd);
    sockfd = m_sockfd;
    int m = 0;

    printf("m_sockfd: %d %d\n", m_sockfd, __LINE__);
VERIFICATION:
    bool bRet = VerifyLogin(m_sockfd, "192.168.2.189" /*m_LocalIP*/);
    if (!bRet) {
        if (m >= 2)  {
            printf("%s %d\n", __func__, __LINE__);
            close(m_sockfd);
            //Log("");
            return false;
        }
        printf("%s %d\n", __func__, __LINE__);
        m++;
        goto VERIFICATION;
    }
    printf("verifylogin successfully\n");
    return true;
}

template< typename T >
void threadpool< T >::SetLoclaIPAddress()
{
    memset(m_LocalIP, 0, 128);
    char szHostName[256] = {0};
    gethostname(szHostName, 256);
    struct hostent* pHostent = (struct hostent*)gethostbyname(szHostName);
    if (pHostent != NULL)
    {
        char* pszHostAddress = inet_ntoa(*((struct in_addr *)pHostent->h_addr));
        if (pszHostAddress)
        {
            memcpy(m_LocalIP, pszHostAddress, strlen(pszHostAddress));
        }
    }
}

template< typename T >
int threadpool< T >::SetNonBlocking(int fd)
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

template< typename T >
bool threadpool< T >::VerifyLogin(int sockfd, char *szLocalIP)
{
    printf("%s %d\n", __func__, __LINE__);
    char szSendData[8192] = { 0 };
    int nDataLen = 0;
    nDataLen = strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"");
    memcpy(szSendData, "<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"auth\" user=\"", nDataLen);
    memcpy(szSendData + nDataLen, "aimuser", strlen("aimuser"));
    nDataLen += strlen("aimuser");
    memcpy(szSendData + nDataLen, "\" pass=\"", strlen("\" pass=\""));
    nDataLen += strlen("\" pass=\"");
    memcpy(szSendData + nDataLen, "7da43a4dc548515c5616d928e968ddfbc9b20d96", strlen("7da43a4dc548515c5616d928e968ddfbc9b20d96")/*g_szPassword, strlen(g_szPassword)*/);
    nDataLen += strlen("7da43a4dc548515c5616d928e968ddfbc9b20d96"/*g_szPassword*/);
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
    else
    {
        memcpy(szSendData + nDataLen, "192.168.2.189", strlen("192.168.2.189"));
        nDataLen += strlen("192.168.2.189");
        //memcpy(szSendData + nDataLen, g_szIPAddress, strlen(g_szIPAddress));
        //nDataLen += strlen(g_szIPAddress);
    }

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
        printf("%s %d\n", __func__, __LINE__);
        //Log("");
        return false;
    }

    char szDecodeData[8192] = {0};
    int  nDecodeData = 0;
    char *appID = NULL, *valueID = NULL, *pswReturn = NULL /**pswIn = NULL*/;
    bRetCode =  ParseRecvInfo2(appID, valueID, pswReturn, szRecvData, 1, szSeqNumber);
    if (!bRetCode)
    {
        printf("%s %d\n", __func__, __LINE__);
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
        //Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        //Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        //Log("get seq element from xml is wrong");
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
        //Log("get code element from xml is wrong");
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
        //Log("get password error,please check the send data");     
        return false;
    }
    return true;
}

template< typename T >
bool threadpool< T >::SendDataToServer2(int pnSocket, char* pszSendData, int nSendLen, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{
    printf("sockfd: %d %d\n", pnSocket, __LINE__);
    while (nSendLen > 0)
    {
        int nRealSend = send(pnSocket, pszSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (pnSocket != -1)
            {
                close(pnSocket);
                //pnSocket = -1;
            }
            //Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }

    return GetDataFromServer(pnSocket, pszRecvData, pRecvDataLen, pszErrorInfo);
}

template< typename T >
bool threadpool< T >::GetDataFromServer(int pSockClient, char* pszRecvData, int* pRecvDataLen, char* pszErrorInfo)
{ 
    char szRecvBuffer[4096] = {0};
    int nRecvLen = recv(pSockClient, szRecvBuffer, 4096, 0);
    if (nRecvLen == -1 || nRecvLen == 0)
    {
        close(pSockClient);
        //pSockClient = -1;

        //Log("recv data from remote server failed!");
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
        bool bRetCode = AES_CryptDataEVP(reinterpret_cast<unsigned char*>(pszInSendData), nInSendDataLen, uszKey, reinterpret_cast<unsigned char*>(uszEncodeData), &nEncodeLen);

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
void threadpool< T >::Run(struct pollfd &pfd, int sockfd)
{
    int m_NeedRetryConnect = 0;
    bool bRet;
    while ( ! m_stop )
    {
        T* request = NULL;
        if (m_NeedRetryConnect) {
            bool err = LoginPvaServer(m_mainIP, m_standbyIP, sockfd);
            if (!err) {
                //Log("");
                continue;
            }
            ChangeVariableNetworkState(pthread_self());
            //addfd(pfd, sockfd);
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            pfd.revents = 0;
            m_NeedRetryConnect = 0;
        }
        //m_queuestat.wait();
        int ret = m_queuestat.try_wait();
        if (ret < 0) {
            if (errno == EAGAIN) {
                goto NOREQUEST;
            }
            else {
                //Log("");
                continue;
                //m_stop = true;
                //break;
            }
        }

        m_queuelocker.lock();
        if ( m_workqueue.empty() )
        {
            m_queuelocker.unlock();
            goto NOREQUEST;
            //continue;
        }
        request = m_workqueue.front();
        m_workqueue.pop_front();
        m_queuelocker.unlock();
        if ( ! request )
        {
            request = NULL;
            goto NOREQUEST;
            //continue;
        }
        //request->SetMinorEpollfd(epollfd);
        request->SetMinorPollfd(&pfd);
        request->SetSockfdUpstream(sockfd);
        bRet = request->ProcessRequest();
        if (!bRet) {
            m_NeedRetryConnect = 1;
            ChangeVariableNetworkState(pthread_self(), false);
            continue;
        }
        if (request->GetFormFlagVar())
            continue;

NOREQUEST:
        //ReadPvaEpoll(&m_NeedRetryConnect, epollfd, request);
        ReadPvaPoll(pfd, m_NeedRetryConnect, request);
    }
}
 
template< typename T >
void threadpool< T >::ReadPvaPoll(struct pollfd &pfd,int &needrelogin, void *arg)
{
    //int ret = poll(pfd, 1, -1);
    int ret = poll(&pfd, 1, 5000);
    if (ret < 0) {
        printf("poll failure\n");
        //Log();
        m_stop = true;
        //break;
    }
    for (int i = 0; i < 1; ++i)
    {
        int sockfd = pfd.fd;
        if (pfd.revents & POLLERR) {
            printf("get an error from %d\n", pfd.fd);
            char errors[100];
            memset(errors, '\0', 100);
            socklen_t length = sizeof(errors);
            if (getsockopt(pfd.fd, SOL_SOCKET, SO_ERROR, &errors, &length) < 0) {
                printf("get socket option failed\n");

            }
            ChangeVariableNetworkState(pthread_self(), false);
            continue;
        }
        else if (pfd.revents & POLLHUP) {
            needrelogin = 1;
            ChangeVariableNetworkState(pthread_self(), false);
            close(sockfd);
            break;
        }
        else if (pfd.revents & POLLIN) {
            bool m_read_upstream_flag = false;
            while (1) {
                int ret = recv( sockfd,m_buffer_upstream + m_read_upstream_idx, 4096, 0 );
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        m_read_upstream_flag = true;
                        break;
                    } else {
                        //Log("");
                        //removefd(epollfd, sockfd);
                        ChangeVariableNetworkState(pthread_self(), false);
                        needrelogin = 1;
                        close(sockfd);
                        break;
                    }
                } else if (ret == 0) {
                    //Log("");
                    //removefd(epollfd, sockfd);
                    ChangeVariableNetworkState(pthread_self(), false);
                    needrelogin = 1;
                        close(sockfd);
                    break;
                } else if (ret > 0) {
                    m_read_upstream_idx += ret;
                    m_read_upstream_len = m_read_upstream_idx;
                }
            }
            if (m_read_upstream_flag) {
                m_read_upstream_flag = false;
                if (arg == NULL) {
                    ReActiveUpdateLocalCache(m_buffer_upstream);
                }
                else {
                    //req_conn *req = (req_conn*)arg;
                    T *req = (T*)arg;
                    bool bRet = req->GetUpdateCacheFlag();
                    if (bRet)
                        ActiveUpgradeLocalPswCache(m_buffer_upstream, (void*)req);
                    else {
                        char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
                        req->ProcessNewPswFromUpstream(m_buffer_upstream, appID, valueID, pswSendData);
                        ReplaceLocalPswCache(appID, valueID, pswSendData);
                    }
                }
            }
        }
        else if (pfd.revents & POLLOUT) {

        }
    }
    memset(m_buffer_upstream, 0, 4096);
}

template< typename T >
bool threadpool< T >::ParseRecvInfo2(char *appID, char *valueID, char *pswReturn,char *pswIn, int type, char *seqNumber)
{
    int* pIdentifer = (int*)pswIn;
    long lIdentifer = *pIdentifer;
    lIdentifer = ntohl(lIdentifer);

    if (lIdentifer != 0x1000 && lIdentifer != 0x1100 && lIdentifer != 0x1110)
    {
        //Log("recv data head identifer is wrong!");
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
        //Log("recv data len is wrong!");
        return false;
    }

    char szEnCodeData[4096] = { 0 };
    char pszDecodeData[8192] = {0};
    int nPacketDataLen = nPacketLen - 8;
    if (nPacketDataLen > 4096)
    {
        //Log("recv data is too big!");
        return false;
    }

    if (lIdentifer == 0x1100)
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

/*
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
*/

template< typename T >
bool threadpool< T >::ParseDownstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        //Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        //Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        //Log("get seq element from xml is wrong");
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
        //Log("get code element from xml is wrong");
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
        //Log("get child element from xml is wrong");
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
bool threadpool< T >::ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut)
{
    xmlDocPtr doc;
    doc = xmlParseMemory(pszXmlBuffer, nBufferLen);
    if (doc == NULL)
    {
        //Log("parse xml from buffer is wrong!");
        return false;
    }

    xmlNodePtr xmlRoot;
    xmlRoot = xmlDocGetRootElement(doc);
    if (xmlRoot == NULL)
    {
        //Log("get root element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlSeq = NULL, *pXmlCode = NULL;
    pXmlSeq = xmlGetProp(xmlRoot, BAD_CAST("seq"));
    if (pXmlSeq == NULL)
    {
        //Log("get seq element from xml is wrong");
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
        //Log("get code element from xml is wrong");
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
        //Log("get child element from xml is wrong");
        xmlFreeDoc(doc);
        return false;
    }

    xmlChar* pXmlPassword = NULL;   
    pXmlPassword = xmlNodeGetContent(nodeChild);
    if (pXmlPassword == NULL)
    {
        //Log("get password element from xml is wrong");
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
    char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
    //char *appID = (char*)malloc(sizeof(char))
    ParseRecvInfo2(appID, valueID, pswSendData, buf);
    ReplaceLocalPswCache(appID, valueID, pswSendData);
}

template< typename T >
bool threadpool< T >::ActiveUpgradeLocalPswCache(char *buf, void *arg)
{
    char appID[80] = {0}, valueID[128] = {0}, pswSendData[256] = {0};
    T *req = (T*)arg;
    req->ParseRecvInfo(appID, valueID, pswSendData, buf);
    //appID = req->GetAppID();
    //valueID = req->GetValueID();
    ReplaceLocalPswCache(req->GetAppID(), req->GetValueID(), pswSendData);
    //ReplaceLocalPswCache(appID, valueID, pswSendData);
}

template< typename T >
bool threadpool< T >::ReplaceLocalPswCache(char *appID, char *valueID, char *pswInfo)
{
    long lAppID = atol(appID);

    sLocalPswCacheInfo *ps;
    ps->lAppID = lAppID;
    if (valueID != NULL) {
        memcpy(ps->szVaultID, valueID, strlen(valueID));
    }
    else {
        memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
    }
    memcpy(ps->szPassword, pswInfo, strlen(pswInfo));
    ps->tmChange = time(0);

    m_LocalPswCacheMapLocker.lock();
    m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo*>::value_type(lAppID, ps));
    m_LocalPswCacheMapLocker.unlock();
    m_UpdateDatFileListLocker.lock();
    m_UpdateDatFileList.push_back(ps);
    m_UpdateDatFileListLocker.unlock();
    m_cachestat.post();
}

template< typename T >
bool threadpool< T >::GetPvaFromLocal(char *appID, char *valueID, char *pswbuf)
{
    assert(appID != NULL);
    m_LocalPswCacheMapLocker.lock();
    if ( m_LocalPswCacheMap.empty()) {
        //Log("无密码缓存");
        m_LocalPswCacheMapLocker.unlock();
        return false;
    }
    std::map<long, sLocalPswCacheInfo*>::iterator It = m_LocalPswCacheMap.begin();
    It = m_LocalPswCacheMap.find(atol(appID));
    if (It != m_LocalPswCacheMap.end()) {
        memcpy(pswbuf, (*It).second->szPassword, strlen((*It).second->szPassword));
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
    /*
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
    */

    if (m_LocalPswCacheMap.empty())
        return true;
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
    std::map<long, sLocalPswCacheInfo*>::iterator It = m_LocalPswCacheMap.begin();
    It = m_LocalPswCacheMap.find(atol(appID));
    if (It != m_LocalPswCacheMap.end()) {
        time_t tmTimeChange = time(0);
        if ((*It).second->tmChange + 60 > tmTimeChange) {
            memcpy(pswReturn, (*It).second->szPassword, strlen((*It).second->szPassword));
            m_LocalPswCacheMapLocker.unlock();
            return true;
        }
        m_LocalPswCacheMapLocker.unlock();
        return false;
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
    char appID[50] = {0};
    time_t tmCurrent = time(0);
    m_LocalPswCacheMapLocker.lock();
    std::map<long, sLocalPswCacheInfo*>::iterator It = m_LocalPswCacheMap.begin();
    while (It != m_LocalPswCacheMap.end())
    {
        //if ((*It).second->tmChange + 60 < tmCurrent) 
        if ((*It).second->tmChange != (time_t)0 && (*It).second->tmChange + 60 < tmCurrent) {
            //req_conn user;
            T user;
            user.Init(true);
            sprintf(appID, "%ld", (*It).first);
            user.SetAppID(appID);
            user.SetValueID((*It).second->szVaultID);
            append(&user);
            n++;
            memset(appID, '\0', 50);
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
        //Log("open password file failed");
        return false;
    }

    fseek(pFile, 0, SEEK_END);
    long lFileSize = ftell(pFile);
    if (lFileSize == 0)
    {
        //Log("get password file size failed");
        fclose(pFile);
        remove(pszPvaFile);
        return false;
    }
    rewind(pFile);

    long nFileType = 0;
    fread(&nFileType, sizeof(long), 1, pFile);
    if (ntohl(nFileType) != 0x1100) //file type identify
    {
        //Log("get password file head type failed");    
        fclose(pFile);
        return false;
    }

    lFileSize -= sizeof(long);
    char* pszDataBuffer= (char*)malloc(lFileSize + 1);
    if (pszDataBuffer == NULL)
    {
        //Log("malloc save file buffer failed");
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
        //Log("read password file buffer failed");
        free(pszDataBuffer);
        return false;
    }

    char* pszDecodeData = (char*)malloc(lFileSize * 2);
    if (pszDecodeData == NULL)
    {
        //Log("malloc decode buffer failed");
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
        //Log("decode file buffer failed");

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

        sLocalPswCacheInfo *ps;
        ps->lAppID = lAppID;
        memcpy(ps->szVaultID, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        memcpy(ps->szPassword, szPassword, nBufferLen);
        ps->tmChange = tmTimeChange;
        m_LocalPswCacheMapLocker.lock();
        m_LocalPswCacheMap.insert(std::map<long, sLocalPswCacheInfo*>::value_type(lAppID, ps));
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
        //Log("");
        return;
    }
    std::map<long, sLocalPswCacheInfo*>::iterator It = m_LocalPswCacheMap.begin();
    while (It != m_LocalPswCacheMap.end())
    {
        memcpy(szBuffer + nBufferIndex, &((*It).first), sizeof(long));
        nBufferIndex += sizeof(long);
        nPasswordLen = strlen((*It).second->szPassword);
        memcpy(szBuffer + nBufferIndex, &nPasswordLen, sizeof(int));
        nBufferIndex += sizeof(int);
        memcpy(szBuffer + nBufferIndex, (*It).second->szPassword, nPasswordLen);
        nBufferIndex += nPasswordLen;
        memcpy(szBuffer + nBufferIndex, &((*It).second->tmChange), sizeof(time_t));
        nBufferIndex += sizeof(time_t);
        It++;
    }
    m_LocalPswCacheMapLocker.unlock();

    char uszEncodeData[102400] = {0};
    int nEncodeLen = 0;
    AES_CryptDataEVP(reinterpret_cast<unsigned char*>(szBuffer), nBufferIndex, szEncodeKey, reinterpret_cast<unsigned char*>(uszEncodeData), &nEncodeLen);

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
    //Log("");
    return -1;
}


#endif
