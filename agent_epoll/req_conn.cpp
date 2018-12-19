#include "req_conn.h"
#include "main.h"
#include "threadpool.h"
//#include "cryptdatafunc.h"

//#ifdef _cplusplus
//extern "C" {
//#endif
//#include "libxml/parser.h"
//#include "libxml/tree.h"
//#ifdef _cplusplus
//}
//#endif

req_conn::req_conn()
{
    m_sockfd_downstream = -1;
    m_main_epollfd = -1;
    m_pool = NULL;
    m_lAppID = NULL;
    m_valueID = NULL;
    m_SeqNumber = NULL;
}

req_conn::~req_conn()
{

}

void req_conn::close_conn( bool real_close )
{
    if( real_close && ( m_sockfd_downstream != -1 ) )
    {
        removefd( m_main_epollfd, m_sockfd_downstream );
        m_sockfd_downstream = -1;
    }
}

void req_conn::Init( int epollfd, int sockfd, const sockaddr_in& addr, void *arg )
{
    m_sockfd_downstream = sockfd;
    m_address = addr;
    m_main_epollfd = epollfd;
    m_pool = (threadpool<req_conn> *)arg;
    int error = 0;
    socklen_t len = sizeof( error );
    getsockopt( m_sockfd_downstream, SOL_SOCKET, SO_ERROR, &error, &len );
    /*
    int reuse = 1;
    setsockopt( m_sockfd_downstream, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof( reuse ) );
    */

    Init();
}

void req_conn::Init(bool needupdate)
{
    m_ActiveUpdateCacheFlag = needupdate;
    //m_linger = false;
}

bool req_conn::ReceiveRequest()
{
    bool m_downstream_flag = false;
    while (1) 
    {
        int ret = recv( m_sockfd_downstream, m_downstream_buf + m_downstream_idx, 4096, 0 );
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                m_downstream_flag = true;
                break;
            } else {
                m_pool->Log("");
                removefd(m_main_epollfd, m_sockfd_downstream);
                break;
            }
        } else if (ret == 0) {
            m_pool->Log("");
            removefd(m_main_epollfd, m_sockfd_downstream);
            break;
        } else if (ret > 0) {
            m_downstream_idx += ret;
            //m_read_upstream_len = m_read_upstream_idx;
        }
    }
    if (!m_downstream_flag) {
        m_pool->Log("");
        return false;
    }

    char *appID = NULL; 
    char *valueID = NULL; 
    char *pswOut;

    unsigned int net_state = GetNetworkState();
    if (net_state >= 8){
        goto NETWORK_OUTLINE;
    }

NETWORK_ONLINE:
    m_pool->ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    //long lAppID = atol(appID);
    memcpy(m_lAppID, appID, strlen(appID));
    memcpy(m_valueID, valueID, strlen(valueID));
    return true;

NETWORK_OUTLINE:
    char *pswInfoBuffer = NULL;
    m_pool->ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    bool bRet = m_pool->GetPvaFromLocal(appID, valueID, pswInfoBuffer);
    if (!bRet)
        SendDataToDownstream(pswInfoBuffer);
    else
        //send("no psw, outline");
    return false;
}

bool req_conn::ProcessPswInfoFromUpstream()
{
    bool bRet = false;
    char *pswSendData = NULL;
    bRet = m_pool->GetOnePswFromLocalCache(m_lAppID, pswSendData);
    if (!bRet)
        goto TOUPSTREAM;
    else {
        if (pswSendData == NULL)
            goto TOUPSTREAM;
    }
    return true;

TOUPSTREAM:
    bRet = SendRequestToUpstream(m_sendbuf_upstream);
    if (!bRet)
        return false;
    return true;
}

bool req_conn::SendRequestToUpstream(char *valueID)
{
    time_t tmCurrent = time(0);
    char szSeqNumber[32] = {0};
    sprintf(szSeqNumber, "%ld", tmCurrent);
    memcpy(m_SeqNumber, szSeqNumber, strlen(szSeqNumber));
    char szSendXml[4096] = {0};
    int nXmlLen = strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"pva\" obj=\"t_password_info\" seq=\"");
    memcpy(szSendXml, "<?xml version=\"1.0\" encoding=\"utf-8\"?><req type=\"pva\" obj=\"t_password_info\" seq=\"", nXmlLen);
    memcpy(szSendXml + nXmlLen, szSeqNumber, strlen(szSeqNumber));
    nXmlLen += strlen(szSeqNumber);
    memcpy(szSendXml + nXmlLen, "\"><vaultid>", strlen("\"><vaultid>"));
    nXmlLen += strlen("\"><vaultid>");
    if (valueID != NULL) {
        memcpy(szSendXml + nXmlLen, m_valueID, strlen(m_valueID));
        nXmlLen += strlen(m_valueID);
    }
    else {
        memcpy(szSendXml + nXmlLen, "2478cbd7fe8f4f22810664407e01f437", strlen("2478cbd7fe8f4f22810664407e01f437"));
        nXmlLen += strlen("2478cbd7fe8f4f22810664407e01f437");
    }
    memcpy(szSendXml + nXmlLen, "</vaultid><appid>", strlen("</vaultid><appid>"));
    nXmlLen += strlen("</vaultid><appid>");
    memcpy(szSendXml + nXmlLen, m_lAppID, strlen(m_lAppID));
    nXmlLen += strlen(m_lAppID);
    memcpy(szSendXml + nXmlLen, "</appid></req>", strlen("</appid></req>"));
    nXmlLen += strlen("</appid></req>");

    char szEncodeXml[8192] = {0};
    int* pHeader = (int*)szEncodeXml;
    *pHeader = htonl(0x1100);
    pHeader += 1;

    int nEncodeLen = 0;
    nEncodeLen = m_pool->EnCodeSendInfo(szSendXml, nXmlLen, szEncodeXml + sizeof(int) * 2, 1);
    nEncodeLen += sizeof(int) * 2;
    *pHeader = htonl(nEncodeLen);

    char szRecvData[8192] = {0};
    int  nRecvDataLen = 0;
    bool bRetCode = SendDataToServer(&m_sockfd_upstream, szEncodeXml, nEncodeLen);
    if (!bRetCode) 
    {
        m_pool->Log("");
        return false;
    }

    /*
    char szDecodeData[8192] = {0};
    int  nDecodeData = 0;
    bRetCode = DecodeRecvData(szRecvData, szDecodeData, &nDecodeData, pszErrorInfo);
    if (!bRetCode)
        return false;

    char szPAPassword[256] = {0};
    bRetCode = ParseXmlData(pszSeqNumber, szDecodeData, nDecodeData, szPAPassword, pnErrorCode, pszErrorInfo);
    if (!bRetCode)
        return false;

    int nPswLen = strlen(szPAPassword);
    if (nPswLen > 32)
        memcpy(pszReturnPsw, szPAPassword, 32);
    else
        memcpy(pszReturnPsw, szPAPassword, nPswLen);
    */

    return true;
}

void req_conn::ProcessNewPswFromUpstream(char *buf)
{
    char *appID = NULL, *valueID = NULL, *pswSendData = NULL;
    m_pool->ParseRecvInfo(appID, valueID, pswSendData, buf);
    SendDataToDownstream(pswSendData);
    memcpy(appID, m_lAppID, strlen(m_lAppID));
    memcpy(valueID, m_valueID, strlen(m_valueID));
    m_pool->ReplaceLocalPswCache(appID, valueID, pswSendData);
}

bool req_conn::ProcessRequest()
{
    bool bRet = false;
    if (m_ActiveUpdateCacheFlag) {
        bRet = SendRequestToUpstream(m_valueID);
        if (!bRet)
            return false;
    } 
    else {
        bRet = ProcessPswInfoFromUpstream();
        if (!bRet)
            return false;
    }
    return true;
}

void req_conn::SendDataToDownstream(char *pswSendData)
{
    int nSendLen = strlen(pswSendData);
    while (nSendLen > 0)
    {
        int nRealSend = send(m_sockfd_downstream, pswSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (m_sockfd_downstream != -1)
            {
                removefd(m_main_epollfd, m_sockfd_downstream);
                //close(*pnSocket);
                //*pnSocket = -1;
            }
            m_pool->Log("send req data info failed!");
            return ;
        }
        nSendLen -= nRealSend;
    }
    return ;

}

bool req_conn::SendDataToServer(int* pnSocket, char* pszSendData, int nSendLen)
{
    while (nSendLen > 0)
    {
        int nRealSend = send(*pnSocket, pszSendData, nSendLen, 0);
        if (nRealSend == -1)
        {
            if (*pnSocket != -1)
            {
                removefd(m_minor_epollfd, *pnSocket);
                //close(*pnSocket);
                *pnSocket = -1;
            }
            m_pool->Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }
    return true;
}

