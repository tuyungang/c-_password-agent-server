#include "req_conn.h"
#include "thread_pool.h"
#include "cryptdatafunc.h"

#include "libxml/parser.h"
#include "libxml/tree.h"

/*
void modfd( struct pollfd &pfd , int sockfd, int new_ev, int old_ev)
{
    pfd.fd = sockfd;
    pfd.events |= ~old_ev;
    pfd.events |= new_ev;
}
*/


req_conn::req_conn()
{
    m_sockfd_downstream = -1;
    m_sockfd_upstream = -1;
    //m_main_epollfd = -1;
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
        //removefd( m_main_epollfd, m_sockfd_downstream );
        m_sockfd_downstream = -1;
    }
}

//void req_conn::Init( int epollfd, int sockfd, const sockaddr_in& addr, void *arg )
void req_conn::Init(struct pollfd &pfd, int sockfd, const sockaddr_in& addr, void *arg )
{
    printf("%s %d\n", __func__, __LINE__);
    m_main_pollfd = &pfd;
    m_sockfd_downstream = sockfd;
    m_address = addr;
    //m_main_epollfd = epollfd;
    m_pool = (threadpool<req_conn> *)arg;
    //m_pool = arg;
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
    printf("%s %d\n", __func__, __LINE__);
    bool m_downstream_flag = false;
    bool m_error_flag = false;
    memset(m_downstream_buf, 0, 4096);
    while (1) 
    {
        int ret = recv( m_sockfd_downstream, m_downstream_buf + m_downstream_idx, 4096, 0 );
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                m_downstream_flag = true;
                break;
            } else {
                m_error_flag = true;
                //m_pool->Log("");
                //removefd(m_main_epollfd, m_sockfd_downstream);
                break;
            }
        } else if (ret == 0) {
            m_error_flag = true;
            //m_pool->Log("");
            //removefd(m_main_epollfd, m_sockfd_downstream);
            break;
        } else if (ret > 0) {
            m_downstream_idx += ret;
            //m_read_upstream_len = m_read_upstream_idx;
        }
    }
    if (!m_downstream_flag) {
        //m_pool->Log("");
        return false;
    }
    if (m_error_flag)
        return false;

    char appID[80] = {0}; 
    char valueID[128] = {0}; 
    char pswOut[256] = {0};

    if (!GetNetworkState()){
        printf("%s %d\n", __func__, __LINE__);
        goto NETWORK_OUTLINE;
    }

NETWORK_ONLINE:
    printf("%s %d\n", __func__, __LINE__);
    ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    //m_pool->ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    //long lAppID = atol(appID);
    memcpy(m_lAppID, appID, strlen(appID));
    memcpy(m_valueID, valueID, strlen(valueID));
    return true;

NETWORK_OUTLINE:
    printf("%s %d\n", __func__, __LINE__);
    char *pswInfoBuffer = NULL;
    ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    //m_pool->ParseRecvInfo(appID, valueID, pswOut, m_downstream_buf);
    bool bRet =m_pool->GetPvaFromLocal(appID, valueID, pswInfoBuffer);
    if (bRet)
        //modfd(m_main_pollfd, m_sockfd_downstream, POLLOUT, POLLIN);
        SendDataToDownstream(pswInfoBuffer);
    //else
        //send("no psw, outline");
    memset(m_downstream_buf, 0, 4096);
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
    //modfd(m_main_pollfd, m_sockfd_downstream, POLLOUT, POLLIN);
    m_GetPswFromLocalCacheLocker.lock();   
    m_GetFormFlag = 1;
    m_GetPswFromLocalCacheLocker.unlock();   
    SendDataToDownstream(pswSendData);
    return true;

TOUPSTREAM:
    bRet = SendRequestToUpstream(NULL);
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
    nEncodeLen = EnCodeSendInfo(szSendXml, nXmlLen, szEncodeXml + sizeof(int) * 2, 1);
    nEncodeLen += sizeof(int) * 2;
    *pHeader = htonl(nEncodeLen);

    char szRecvData[8192] = {0};
    int  nRecvDataLen = 0;
    bool bRetCode = SendDataToServer(&m_sockfd_upstream, szEncodeXml, nEncodeLen);
    if (!bRetCode) 
    {
        //m_pool->Log("");
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

int req_conn::EnCodeSendInfo(char* pszInSendData, int nInSendDataLen, char* pszOutEncodeData, int nEncodeType)
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


void req_conn::ProcessNewPswFromUpstream(char *buf, char *appID, char *valueID, char *pswOut)
{
    char /**appID = NULL, *valueID = NULL,*/ *pswSendData = NULL;
    //m_pool->ParseRecvInfo(appID, valueID, pswSendData, buf);
    ParseRecvInfo(appID, valueID, pswSendData, buf);
    SendDataToDownstream(pswSendData);
    //memcpy(appID, m_lAppID, strlen(m_lAppID));
    //memcpy(valueID, m_valueID, strlen(m_valueID));
    //m_pool->ReplaceLocalPswCache(appID, valueID, pswSendData);
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
        printf("%s %d\n", __func__, __LINE__);
        bRet = ProcessPswInfoFromUpstream();
        if (!bRet)
            return false;
    }
    printf("%s %d\n", __func__, __LINE__);
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
                //removefd(m_main_epollfd, m_sockfd_downstream);
                //close(*pnSocket);
                //*pnSocket = -1;
            }
            //m_pool->Log("send req data info failed!");
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
                //removefd(m_minor_epollfd, *pnSocket);
                //close(*pnSocket);
                *pnSocket = -1;
            }
            //m_pool->Log("send req data info failed!");
            return false;
        }
        nSendLen -= nRealSend;
    }
    return true;
}

bool req_conn::ParseRecvInfo(char *appID, char *valueID, char *pswReturn,char *pswIn, int type, char *seqNumber)
{
    int* pIdentifer = (int*)pswIn;
    long lIdentifer = *pIdentifer;
    lIdentifer = ntohl(lIdentifer);

    if (lIdentifer != 0x2000 && lIdentifer != 0x1100 && lIdentifer != 0x1110)
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
    char pszDecodeData[8192] = {};
    int nPacketDataLen = nPacketLen - 8;
    if (nPacketDataLen > 4096)
    {
        //Log("recv data is too big!");
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

bool req_conn::ParseLoginReqXmlData(char* pszSeqNumber, char* pszXmlBuffer, int nBufferLen)
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
        //Log("get seq number is not same to send seq number");
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

bool req_conn::ParseUpstreamXmlInfo(char *appID, char *valueID, char *pszXmlBuffer, int nBufferLen, char *pswOut)
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

void req_conn::ParseDownstreamInfo(char *appID, char *valueID, char *pszDecodeData, int nBufferLen)
{
    char *m_vID = NULL;
    m_vID = strpbrk(pszDecodeData,"=");
    if (!m_vID) {
        //Log("");
        return;
    }
    *m_vID++ = '\0';
    valueID = m_vID;
    appID = pszDecodeData;
    return;
}
