/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  loc_sock.cpp
  * @brief TCP Socket Interface used by loc_wget
  * @note  Check only one socket
  */


#include "loc_sock.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "mbed.h"
#include "NetworkInterface.h"
#include "TCPSocket.h"

#include "liveobjects-sys/loc_trace.h"
#include "liveobjects-sys/LiveObjectsClient_Platform.h"

extern NetworkInterface*  _netw_iface;

static TCPSocket* _LO_sock_current  = NULL;

//---------------------------------------------------------------------------------
//
extern "C"  int LO_sock_dnsSetFQDN(const char* fqdn, const char* ip_address)
{
    LOTRACE_ERR("LO_sock_dnsSetFQDN: NOT IMPLEMENTED");
    return -1;
}

//---------------------------------------------------------------------------------
//
extern "C"  void LO_sock_disconnect(socketHandle_t *pHdl)
{
    if (pHdl != NULL) {
        TCPSocket* pTcpSock = *(TCPSocket**)pHdl;
        if (_LO_sock_current != pTcpSock) LOTRACE_ERR("LO_sock_disconnect - BAD HDL %p (expected %p)", pTcpSock, _LO_sock_current);
        else _LO_sock_current = NULL;
        if (pTcpSock) {
            LOTRACE_DBG("LO_sock_disconnect: Close and delete.");
            pTcpSock->close();
            delete pTcpSock;
        }
        *((TCPSocket**)pHdl) = NULL;
    }
}

//---------------------------------------------------------------------------------
//
extern "C" int LO_sock_connect( short retry, const char* remoteHostAddress, uint16_t remoteHostPort , socketHandle_t  *pHdl )
{
    int ret;
    int i;
    TCPSocket* pTcpSock;

    LOTRACE_INF("Connecting to server %s:%d (retry=%d) ...", remoteHostAddress, remoteHostPort, retry);

    if (pHdl) *pHdl = SOCKETHANDLE_NULL;

    if (_LO_sock_current) {
        LOTRACE_WARN("Previous not closed !!!!");
        LO_sock_disconnect((void**)&_LO_sock_current);
    }

    if (retry <= 0) retry = 1;
    pTcpSock = new TCPSocket(_netw_iface);
    if (pTcpSock == NULL) {
        LOTRACE_ERR("Failed to create TCP socket");
        return -1;
    }

    pTcpSock->set_blocking(true); // Wait forever

    ret = -1;
    for(i=0; i < retry; i++) {
        ret = pTcpSock->connect(remoteHostAddress, remoteHostPort);
        if (ret == 0)  {
            break;
        }
        pTcpSock->close();
    }

    if (ret != 0){
        LOTRACE_ERR("Failed while connecting to server %s:%d, ret= %d",
                remoteHostAddress, remoteHostPort, ret);
        delete pTcpSock;
        return -1;
    }

    LOTRACE_INF("Connected to server %s:%d OK", remoteHostAddress, remoteHostPort);

    pTcpSock->set_timeout(500);

    //_netw_socket->set_blocking(false); // Set non-blocking

    _LO_sock_current = pTcpSock;

    if (pHdl) *pHdl = pTcpSock;

    return 0;
}


//---------------------------------------------------------------------------------
//
extern "C" int LO_sock_send(socketHandle_t hdl, const char* buf_ptr)
{
    TCPSocket* pTcpSock =  (TCPSocket *) hdl;
    int len = strlen(buf_ptr);
    const char* pc = buf_ptr;

    LOTRACE_DBG("send_data: len=%d\r\n%s", len, buf_ptr);

    if (_LO_sock_current != pTcpSock) LOTRACE_ERR("LO_sock_send: BAD HDL %p (expected %p)", pTcpSock, _LO_sock_current);

    while (len > 0) {
        int ret = pTcpSock->send(pc, len);
        if (ret <= 0) {
            LOTRACE_WARN("send_data: ERROR while sebnding data , len=%d/%d", strlen(buf_ptr)-len, strlen(buf_ptr));
            return -1;
        }
        pc += ret;
        len -= ret;
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
extern "C" int LO_sock_recv(socketHandle_t hdl, char* buf_ptr, int buf_len)
{
    int ret ;
    TCPSocket* pTcpSock =  (TCPSocket *) hdl;
    if (pTcpSock == NULL) {
        LOTRACE_ERR("LO_sock_recv(len=%d) -> NO SOCKET !!!", buf_len);
        return -1;
    }

    LOTRACE_DBG("LO_sock_recv(buf_len=%d) ....", buf_len);
    if (_LO_sock_current != pTcpSock) LOTRACE_ERR("LO_sock_recv: BAD HDL %p (expected %p)", pTcpSock, _LO_sock_current);

    ret = pTcpSock->recv(buf_ptr, buf_len);
    if(NSAPI_ERROR_WOULD_BLOCK == ret){
        LOTRACE_INF("LO_sock_recv(len=%d) -> ERROR_WOULD_BLOCK (%d)", buf_len, ret);
        return 0;
    }

    if(ret < 0) {
        LOTRACE_ERR("LO_sock_recv(len=%d) -> ERROR %d", buf_len, ret);
        return ret;
    }

    buf_ptr[ret] = 0;
    if (ret == 0) {
        LOTRACE_ERR("LO_sock_recv(len=%d) ->  ret = 0 !!!", buf_len);
        return 0;
    }

    LOTRACE_DBG("LO_sock_recv(len=%d)", ret);
    return ret;
}

//---------------------------------------------------------------------------------
//
extern "C" int LO_sock_read_line(socketHandle_t hdl, char* buf_ptr, int buf_len)
{
    int len = 0;
    short retry = 0;
    char cc;
    TCPSocket* pTcpSock =  (TCPSocket *) hdl;

    if (pTcpSock == NULL) {
        LOTRACE_ERR("LO_sock_read_line(len=%d) -> NO SOCKET !!!", buf_len);
        return -1;
    }

    if (_LO_sock_current != pTcpSock) LOTRACE_ERR("LO_sock_read_line: BAD HDL %p (expected %p)", pTcpSock, _LO_sock_current);

    cc = 0;
    while (1) {
        int ret = pTcpSock->recv(&cc, 1);
        if (NSAPI_ERROR_WOULD_BLOCK == ret) {
            LOTRACE_INF("LO_sock_read_line(len=%d) retry=%d -> ERROR_WOULD_BLOCK (%d)", len, retry, ret);
            if (++retry < 6) {
                wait_ms(200);
                continue;
            }
            return -1;
        }

        if (ret < 0) {
            LOTRACE_ERR("LO_sock_read_line(len=%d) -> ERROR %d",  len, ret);
            return ret;
        }
        if (ret == 0) {
            LOTRACE_ERR("LO_sock_read_line(len=%d) ->  ret=0 -> Closed by peer  !!!", len);
            return -1;
        }
        if (cc == '\n') {
            LOTRACE_DBG("LO_sock_read_line(len=%d) -> EOL", len);
            break;
        }

        buf_ptr[len++] = cc;
        if (len >= buf_len) {
            LOTRACE_ERR("LO_sock_read_line(len=%d) ->  TOO SHORT  !!!", len);
            return -1;
        }
        retry = 0;
    }

    if ((cc == '\n') && (len >= 1) && (buf_ptr[len-1] == '\r')) {
        len--;
        if (len == 0) LOTRACE_DBG("LO_sock_read_line ->  BODY  !!!");
    }
    buf_ptr[len] = 0;

    return len;
}
