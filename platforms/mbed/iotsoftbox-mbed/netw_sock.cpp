/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file  netw_wrapper.cpp
 * @brief Network Interface.
 */

#include <stdbool.h>
#include <string.h>

#include "netw_sock.h"

#include "NetworkInterface.h"
#include "TCPSocket.h"

#include "liveobjects-sys/loc_trace.h"
#include "liveobjects-sys/LiveObjectsClient_Platform.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"

//---------------------------------------------------------------------------------
//

NetworkInterface*                _netw_iface;

static TCPSocket*                _netw_socket;
static  uint8_t                  _netw_bSockState;


//---------------------------------------------------------------------------------
//
extern "C" uint8_t f_netw_sock_isOpen( Network *pNetwork )
{
    if ((_netw_socket) && (_netw_bSockState == 0x01)) {
        return 1;
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
extern "C" uint8_t f_netw_sock_isLost( Network *pNetwork )
{
    if ((_netw_socket)  && (_netw_bSockState &0x01)) {
        return _netw_bSockState&0x02;
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
extern "C" int f_netw_sock_setup( Network *pNetwork )
{
    if (_netw_socket) {
        LOTRACE_INF("f_netw_sock_setup: sock=%p ...", _netw_socket);
        //_netw_socket->set_timeout(500);
        //_netw_socket->set_blocking(false);
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
extern "C" int f_netw_sock_close( Network *pNetwork )
{
    if (_netw_socket) {
        LOTRACE_INF("f_netw_sock_close: close and delete - sock=%p ...", _netw_socket);
        _netw_socket->close();
        delete _netw_socket;
        _netw_socket = NULL;
    }
    LOTRACE_INF("f_netw_sock_close: closed");
    if (pNetwork) pNetwork->my_socket = NULL;
    _netw_bSockState = 0;
    return 0;
}


//---------------------------------------------------------------------------------
//
extern "C"  int f_netw_sock_send( void *ctx, const unsigned char *buf, size_t len)
{
    int size = -1;
    Network *pNetwork = (Network *)ctx;
    if ((pNetwork == NULL) || (pNetwork->my_socket != _netw_socket)) {
        LOTRACE_ERR("ERROR while sending data len=%d, No SOCKET", len);
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    size = _netw_socket->send(buf, len);
    if(NSAPI_ERROR_WOULD_BLOCK == size){
        LOTRACE_ERR("ERROR while sending data len=%d, WOULD BLOCKED", len);
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if(size < 0){
        LOTRACE_ERR("ERROR while sending data len=%d, rc=%d", len, size);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return size;
}

//---------------------------------------------------------------------------------
//
extern "C"  int f_netw_sock_recv(void *ctx, unsigned char *buf, size_t len)
{
    int recv = -1;
    Network *pNetwork = (Network *)ctx;
    if ((pNetwork == NULL) || (pNetwork->my_socket != _netw_socket)) {
        LOTRACE_ERR("ERROR while reading data len=%d, No SOCKET", len);
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    recv = _netw_socket->recv(buf, len);
    if (recv <= 0) {
        if(NSAPI_ERROR_WOULD_BLOCK == recv){
            LOTRACE_DBG_VERBOSE("f_recv(len=%d) -> ERROR_WOULD_BLOCK", len);
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if(recv < 0){
            LOTRACE_ERR("f_recv(len=%d) -> ERROR %d", len, recv);
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }
        if (recv == 0) {
        	_netw_bSockState |= 0x02;
            LOTRACE_ERR("f_recv(len=%d) -> ERROR  SSL_PEER_CLOSE_NOTIF", len);
            return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; //MBEDTLS_ERR_NET_CONN_RESET;
        }
    }
    return recv;
}

//---------------------------------------------------------------------------------
//
extern "C" int f_netw_sock_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t tmo)
{
    int ret;

    LOTRACE_DBG_VERBOSE("f_recv_timeout(len=%d,tmo=%u) ...", len, tmo);

    ret = f_netw_sock_recv(ctx, buf, len);
    if (ret < 0) {
        if (MBEDTLS_ERR_SSL_WANT_READ != ret) {
            LOTRACE_ERR("f_recv_timeout(len=%d,tmo=%u) -> ERROR -x%X", len, tmo,  -ret);
        }
    }
    else if (ret == 0) {
        LOTRACE_ERR("f_recv_timeout(len=%d,tmo=%u) -> ERROR 0 !!", len, tmo);
    }
    else LOTRACE_DBG_VERBOSE("f_recv_timeout(len=%d,tmo=%u) -> ret=%d",  len, tmo, ret);
    return ret;
}

//---------------------------------------------------------------------------------
//
extern "C" int f_netw_sock_connect( Network *pNetwork, const  char* RemoteHostAddress, uint16_t RemoteHostPort, uint32_t tmo_ms)
{
    int ret;
    LOTRACE_INF("Connecting to server %s:%d ...",
            RemoteHostAddress , RemoteHostPort);

    if (_netw_socket) {
        f_netw_sock_close(pNetwork);
    }
    _netw_bSockState = 0;

    if (pNetwork) pNetwork->my_socket = NULL;

    _netw_socket = new TCPSocket(_netw_iface);
    if (_netw_socket == NULL) {
        LOTRACE_ERR("Failed to create TCP socket");
        return -1;
    }

    if (pNetwork) pNetwork->my_socket = _netw_socket;

    //_netw_socket->attach(this, &M2MConnectionHandlerPimpl::socket_event);
    _netw_socket->set_blocking(true); // Wait forever
    _netw_socket->set_timeout(tmo_ms);

    ret = _netw_socket->connect(RemoteHostAddress, RemoteHostPort);
    if (ret != 0){
        LOTRACE_ERR("Failed while connecting to server %s:%u, ret= %d", RemoteHostAddress, RemoteHostPort, ret);
        f_netw_sock_close(pNetwork);
        return -1;
    }
    LOTRACE_INF("Connected to server %s:%u OK", RemoteHostAddress, RemoteHostPort);
    _netw_bSockState = 0x01;

    _netw_socket->set_timeout(500);

    //_netw_socket->set_blocking(false); // Set non-blocking

    return 0;
}

//---------------------------------------------------------------------------------
//
extern "C" int f_netw_sock_init( Network *pNetwork,  void* net_iface_handler)
{
    LOTRACE_DBG("f_netw_sock_init(%p,%p)", pNetwork, net_iface_handler);

    if ((pNetwork == NULL) || (net_iface_handler == NULL)) {
    	return -1;
    }

    pNetwork->my_socket = SOCKETHANDLE_NULL;

    _netw_iface = (NetworkInterface*)net_iface_handler;
    _netw_socket = NULL;
    _netw_bSockState = 0;

    return 0;
}



