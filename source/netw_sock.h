/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   netw_sock.h
  * @brief  Define network socket interface
  */


#ifndef __netw_sock_H_
#define __netw_sock_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

int     f_netw_sock_init( void *pNetwork ,  void* net_iface_handler);


uint8_t f_netw_sock_isOpen( void *hdl );

uint8_t f_netw_sock_isLost( void *ctx );

int  f_netw_sock_setup( void *ctx );

int  f_netw_sock_close( void* hdl );

int  f_netw_sock_connect( void **pSockHd, const  char* RemoteHostAddress, uint16_t RemoteHostPort , uint32_t tmo_ms);


int  f_netw_sock_send( void *hdl, const unsigned char *buf, size_t len );

int  f_netw_sock_recv( void *hdl, unsigned char *buf, size_t len );

int  f_netw_sock_recv_timeout( void *hdl, unsigned char *buf, size_t len, uint32_t tmo );


#if defined(__cplusplus)
}
#endif

#endif //__netw_sock_H_
