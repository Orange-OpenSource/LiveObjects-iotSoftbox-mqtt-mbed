/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_sock.h
  * @brief  TCP Socket Interface wrapper
  *
  */

#ifndef __loc_sock_H_
#define __loc_sock_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void* LO_sock_connect( short retry, const char* remoteHostAddress, uint16_t remoteHostPort );

void  LO_sock_disconnect( void** hdl );

int   LO_sock_send( void* hdl, const char* buf_ptr );

int   LO_sock_recv( void* hdl, char* buf_ptr, int buf_len );

int   LO_sock_read_line( void* hdl, char* buf_ptr, int buf_len );


#if defined(__cplusplus)
}
#endif

#endif /* __loc_sock_H_ */
