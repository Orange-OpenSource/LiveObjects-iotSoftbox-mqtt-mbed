/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   netw_wrapper.h
  * @brief  Define network interface
  */


#ifndef __netw_wrapper_H_
#define __netw_wrapper_H_

#include "liveobjects-client/LiveObjectsClient_Security.h"

#include "liveobjects-sys/mqtt_network_interface.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct{
    const char*    RemoteHostAddress;
    unsigned short RemoteHostPort;
    unsigned int   TimeoutMs;
} LiveObjectsNetConnectParams_t;

unsigned char netw_isLost(Network *pNetwork);

int netw_init(Network *pNetwork, void* net_iface_handler);

int netw_setSecurity(Network *pNetwork, const LiveObjectsSecurityParams_t* params);

int netw_connect(Network *pNetwork, LiveObjectsNetConnectParams_t* params);

void netw_disconnect(Network *pNetwork, int cause);

#if defined(__cplusplus)
}
#endif

#endif //__netw_wrapper_H_
