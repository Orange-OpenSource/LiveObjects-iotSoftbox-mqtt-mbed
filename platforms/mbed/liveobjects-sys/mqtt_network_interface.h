/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */


/**
  * @file   mqtt_network_interface.h
  * @brief  Define structure used/required by the MQTTClient soft package
  */


#ifndef __MQTT_NETWORK_INTERFACE_H_
#define __MQTT_NETWORK_INTERFACE_H_

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct Network Network;

struct Network{
	void* sock_hdl;
    int (*mqttread)  (Network*, unsigned char*, int, int);
    int (*mqttwrite) (Network*, unsigned char*, int, int);

    //void (*disconnect) (Network*);
};

#if defined(__cplusplus)
}
#endif

#endif /* __MQTT_NETWORK_INTERFACE_H_ */
