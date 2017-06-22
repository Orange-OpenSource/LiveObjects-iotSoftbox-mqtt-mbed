/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  LiveObjectsClient_Config.h
  * @brief Default configuration for LiveObjects Client library
  *
  * To implement or not a Live Objects Feature, set to 1 or 0 (by default 1, it is impelmented):
  * - LOC_FEATURE_MBEDTLS      SSL/TLS feature
  * - LOC_FEATURE_LO_STATUS    'Status/Info' feature.
  * - LOC_FEATURE_LO_PARAMS    'Configuration Parameters' feature.
  * - LOC_FEATURE_LO_DATA      'Collected Data' feature.
  * - LOC_FEATURE_LO_COMMANDS  'Commands' feature.
  * - LOC_FEATURE_LO_RESOURCES 'Resources' feature.
  *
  * Tunable parameters:
  * - LOC_SERV_TIMEOUT  Connection Timeout in milliseconds (default 20 seconds)
  * - LOC_MQTT_API_KEEPALIVEINTERVAL_SEC  Period of MQTT Keepalive message (default: 30 seconds)
  * - LOC_MQTT_DEF_COMMAND_TIMEOUT Timeout in milliseconds to wait for a MQTT ACK/NACK response after sending MQTT request
  * - LOC_MQTT_DEF_SND_SZ  Size (in bytes) of static MQTT buffer used to send a MQTT message (default: 2 K bytes)
  * - LOC_MQTT_DEF_RCV_SZ  Size (in bytes) of static MQTT buffer used to receive a MQTT message (default: 2 K bytes)
  * - LOC_MQTT_DEF_TOPIC_NAME_SZ  Max Size (in bytes) of MQTT Topic name (default: 40 bytes)
  * - LOC_MQTT_DEF_DEV_ID_SZ  Max Size (in bytes) of Device Identifier (default: 20 bytes)
  * - LOC_MQTT_DEF_NAME_SPACE_SZ  Max Size (in bytes) o Name Space (default: 20 bytes)
  * - LOC_MQTT_DEF_PENDING_MSG_MAX  Max Number of pending MQTT Publish messages (default: 5 messages)
  * - LOC_MAX_OF_COMMAND_ARGS  Max Number of arguments in command (default: 5 arguments)
  * - LOC_MAX_OF_DATA_SET  Max Number of collected data streams (or also named 'data sets')  (default: 5 data streams)
  * - LOM_JSON_BUF_SZ  Size (in bytes) of static JSON buffer used to encode the JSON payload to be sent (default: 1 K bytes)
  * - LOM_JSON_BUF_USER_SZ  Size (in bytes) of static JSON buffer used to encode a user JSON payload (default: 200 bytes)
  *
  */


#ifndef __LiveObjectsClient_Config_H_
#define __LiveObjectsClient_Config_H_

/* User can overwrite parameters */
#include "liveobjects_dev_config.h"

#ifndef LOC_MQTT_DUMP_MSG
#define LOC_MQTT_DUMP_MSG                    3
#endif

#ifndef LOC_FEATURE_MBEDTLS
#define LOC_FEATURE_MBEDTLS                  1
#endif


#ifndef LOC_FEATURE_LO_STATUS
#define LOC_FEATURE_LO_STATUS                1
#endif
#ifndef LOC_FEATURE_LO_PARAMS
#define LOC_FEATURE_LO_PARAMS                1
#endif
#ifndef LOC_FEATURE_LO_DATA
#define LOC_FEATURE_LO_DATA                  1
#endif
#ifndef LOC_FEATURE_LO_COMMANDS
#define LOC_FEATURE_LO_COMMANDS              1
#endif
#ifndef LOC_FEATURE_LO_RESOURCES
#define LOC_FEATURE_LO_RESOURCES             1
#endif



/** Connection Timeout in milliseconds */
#ifndef LOC_SERV_TIMEOUT
#define LOC_SERV_TIMEOUT                     20000
#endif

/* MQTT Default parameters */
#ifndef LOC_MQTT_API_KEEPALIVEINTERVAL_SEC
#define LOC_MQTT_API_KEEPALIVEINTERVAL_SEC   30
#endif

#ifndef LOC_MQTT_DEF_COMMAND_TIMEOUT
#define LOC_MQTT_DEF_COMMAND_TIMEOUT         5000
#endif

#ifndef LOC_MQTT_DEF_SND_SZ
#define LOC_MQTT_DEF_SND_SZ                  (1024*2)
#endif

#ifndef LOC_MQTT_DEF_RCV_SZ
#define LOC_MQTT_DEF_RCV_SZ                  (1024*2)
#endif


#ifndef LOC_MQTT_DEF_TOPIC_NAME_SZ
#define LOC_MQTT_DEF_TOPIC_NAME_SZ           40
#endif

#ifndef LOC_MQTT_DEF_DEV_ID_SZ
#define LOC_MQTT_DEF_DEV_ID_SZ               20
#endif

#ifndef LOC_MQTT_DEF_NAME_SPACE_SZ
#define LOC_MQTT_DEF_NAME_SPACE_SZ           20
#endif

#ifndef LOC_MQTT_DEF_PENDING_MSG_MAX
#define LOC_MQTT_DEF_PENDING_MSG_MAX         5
#endif

#ifndef LOC_MAX_OF_COMMAND_ARGS
#define LOC_MAX_OF_COMMAND_ARGS              5
#endif

#ifndef LOC_MAX_OF_DATA_SET
#define LOC_MAX_OF_DATA_SET                  5
#endif

#ifndef LOC_MAX_OF_STATUS_SET
#define LOC_MAX_OF_STATUS_SET                1
#endif


#ifndef LOM_JSON_BUF_SZ
#define LOM_JSON_BUF_SZ                      1024
#endif

#ifndef LOM_JSON_BUF_USER_SZ
#define LOM_JSON_BUF_USER_SZ                 1024
#endif

#ifndef LOM_PUSH_ASYNC
#define LOM_PUSH_ASYNC                       0
#endif

#endif /* __LiveObjectsClient_Config_H_ */
