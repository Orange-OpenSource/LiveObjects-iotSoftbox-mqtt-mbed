/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_msg.h
  * @brief  Interface to encode/decode JSON messages
  *
  */

#ifndef __loc_msg_H_
#define __loc_msg_H_

#include "liveobjects-client/LiveObjectsClient_Config.h"
#include "liveobjects-client/LiveObjectsClient_Defs.h"

#include "mbedtls/config.h"

#include "mbedtls/md5.h"


#define LOM_PUSH_FLAG         1

/**
 * @brief Define an array of simple LiveObjects data elements
 */
typedef struct {
    const LiveObjectsD_Data_t*     data_ptr;   ///< Address of the first simple LiveObjects data element in array
    int                            data_nb;    ///< Number of elements in array
} LOMArrayOfData_t;


/**
 * @brief Define an array of LiveObjects configuration parameter elements
 */
typedef struct {
    const LiveObjectsD_Param_t*    param_ptr;  ///< Address of the first LiveObjects parameter element in array
    int                            param_nb;   ///< Number of elements in array
} LOMArrayOfParams_t;



/**
 * @brief Define a set of user 'status' to be published to the LiveObjects server
 */
typedef struct {
    LOMArrayOfData_t               data_set;          ///< Array of data : 'status' elements
#if LOM_PUSH_FLAG
    uint8_t                        pushtoLOServer;   ///< flag to publish 'info' to the LiveObject Server
#endif
} LOMSetOfStatus_t;


/**
 * @brief Define a set of user data to be published to the LOM server
 *        in a same stream flow (and also in the same time)
 *
 * TODO: array sizes must be defined in configuration file (and tunable by user)
 */
typedef struct {
    LOMArrayOfData_t               data_set;          ///< Array of data : 'collected data' elements
    const LiveObjectsD_GpsFix_t*   gps_ptr;           ///< Optional, current GPS position
    char                           stream_id[80];     ///< stream-id
    char                           model[80];         ///< model
    char                           tags[80];          ///< tags in JSON format
    char                           timestamp[24];     ///< ? TODO
#if LOM_PUSH_FLAG
    uint8_t                        pushtoLOServer;   ///< flag to forward 'collected data' to the LiveObject Server
#endif
} LOMSetOfData_t;


/**
 * @brief Define the full set of user configuration parameters to be published to the LOM server
 *
 */
typedef struct {
    LOMArrayOfParams_t             param_set;         ///< Array of configuration parameters
    LiveObjectsD_CallbackParams_t  param_callback;    ///< User callback function, called when parameter is updated
#if LOM_PUSH_FLAG
    uint8_t                        pushtoLOServer;    ///< flag to publish 'config parameter' to the LiveObject Server
#endif
} LOMSetOfParams_t;


/**
 * @brief Define the partial set of updated (or not) user configuration parameters.
 *
 */
typedef struct {
    int32_t                        cid;                      ///< Correlation Identigfier
    int32_t                        nb_of_params;             ///< Number of elements in tab_of_param_ptr
    const LiveObjectsD_Param_t*    tab_of_param_ptr[LOC_MAX_OF_COMMAND_ARGS]; ///< array of configuration parameters
} LOMSetofUpdatedParams_t;

/**
 * @brief Define a set of user commands
 *
 */
typedef struct {
    uint8_t                        cmd_enable;
    const LiveObjectsD_Command_t*  cmd_ptr;         ///< Address of the first LiveObjects command element in array
    int                            cmd_nb;          ///< Number of elements in array
    LiveObjectsD_CallbackCommand_t cmd_callback;    ///< User callback function called to process the received command
} LOMSetofCommands_t;


/**
 * @brief Define a group of user resources
 *
 */
typedef struct {
    uint8_t                                rsc_enable;
    const LiveObjectsD_Resource_t*         rsc_ptr;        ///< Address of the first LiveObjects resource element in array
    int                                    rsc_nb;         ///< Number of elements in array
    LiveObjectsD_CallbackResourceNotify_t  rsc_cb_ntfy;    ///< User callback function called to notify begin/end of transfer
    LiveObjectsD_CallbackResourceData_t    rsc_cb_data;    ///< User callback function called to notify that data can be read
#if LOM_PUSH_FLAG
    uint8_t                                pushtoLOServer;
#endif
} LOMSetOfResources_t;

/**
 * @brief Request to update one user resource
 *        received from the LiveObjects platform
 *
 */
typedef struct {
    int32_t             ursc_cid;                       ///< Correlation Id of the current transfer
    const LiveObjectsD_Resource_t*  ursc_obj_ptr;       ///< Resource to update
    char                ursc_vers_old[10];              ///< Old version sent by the LiveObbject platform
    char                ursc_vers_new[10];              ///< New version sent by the LiveObbject platform
    char                ursc_md5[16];                   ///< MD5
    uint32_t            ursc_size;                      ///< Size of the resource to be transfered in device
    char                ursc_uri[80];                   ///<< URI to get the resource

    uint8_t             ursc_connected;                 ///< Flag indicating if device is always  connected to the HTTP server
    uint8_t             ursc_retry;                     ///< Count the number to (re)connect to the HTTP server
    uint32_t            ursc_offset;                    ///< Offset in the current transfer of resource

    mbedtls_md5_context md5_ctx;                        ///< Conetext of MAD5 (using MD5 algo in mbedtls)

} LOMSetOfUpdatedResource_t;


const char* LO_msg_encode_status( uint8_t from, const LOMArrayOfData_t* p );

const char* LO_msg_encode_data( uint8_t from, const LOMSetOfData_t* p );

const char* LO_msg_encode_resources( uint8_t from, const LOMSetOfResources_t* p );

const char* LO_msg_encode_params_all( uint8_t from, const LOMArrayOfParams_t* p, int32_t cid );

const char* LO_msg_encode_cmd_resp( uint8_t from, int32_t cid, const LiveObjectsD_Data_t* data_ptr, int data_nb );


const char* LO_msg_encode_rsc_result( int32_t cid, LiveObjectsD_ResourceRespCode_t result );

const char* LO_msg_encode_params_update( const LOMSetofUpdatedParams_t* p );

const char* LO_msg_encode_cmd_result( int32_t cid, int result );




LiveObjectsD_ResourceRespCode_t LO_msg_decode_rsc_req(
        const char*                payload_data,
        uint32_t                   payload_len,
        const LOMSetOfResources_t* p,
        LOMSetOfUpdatedResource_t* r,
        int32_t* cid);


/**
 * @brief Decode a received JSON message to update configuration parameters
 *
 */
int LO_msg_decode_params_req(
        const char*               payload_data,
        uint32_t                  payload_len,
        const LOMSetOfParams_t*   p,
        LOMSetofUpdatedParams_t*  r);


int LO_msg_decode_cmd_req(
        const char*               payload_data,
        uint32_t                  payload_len,
        const LOMSetofCommands_t* p,
        int32_t*                  pCid
        );

#if defined(__cplusplus)
}
#endif

#endif /* __loc_msg_H_ */
