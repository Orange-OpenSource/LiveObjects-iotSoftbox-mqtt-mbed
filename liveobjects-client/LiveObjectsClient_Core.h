/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  LiveObjectsClient_Core.h
  * @brief Live Objects Client Interface (public functions)
  */

#ifndef __LiveObjectsClient_Core_H_
#define __LiveObjectsClient_Core_H_

#include <stdint.h>

#include "liveobjects-client/LiveObjectsClient_Defs.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum {
    LOTRACE_LEVEL_NONE = 0,
    LOTRACE_LEVEL_ERR = 1,
    LOTRACE_LEVEL_WARN,
    LOTRACE_LEVEL_INF,
    LOTRACE_LEVEL_DBG,
    LOTRACE_LEVEL_VERBOSE,
    LOTRACE_LEVEL_MAX
} lotrace_level_t;

//==================================================================
/**
 * * \addtogroup Init  Initialization
 *
 * This section describes functions to create the LiveObjects Client device
 * before connecting this device to the remote LiveObjects platform.
 * @{
 */

/**
 * @brief Check the value of the LiveObjects Apikey
 *
 * @param apikey      Pointer to Api Key c-string.
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_CheckApiKey(const char* apikey);

 /**
  * @brief Init the Debug Trace Module with a given trace level
  *
  * @param level       Log level.
  */
 void LiveObjectsClient_InitDbgTrace(lotrace_level_t level);


/**
 * @brief Initialize the LiveObjects Client Instance (only one instance on board)
 *        This should always be called first.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Init(void* network_itf_handle);

/**
 * @brief Set Device Identifier.
 *        This should be called before the LiveObjectsClient_Connect() function.
 *
 * @param dev_id      Pointer to Device Identifier c-string.
 *                    Your device id (ex: IMEI, serial number, MAC adress, etc.)
 *                    Should only contain alphanumeric characters (a-z, A-Z, 0-9)
 *                    and/or any special characters in the following list : : - _ | + ,
 *                    and must avoid # / !.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_SetDevId(const char* dev_id);

/**
 * @brief Set the name space.
 *        This should be called before the LiveObjectsClient_Connect() function.
 *
 * @param name_space  Pointer to NameSpace c-string.
 *                    Used to avoid conflicts between various families of identifier
 *                    (ex: device model, identifier class "imei", msisdn", "mac", etc.)
 *                    Should preferably only contain alphanumeric characters (a-z, A-Z, 0-9).
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_SetNameSpace(const char* name_space);

/**
 * @brief Call to resolve the domain name of Live Objects platform defined by LOC_SERV_IP_ADDRESS.
 *   This should be called :
 *    - when the IP network is up
 *    - and before the LiveObjectsClient_Connect() function.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_DnsResolve(void);

/**
 * @brief Use to add  a couple (Domain name, IP address).
 *   This should be called before the LiveObjectsClient_Connect() function.
 *
 * @param domain_name       Domain name (FQDN).
 * @param ip_address        IP (v4) Address.
 *
 * @note If IPV4 Address is NULL, the DNS resolver will be called to resolve the IP address.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_DnsSetFQDN(const char* domain_name, const char* ip_address);

/* @} group end : Init */

//==================================================================
/**
 * * \addtogroup Config  IoT Configuration Operations
 *
 * This section describes functions to configure the LiveObjects IoT device.
 *
 * @note Device can be already connected to the LiveObjects platform.
 * @{
 */

/**
 * @brief Set the debug log level
 *
 * @param level       Log level.
 */
void LiveObjectsClient_SetDbgLevel(lotrace_level_t level);


/**
 * @brief Set mode to dump the published MQTT messages
 *
 * @param mode     MQTT Msg Dump Mode
 *                  0 : Disable
 *                  1 : Enable, text format
 *                  3 : ENable, test + hexa format.
 */
void  LiveObjectsClient_SetDbgMsgDump(uint16_t mode);

/**
 * @brief Define a set of user data as the LiveObjects IoT Configuration parameters.
 *
 * @param param_ptr   Pointer to an array of Configuration Parameters
 * @param param_nb    Number of elements in this array.
 * @param callback    User callback function, called to check the parameter to be updated.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_AttachCfgParams (
        const LiveObjectsD_Param_t* param_ptr, int32_t param_nb,
        LiveObjectsD_CallbackParams_t callback);


/**
 * @brief Define the set of user data as the LiveObjects IoT Status.
*
 * @param status_ptr  Pointer to an array of LiveObjects IoT Data.
 * @param status_nb   Number of elements in this array.
 *
 * @return an handle value >= 0  if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_AttachStatus (const LiveObjectsD_Data_t* status_ptr, int32_t status_nb);


/**
 * @brief Define the set of user data as the LiveObjects IoT Collected Data.
 *
 *
 * @param prefix      add stream prefix
 *                       prefix=1 -> urn:lo:nsid:<name space>:<device id>!
 *                       prefix=2 -> <name space>:<device id>!
 *
 * @param stream_id   Pointer to a c-string specifying the Stream Identifier:
 *                    Identifier of the timeseries this collected data belongs to.
 * @param model       Pointer to a c-string specifying the Model:
 *                    a string identifying the schema used for the "value" part of the message,
 *                    to avoid conflict at data indexing.
 * @param tags        Optional, pointer to a c-string specifying the tags, coded in JSON format
 *                    (i.e "\"tag1\", \"tag2\"" )
 * @param gps_ptr     Optional, pointer to structure given the current GPS position.
 * @param data_ptr    Pointer to an array of LiveObjects IoT Data
 * @param data_nb     Number of elements in this array.
 *
 * @return an handle value >= 0  if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_AttachData (
        uint8_t prefix,
        const char* stream_id, const char* model, const char* tags,
        const LiveObjectsD_GpsFix_t* gps_ptr,
        const LiveObjectsD_Data_t*   data_ptr, int32_t data_nb);


/**
 * @brief Define the set of user commands.
 *
 * @param cmd_ptr     Pointer to an array of LiveObjects IoT Commands
 * @param cmd_nb      Number of elements in this array.
 * @param callback    User callback function, called when a command is received from LiveObjects server.
 *
 * @return an handle value >= 0  if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_AttachCommands (
        const LiveObjectsD_Command_t* cmd_ptr,
        int32_t cmd_nb,
        LiveObjectsD_CallbackCommand_t callback);


/**
 * @brief Define the set of user resources
 *
 * @param rsc_ptr     Pointer to an array of LiveObjects IoT Resources
 * @param rsc_nb      Number of elements in this array.
 * @param ntfyCB      User callback function, called when download operation is requested or completed by LiveObjects server.
 * @param dataCB      User callback function, called when data is ready to be read.
 *
 * @return an handle value >= 0  if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_AttachResources (
        const LiveObjectsD_Resource_t* rsc_ptr,
        int32_t rsc_nb,
        LiveObjectsD_CallbackResourceNotify_t ntfyCB,
        LiveObjectsD_CallbackResourceData_t   dataCB);

/**
 * @brief Enable/disable command feature.
 *
 * @param enable       Boolean to enable/disable the feature

 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_ControlCommands (bool enable);

/**
 * @brief Enable/disable 'resource' feature.
 *
 * @param enable       Boolean to enable/disable the feature

 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_ControlResources (bool enable);


/**
 * @brief Remove a set of user data
 *
 * @param handle      Collected data handle (returned by LiveObjectsClient_AttachData)

 * @return  0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_RemoveData(int handle);


/**
 * @brief Change the stream-id of a collect data set
 *
 * @param handle      Collected data handle (returned by LiveObjectsClient_AttachData)
 * @param stream_id   Pointer to a c-string specifying the Stream Identifier:
 *                    Identifier of the timeseries this collected data belongs to.

 * @return  0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_ChangeDataStreamId( uint8_t prefix, int handle, const char* stream_id );

/**
 * @brief Remove a set of user commands
 *
 * @param handle     command handle (returned by LiveObjectsClient_AttachCommands)

 * @return  0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_RemoveCommands(void);

/**
 * @brief Remove a set of user resources
 *
 * @return  0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_RemoveResources(void);


/* @} group end : Config */


//==================================================================
/**
 * \addtogroup  DynamicOpe   Dynamic Operations
 *
 * @{
 */

/**
 * @brief Create a LiveObjects Client thread to do LiveObjectsClient_Run().
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 *
 */
int LiveObjectsClient_ThreadStart(LiveObjectsD_CallbackState_t callback);


/**
 * @brief Return the state of LiveObjectsClient_Run().
 *
 * @return
 *  > 0 : Running
 *   0 : Never started
 *  -1 : Stopping
 *  -2 : Stopped
 *
 */
int8_t LiveObjectsClient_ThreadState(void);


/**
 * @brief Main loop of LiveObjects Client thread.
 *
 * A loop doing:
 * - Connect to LiveObjects server
 *     -# : Initialize and declare all sets of items (if attached): Status, Configuration, Resources, Commands
 *     -# : Subscribe to required topics
 *     -# : Do  (while it is always connected to LiveObject server)\n
 *          3.1 Process all pending requests (from users): Status, Configuration, Resources, Collected Data, Pending Publish requests\n
 *          3.2 Process incoming MQTT data (calling callback functions)\n
 *     -# : Disconnect
 * - Wait a delay and retry the first connection step.
 *
 * @note However, user may build this own loop by calling the functions below:
 * - LiveObjectsClient_Connect
 * - LiveObjectsClient_Cycle
 * - LiveObjectsClient_Disconnect
 */
void LiveObjectsClient_Run(LiveObjectsD_CallbackState_t callback);


/**
 * @brief Stop the main loop of LiveObjects Client thread.
 *
 * @return 0 if it was running, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Stop(void);

/**
 * @brief Connect the device to the remote LiveObjects Server.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Connect(void);

/**
 * @brief Disconnect the device to the remote LiveObjects Server.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Disconnect(void);


/**
 * @brief Do only a MQTT schedule
 *  - processing MQTT ping message
 *  - receiving MQTT messages and if necessary calling user callback function
 *
 * @param timeout_ms   Time in milliseconds to wait for message sent/published by LiveObjects platform
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Yield(int timeout_ms);


/**
 * @brief Do a LiveObjects MQTT cycle
 * - processing all pending message to be sent
 * - and then calling LiveObjectsClient_Yield
 *
 * @param timeout_ms   Time in milliseconds to wait for message sent/published by LiveObjects platform
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Cycle( int timeout_ms );


/* @} group end : DynamicOpe */

//==================================================================
/**
 * \addtogroup  TriggerOpe Trigger to request an action
 *
 * Note that action will be effectively performed in the next loop of LiveObjects IoT Client thread
 * The order of push actions is not guaranteed.
 *
 * @{
 */

/**
 * @brief Request to publish one set of 'status' to LiveObjects server.
 *
 * @param handle      Handle of user status set
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_PushStatus(int handle);

/**
 * @brief Request to publish one set of 'collected data' to LiveObjects server.
 *
 * @param handle      Handle of collected data set
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_PushData(int handle);

/**
 * @brief Request to publish the set of configuration parameters to LiveObjects server.
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_PushCfgParams(void);

/**
 * @brief Request to publish the set of resources to LiveObjects server.
 *
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */

int LiveObjectsClient_PushResources(void);

/* @} group end : TriggerOpe */


//==================================================================
/**
 * \addtogroup  Async Asynchronous Operations
 *
 *
 * @{
 */

/**
 * @brief Read data from the current resource transfer.
 *
 * @param rsc_ptr     Pointer to the user resource item.
 * @param data_ptr    Pointer to the user buffer to receive data
 * @param data_len    Length (in bytes) of this buffer
 *
 * @return The number of read bytes, otherwise a negative value or zero is an error.
 */
int LiveObjectsClient_RscGetChunck(
        const LiveObjectsD_Resource_t* rsc_ptr,
        char* data_ptr, int data_len);


/**
 * @brief Request to publish a command response.
 *
 * @param cid         Correlation Identifier ((given by LiveObjects client while command receipt).
 * @param data_ptr    Pointer to the first data in  an array of data (not an array of pointers)
 * @param data_nb     The number of data in array
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_CommandResponse(int32_t cid, const LiveObjectsD_Data_t* data_ptr, int data_nb);


/**
 * @brief Publish a payload (JSON message) onto the topic toward a LiveObjects platform.
 *        This operation is done with QOS=0 : no ack from server.
 *
 * @param topic_name   Pointer to a c-string specifying the MQTT topic.
 * @param payload_data Pointer to a c-string containing the user payload (JSON text message).
 *
 * @return 0 if successful, otherwise a negative value when occur occurs.
 */
int LiveObjectsClient_Publish(
        const char* topic_name,
        const char* payload_data);

/* @} group end : Async */

#if defined(__cplusplus)
}
#endif

#endif /* __LiveObjectsClient_Core_H_ */
