/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  LiveObjectsClient_Defs.h
  * @brief Global Definitions used by LiveObjects Client (using json representation)
  */

#ifndef __LiveObjectsClient_Defs_H_
#define __LiveObjectsClient_Defs_H_

#include <stdint.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief GPS position
 */
typedef struct {
    uint8_t gps_valid;      ///< Flag indicating if GPS position is valid
    float   gps_lat;        ///< Latitude
    float   gps_long;       ///< Longitude
} LiveObjectsD_GpsFix_t;


/**
 * @brief Define type of LiveObjects Data (item)
 *
 * \todo: Support array, 64-bit integer and 64-bit unsigned integer.
 */
typedef enum {
    LOD_TYPE_UNKNOWN = 0, ///< Unknown
    LOD_TYPE_INT32 = 1,   ///< 32-bit Signed integer
    LOD_TYPE_INT16,       ///< 16-bit Signed integer
    LOD_TYPE_INT8,        ///<  8-bit Signed integer
    LOD_TYPE_UINT32,      ///< 32-bit Unsigned integer
    LOD_TYPE_UINT16,      ///< 16-bit Unsigned integer
    LOD_TYPE_UINT8,       ///< 8-bit Unsigned integer
    LOD_TYPE_STRING_C,    ///< c-string (terminated by null character)
    LOD_TYPE_BOOL,        ///< boolean - value defined as 8-bit unsigned integer, and JSON value: "true" our "false"
    LOD_TYPE_FLOAT,       ///< 32-bit float
    LOD_TYPE_DOUBLE,      ///< 64-bit float
    LOD_TYPE_MAX_NOT_USED
} LiveObjectsD_Type_t;

/**
 * @brief Define an user data (item) to build a JSON format
 */
typedef struct {
    LiveObjectsD_Type_t  data_type;    ///< Type of user data
    const char*          data_name;    ///< Name of user data (used as the JSON name)
    void*                data_value;   ///< Pointer to the user data value
} LiveObjectsD_Data_t;


/**
 * @brief Define an user configuration parameter to build  JSON format
 */
typedef struct {
    uint32_t             parm_uref;    ///< Parameter user reference (maybe useful for user)
    LiveObjectsD_Data_t  parm_data;    ///< Data specifying the configuration parameter
} LiveObjectsD_Param_t;


/**
 * @brief Define an user resource
 */
typedef struct {
    int         rsc_uref;          ///< Resource user reference (maybe useful for user)
    const char* rsc_name;          ///< Resource name
    const char* rsc_version_ptr;   ///< Pointer to a c_string specifying the current resource Version
    uint16_t    rsc_version_sz;    ///< Max size in bytes of version c-string
} LiveObjectsD_Resource_t;


/**
 * @brief Define an user command entry
 */
typedef struct {
    uint32_t            cmd_uref;   ///< Command user reference (maybe useful for user)
    const char*         cmd_name;   ///< Command name
    int                 cmd_cid;    ///< Correlation Id
} LiveObjectsD_Command_t;


/**
 * @brief Define one command argument (in command received from LiveObject server)
 */
typedef struct {
    const char* arg_name;     ///< Pointer to argument name (it is a JSON tag)
    const char* arg_value;    ///< Pointer to argument value
    uint16_t    arg_type;     ///< Argument type: 0= Primitive JSON type, otherwise it is a STRING (JSON value with double-quote)
} LiveObjectsD_CommandArg_t;


/**
 * @brief Define command request header (block without argument)
 */
typedef struct {
    uint32_t    cmd_blk_len;    ///< Size of this allocated  memory block (including this header and all command arguments, nested just after this header)
    const LiveObjectsD_Command_t* cmd_ptr;  ///< Pointer to the user command
    int         cmd_cid;        ///< Correlation Id (required to set in command response)
    uint16_t    cmd_args_nb;    ///< Number of arguments (see LiveObjectsD_CommandRequestBlock_t if there is at least one argument)
}  LiveObjectsD_CommandRequestHeader_t;

/**
 * @brief Define command request block with at least one argument
 *
 * \code{.unparsed}
 *  ===============
 *  | CMD HEADER  |
 *  |=============|
 *  | CmdArg 1    | ----
 *  | ....        |    |
 *  | CmdArg n    | --------
 *  |=============|    |   |
 *  | Arg Name 1  |<---|   |
 *  | Arg Value 1 |        |
 *  |-------------|        |
 *  |    ...      |        |
 *  |-------------|        |
 *  | Arg Name n  |<--------
 *  | Arg Value n |
 *  ===============
 * \endcode
 */
typedef struct {
    LiveObjectsD_CommandRequestHeader_t  hd;             ///< Request header
    const LiveObjectsD_CommandArg_t      args_array[1];  ///< The first command arguments. May be followed by others arguments.
} LiveObjectsD_CommandRequestBlock_t;


/**
 * @brief  LiveObjects Client State
 */
typedef enum {
    CSTATE_DISCONNECTED = 0,  ///< Client is disconnected to the  LiveObjects platform
    CSTATE_CONNECTING,        ///< Client is trying to establish a connection to the LiveObjects platform
    CSTATE_CONNECTED,         ///< Client is connected to the  LiveObjects platform
    CSTATE_DOWN               ///< Client Thread is down or stopped
} LiveObjectsD_State_t;

/**
 * @brief  Prototype of a user callback function called to notify the LiveObjects Client state changes.
 *
 * @param state   LiveObjects Client State
 */
typedef void (*LiveObjectsD_CallbackState_t) ( LiveObjectsD_State_t state );


/**
 * @brief  Type of a user callback function linked to a set of configuration parameters.
 *         This function will be called when user configuration parameter must be
 *         updated with a new value.
 *
 * @param param_ptr   Pointer to the LiveObject Configuration Parameter to be updated.
 * @param val_ptr     Pointer to a value.
 * @param val_len     Length of this value.
 *
 * @return
 *       1 : accepted, otherwise refused by user.
 */
typedef int (*LiveObjectsD_CallbackParams_t) (
        const LiveObjectsD_Param_t* param_ptr,
        const void* val_ptr, int val_len);

/**
 * @brief  Type of a user callback function linked to a set of user commands.
 *         This function will be called when a command must be processed by user.
 *
 * @param pCmdReqBlk   Pointer to a data block given arguments
 */
typedef int (*LiveObjectsD_CallbackCommand_t) (
        LiveObjectsD_CommandRequestBlock_t* pCmdReqBlk);


/**
 * @brief  Enum of resource response code
 **/
typedef enum {
    RSC_RSP_OK = 0,                    ///< OK, no error.
    RSC_RSP_ERR_INTERNAL_ERROR,        ///< Internal Error (decoding the JSON message, ..)
    RSC_RSP_ERR_WRONG_SOURCE_VERSION,  ///< User refuses transfer because wrong version
    RSC_RSP_ERR_INVALID_RESOURCE,      ///< Unknown resource.
    RSC_RSP_ERR_NOT_AUTHORIZED,        ///< Transfer is not allowed (busy, ..).
    RSC_RSP_ERR_BUSY,                  ///< Busy. Not used, replaced by RSC_RSP_ERR_NOT_AUTHORIZED.
    RCP_RSP_MAX
} LiveObjectsD_ResourceRespCode_t;

/**
 * @brief  Type of a user callback function.
 *         This function will be called when a download is requested or completed.
 * @param state         0: started, 1 : completed without error, 2 : completed with error
 * @param rsc_ptr       Pointer to the user resource
 * @param version_old   Old version (known by the LiveObject server)
 * @param version_new   New version requested
 * @param rsc_size      Size in bytes of the new resource to be download.
 *
 * @return
 *     when state=0      (started),   0: Accepted otherwise the value of refused cause.
 *     when state=1 or 2 (completed), no meaning
 */
typedef LiveObjectsD_ResourceRespCode_t (*LiveObjectsD_CallbackResourceNotify_t) (
        uint8_t state,
        const LiveObjectsD_Resource_t* rsc_ptr,
        const char* version_old,
        const char* version_new,
        uint32_t rsc_size);

/**
 * @brief  Type of a user callback function.
 *         This function will be called when data is ready to be read on TCP socket.
 *         The user application has to call the LiveObjectsClient_RscGetChunck()
 *         function to read data
 *
 * @param rsc_ptr      Pointer to the user resource element.
 * @param rsc_offset   Data offset.
 *
 * @return Length (in bytes) of read data. Negative value or 0 is an error stopping the download.
 *
 */
typedef int (*LiveObjectsD_CallbackResourceData_t) (
        const LiveObjectsD_Resource_t* rsc_ptr,
        uint32_t rsc_offset);


#if defined(__cplusplus)
}
#endif

#endif /* __LiveObjectsClient_Defs_H_ */
