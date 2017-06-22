/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  loc_msg_encode.c
  * @brief Encode JSON messages to be published
  */

#include "liveobjects-client/LiveObjectsClient_Config.h"

#include "loc_msg.h"
#include "loc_json_api.h"
#include "loc_sys.h"

#ifndef TRACE_GROUP
#define TRACE_GROUP "JSON"
#endif
#include "liveobjects-sys/loc_trace.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "liveobjects-sys/LiveObjectsClient_Platform.h"

//static char _LO_msg_buf[LOM_JSON_BUF_SZ];

//---------------------------------------------------------------------------------
//
static const char* LO_msg_encode_status_buf( char* buf_ptr, uint32_t buf_len, const LOMArrayOfData_t* pObjSet )
{
    int ret, i;
    const LiveObjectsD_Data_t* data_ptr;
    ret = LO_json_begin_section(buf_ptr, buf_len, "info");
    if (ret) {
        LOTRACE_ERR("encode_status: failed (LO_json_begin)");
        return NULL;
    }
    data_ptr = pObjSet->data_ptr;
    for (i=0; i < pObjSet->data_nb; i++) {
        LOTRACE_DBG("encode_status: [%d] - data_type=%d=%s data_name=%s",
                i, data_ptr->data_type, LO_getDataTypeToStr(data_ptr->data_type), data_ptr->data_name);
        ret = LO_json_add_item(data_ptr, buf_ptr, buf_len);
        if (ret) {
            LOTRACE_ERR("encode_status: failed (LO_json_add_item)");
            return NULL;
        }
        data_ptr++;
    }
    ret = LO_json_end_section(buf_ptr, buf_len);
    if (ret) {
        LOTRACE_ERR("encode_status: failed (LO_json_end)");
        return NULL;
    }
    return buf_ptr;
}

//---------------------------------------------------------------------------------
//
static const char* LO_msg_encode_data_buf(char* buf_ptr, uint32_t buf_len, const LOMSetOfData_t* pSetData)
{
    int ret;

    ret = LO_json_begin(buf_ptr, buf_len);
    if (ret) LOTRACE_ERR("encode_data: failed (LO_json_begin)");

    if (ret == 0) {
        // stream id
        ret = LO_json_add_name_str("s", pSetData->stream_id , buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (stream_id)");
    }

    // timestamp
    if ((ret == 0) && (pSetData->timestamp[0])) {
        ret = LO_json_add_name_str("ts", pSetData->timestamp, buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (timestamp)");
    }

    if (ret == 0) {
        // model
        ret = LO_json_add_name_str("m", pSetData->model, buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (model)");
    }

    // Add GPS localization
    if ((ret == 0)  && (pSetData->gps_ptr) && (pSetData->gps_ptr->gps_valid)) {
        char msg[80];
        snprintf(msg, sizeof(msg)-1, "%3.6f,%3.6f", pSetData->gps_ptr->gps_lat, pSetData->gps_ptr->gps_long);
        ret = LO_json_add_name_array("loc", msg, buf_ptr, buf_len);
    }

    if (ret == 0) {
        ret = LO_json_add_section_start("v", buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (add section v)");
    }

    if (ret == 0) {
        int i;
        const LiveObjectsD_Data_t* data_ptr = pSetData->data_set.data_ptr;
        for (i=0; i < pSetData->data_set.data_nb;i++) {
            LOTRACE_DBG("encode_data: [%d] - data_type=%d=%s data_name=%s",
                    i, data_ptr->data_type, LO_getDataTypeToStr(data_ptr->data_type), data_ptr->data_name);
            ret = LO_json_add_item(data_ptr, buf_ptr, buf_len);
            if (ret) {
                LOTRACE_ERR("encode_data: failed (LO_json_add_item)");
                break;
            }
            data_ptr++;
        }
    }

    if (ret == 0) {
        ret = LO_json_add_section_end( buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (end section v)");
    }

    if ((ret == 0) &&  (pSetData->tags[0])) {
        ret = LO_json_add_name_array( "t", pSetData->tags, buf_ptr, buf_len );
        if (ret) LOTRACE_ERR("encode_data: failed (LO_json_add_name_str(\"t\", ...)");
    }

    if (ret == 0) {
        ret = LO_json_end(buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_data: failed (LO_json_end)");
    }

    return (ret == 0)  ? buf_ptr : NULL;
}

//---------------------------------------------------------------------------------
//
static const char* LO_msg_encode_resources_buf(char* buf_ptr, uint32_t buf_len, const LOMSetOfResources_t* pSetResources )
{
    int ret, i;
    const LiveObjectsD_Resource_t* rsc_ptr;

    ret = LO_json_begin_section(buf_ptr, buf_len, "rsc");
    if (ret) {
        LOTRACE_ERR("encode_resources: failed (LO_json_begin)");
        return NULL;
    }
    rsc_ptr = pSetResources->rsc_ptr;
    for (i=0; i < pSetResources->rsc_nb; i++) {
        LOTRACE_DBG("encode_resources: [%d] - rsc_name=%s version=%s",
                i, rsc_ptr->rsc_name, rsc_ptr->rsc_version_ptr);
        if (ret == 0) ret = LO_json_add_section_start( rsc_ptr->rsc_name, buf_ptr, buf_len);
        if (ret == 0) ret = LO_json_add_name_str("v", rsc_ptr->rsc_version_ptr, buf_ptr, buf_len);


        // metadata section: empty
        if (ret == 0) ret = LO_json_add_section_start("m", buf_ptr, buf_len);
        if (ret == 0) ret = LO_json_add_section_end(buf_ptr, buf_len);

        if (ret == 0) ret = LO_json_add_section_end(buf_ptr, buf_len);
        if (ret) {
            LOTRACE_ERR("encode_resources: failed (rsc[%d] - rsc_name=%s version=%s)",
                    i, rsc_ptr->rsc_name, rsc_ptr->rsc_version_ptr);
            return NULL;
        }
        rsc_ptr++;
    }
    ret = LO_json_end_section(buf_ptr, buf_len);
    if (ret) {
        LOTRACE_ERR("encode_resources: failed (LO_json_end)");
        return NULL;
    }
    return buf_ptr;
}

//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_params_all_buf(char* buf_ptr, uint32_t buf_len, const LOMArrayOfParams_t* params_array, int32_t cid)
{
    int ret, i;
    const LiveObjectsD_Param_t* param_ptr;

    ret = LO_json_begin_section(buf_ptr, buf_len, "cfg");
    if (ret) {
        LOTRACE_ERR("encode_cfg_all: failed (LO_json_begin)");
        return NULL;
    }
    param_ptr = params_array->param_ptr;
    for (i=0; i < params_array->param_nb; i++) {
        LOTRACE_DBG("encode_cfg_all: [%d] - data_type=%d=%s data_name=%s ...",
                i, param_ptr->parm_data.data_type, LO_getDataTypeToStr(param_ptr->parm_data.data_type), param_ptr->parm_data.data_name);
        ret = LO_json_add_param(&param_ptr->parm_data, buf_ptr, buf_len);
        if (ret) {
            LOTRACE_ERR("encode_cfg_all: failed (LO_json_add_param)");
            return NULL;
        }
        param_ptr++;
    }

    if (cid) {
        if (ret == 0) {
            ret = LO_json_add_section_end(buf_ptr, buf_len);
            if (ret) LOTRACE_ERR("encode_cfg_update: failed (LO_json_end_section)");
        }

        if (ret == 0) {
            ret = LO_json_add_name_int("cid", cid, buf_ptr, buf_len);
            if (ret) LOTRACE_ERR("encode_cfg_update: failed while adding cid=%"PRIi32", rc=%d", cid, ret);
        }
        if (ret == 0) {
            ret = LO_json_end(buf_ptr, buf_len);
            if (ret) LOTRACE_ERR("encode_cfg_update: failed (LO_json_end)");
        }
    } else {
        ret = LO_json_end_section(buf_ptr, buf_len);
        if (ret) {
            LOTRACE_ERR("encode_cfg_all: failed (LO_json_end)");
            return NULL;
        }
    }
    return buf_ptr;
}

//---------------------------------------------------------------------------------
//
static const char* LO_msg_encode_cmd_resp_buf(char* buf_ptr, uint32_t buf_len,
        int32_t cid, const LiveObjectsD_Data_t* data_ptr, int data_nb)
{
    int ret;

    if  (cid == 0) {
        LOTRACE_ERR("encode_cmd_resp_buf: failed, invalid parameters cid=%"PRIu32, cid);
        return NULL;
    }

    ret = LO_json_begin_section(buf_ptr, buf_len, "res");
    if (ret) LOTRACE_ERR("encode_cmd_resp_buf: failed (LO_json_begin)");

    if ((ret == 0) && (data_ptr)  && (data_nb > 0)) {
        int i;
        const LiveObjectsD_Data_t* p_data = data_ptr;
        for (i=0; i < data_nb; i++) {
            LOTRACE_DBG("encode_cmd_resp_buf: [%d] - data_type=%d=%s data_name=%s",
                    i, p_data->data_type, LO_getDataTypeToStr(p_data->data_type), p_data->data_name);
            ret = LO_json_add_item(p_data, buf_ptr, buf_len);
            if (ret) {
                LOTRACE_ERR("encode_cmd_resp_buf: failed (LO_json_add_item)");
                break;
            }
            p_data++;
        }
    }

    if (ret == 0) {
        ret = LO_json_add_section_end(buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_cmd_resp_buf: failed (LO_json_end_section)");
    }

    if (ret == 0) {
        ret = LO_json_add_name_int("cid", cid, buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_cmd_resp_buf: failed while adding cid=%"PRIi32", rc=%d", cid, ret);
    }

    if (ret == 0) {
        ret = LO_json_end(buf_ptr, buf_len);
        if (ret) LOTRACE_ERR("encode_cmd_resp_buf: failed (LO_json_end)");
    }
    return  (ret == 0) ? buf_ptr : NULL;
}

//=================================================================================
//
//---------------------------------------------------------------------------------

static char _LO_msg_buf[LOM_JSON_BUF_SZ];

//---------------------------------------------------------------------------------
//
static const char* lib_rsc_res[] = {
        "OK",
        "INTERNAL_ERROR",
        "UNKNOWN_RESOURCE",
        "WRONG_SOURCE_VERSION",
        "INVALID_RESOURCE",
        "NOT_AUTHORIZED",
        "BUSY"
};

const char* LO_msg_encode_rsc_result(int32_t cid, LiveObjectsD_ResourceRespCode_t result)
{
    int ret;

    if  (cid == 0) {
        LOTRACE_ERR("encode_rsc_result: failed, invalid parameters cid=%"PRIu32, cid);
        return NULL;
    }

    ret = LO_json_begin(_LO_msg_buf, LOM_JSON_BUF_SZ);
    if (ret) LOTRACE_ERR("encode_rsc_result: failed (LO_json_begin)");

    if (ret == 0) {
        int res_idx = result;
        if ((res_idx < 0) || (res_idx >= RCP_RSP_MAX)) res_idx = RSC_RSP_ERR_INTERNAL_ERROR;
        LOTRACE_INF("encode_rsc_result: cid=%"PRIi32", result=%d -> %d res=%s", cid, result, res_idx, lib_rsc_res[res_idx]);
        ret = LO_json_add_name_str("res", lib_rsc_res[res_idx], _LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_rsc_result: failed while adding res=%d %d %s, rc=%d", result, res_idx, lib_rsc_res[res_idx], ret);
    }

    if (ret == 0) {
        ret = LO_json_add_name_int("cid", cid, _LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_rsc_result: failed while adding cid=%"PRIi32", rc=%d", cid, ret);
    }

    if (ret == 0) {
        ret = LO_json_end(_LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_rsc_result: failed (LO_json_end)");
    }
    return  (ret == 0) ? _LO_msg_buf : NULL;
}


//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_params_update(const LOMSetofUpdatedParams_t* pParamUpdateSet)
{
    int ret;

    if (pParamUpdateSet == NULL) {
        LOTRACE_ERR("encode_cfg_update: failed, invalid parameters pParamUpdateSet=%p", pParamUpdateSet);
        return NULL;
    }

    if  (pParamUpdateSet->cid == 0) {
        LOTRACE_ERR("encode_cfg_update: failed, invalid parameters cid=%"PRIu32, pParamUpdateSet->cid);
        return NULL;
    }

    if ((pParamUpdateSet->nb_of_params == 0) || (pParamUpdateSet->tab_of_param_ptr[0] == NULL)) {
        LOTRACE_WARN("encode_cfg_update: Empty");
        return NULL;
    }

    ret = LO_json_begin_section(_LO_msg_buf, LOM_JSON_BUF_SZ, "cfg");
    if (ret) LOTRACE_ERR("encode_cfg_update: failed (LO_json_begin)");

    if (ret == 0) {
        int i;
        const LiveObjectsD_Param_t* param_ptr;
        for (i=0; i < pParamUpdateSet->nb_of_params; i++) {
            param_ptr = pParamUpdateSet->tab_of_param_ptr[i];
            if (param_ptr == NULL) {
                LOTRACE_ERR("encode_cfg_update: failed while getting next param object [%d/%"PRIi32"]", i, pParamUpdateSet->nb_of_params );
                break;
            }
            LOTRACE_DBG("encode_cfg_update: [%d] - data_type=%d=%s data_name=%s ...",
                    i, param_ptr->parm_data.data_type, LO_getDataTypeToStr(param_ptr->parm_data.data_type), param_ptr->parm_data.data_name);
            ret = LO_json_add_param(&param_ptr->parm_data, _LO_msg_buf, LOM_JSON_BUF_SZ);
            if (ret) {
                LOTRACE_ERR("encode_cfg_update: failed (LO_json_add_param)");
                break;
            }
        }
    }
    if (ret == 0) {
        ret = LO_json_add_section_end(_LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cfg_update: failed (LO_json_end_section)");
    }

    if (ret == 0) {
        ret = LO_json_add_name_int("cid", pParamUpdateSet->cid, _LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cfg_update: failed while adding cid=%"PRIi32", rc=%d", pParamUpdateSet->cid, ret);
    }

    if (ret == 0) {
        ret = LO_json_end(_LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cfg_update: failed (LO_json_end)");
    }
    return  (ret == 0) ? _LO_msg_buf : NULL;
}


//---------------------------------------------------------------------------------
//
static const char* lib_res[] = {
        "Invalid",
        "Bad format",
        "Not supported",
        "Not processed"
};

const char* LO_msg_encode_cmd_result(int32_t cid, int result)
{
    int ret;

    if  (cid == 0) {
        LOTRACE_ERR("encode_cmd_resp: failed, invalid parameters cid=%"PRIu32, cid);
        return NULL;
    }

    ret = LO_json_begin_section(_LO_msg_buf, LOM_JSON_BUF_SZ, "res");
    if (ret) LOTRACE_ERR("encode_cmd_resp: failed (LO_json_begin)");

    if (ret == 0) {
        if (result < 0) {
            int err_idx = -result - 1;
            LOTRACE_WARN("encode_cmd_resp: ERROR result=%d  err_idx=%d", result, err_idx);
            ret = LO_json_add_name_int("lom_err_code", result, _LO_msg_buf, LOM_JSON_BUF_SZ);
            if (ret) LOTRACE_ERR("encode_cmd_resp: failed (LO_json_end_section)");

            if ((ret == 0) && (err_idx >= 0) && (err_idx < 4)) {
                ret = LO_json_add_name_str("lom_error", lib_res[err_idx], _LO_msg_buf, LOM_JSON_BUF_SZ);
            }
        }
        else if (result > 0) { // User code
            ret = LO_json_add_name_int("result", result, _LO_msg_buf, LOM_JSON_BUF_SZ);
        }
        else  { // result == 0,  Not called => pending request; Delayed response procssed by user.
            ; // ret = LO_json_add_name_str("status", "pending", _LO_msg_buf, LOM_JSON_BUF_SZ);
        }
    }

    if (ret == 0) {
        ret = LO_json_add_section_end(_LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cmd_resp: failed (LO_json_end_section)");
    }

    if (ret == 0) {
        ret = LO_json_add_name_int("cid", cid, _LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cmd_resp: failed while adding cid=%"PRIi32", rc=%d", cid, ret);
    }

    if (ret == 0) {
        ret = LO_json_end(_LO_msg_buf, LOM_JSON_BUF_SZ);
        if (ret) LOTRACE_ERR("encode_cmd_resp: failed (LO_json_end)");
    }
    return  (ret == 0) ? _LO_msg_buf : NULL;
}

//---------------------------------------------------------------------------------
//
static const char* LO_msg_alloc(uint8_t from, const char* p_msg)
{
    char* p = NULL;
    int  len = strlen(p_msg);
    if (len  > 0) {
        len += 3;
        p = (char*)malloc(len);
        if (p) {
            LOTRACE_DBG("LO_msg_alloc(from %x) - MEM_ALLOC %p len=%d", from, p, len);
            *p = from;          // First byte is used to indicate the type of message
            strcpy(p+1, p_msg); // And copy JSON msg in this allocated buffer
        }
        else {
            LOTRACE_ERR("LO_msg_alloc(from %x): ERROR malloc(len=%d)", from, len);
        }
    }
    return p;
}


static char _LO_msg_buf[LOM_JSON_BUF_SZ];
static char _LO_msg_buf_user[LOM_JSON_BUF_USER_SZ];

//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_cmd_resp(uint8_t from, int32_t cid, const LiveObjectsD_Data_t* data_ptr, int data_nb)
{

    const char *p_msg;
    if (from == 0) { // Called by the LOM Client Thread.
        p_msg = LO_msg_encode_cmd_resp_buf(_LO_msg_buf, LOM_JSON_BUF_SZ , cid, data_ptr, data_nb);
    }
    else {;
        // TODO: lock ? here it is called by application. And there is only one thread in this example !!
        // Use a local buffer to build JSON message
        p_msg = LO_msg_encode_cmd_resp_buf(_LO_msg_buf_user, LOM_JSON_BUF_USER_SZ, cid, data_ptr, data_nb);
        if (p_msg) {
            p_msg = LO_msg_alloc(from, p_msg);
        }
        //TODO: unlock
    }
    return p_msg;
}


//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_status( uint8_t from, const LOMArrayOfData_t* pObjSet )
{
    const char *p_msg;

    if (pObjSet == NULL) {
        LOTRACE_ERR("encode_status: failed, invalid parameters pObjSet=%p", pObjSet);
        return NULL;
    }
    if ((pObjSet->data_nb == 0) || (pObjSet->data_ptr == NULL)) {
        LOTRACE_WARN("encode_status: Empty");
        return NULL;
    }

    if (from == 0) { // Called by the LiveObjects Client Thread.
        p_msg = LO_msg_encode_status_buf(_LO_msg_buf, LOM_JSON_BUF_SZ , pObjSet);
    }
    else {
        // TODO: lock ? here it is called by application. And there is only one thread in this example !!
        // Use a local buffer to build JSON message
       if (MSG_MUTEX_LOCK()) {
            LOTRACE_ERR("Error to lock mutex");
            return NULL;
        }
        p_msg = LO_msg_encode_status_buf(_LO_msg_buf_user, LOM_JSON_BUF_USER_SZ, pObjSet);
        if (p_msg) {
            p_msg = LO_msg_alloc(from, p_msg);
        }
        //TODO: unlock
        MSG_MUTEX_UNLOCK();
    }
    return p_msg;
}


//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_data( uint8_t from, const LOMSetOfData_t* pSetData )
{
    const char *p_msg;

    if ((pSetData == NULL) || (pSetData->stream_id[0] == 0)) {
        LOTRACE_ERR("encode_data: failed, invalid parameters pDataSet=%p", pSetData);
        return NULL;
    }

    if ((pSetData->data_set.data_nb == 0) || (pSetData->data_set.data_ptr == NULL)) {
        LOTRACE_WARN("encode_data: Empty");
        return NULL;
    }
    if (from == 0) { // Called by the LiveObjects Client Thread.
        p_msg = LO_msg_encode_data_buf(_LO_msg_buf, LOM_JSON_BUF_SZ , pSetData);
    }
     else {
         // TODO: lock ? here it is called by application. And there is only one thread in this example !!
         // Use a local buffer to build JSON message
         if (MSG_MUTEX_LOCK()) {
              LOTRACE_ERR("Error to lock mutex");
              return NULL;
          }
         p_msg = LO_msg_encode_data_buf(_LO_msg_buf_user, LOM_JSON_BUF_USER_SZ, pSetData);
         if (p_msg) {
             p_msg = LO_msg_alloc(from, p_msg);
        }
        //TODO: unlock
        MSG_MUTEX_UNLOCK();
    }
    return p_msg;
}

//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_resources( uint8_t from, const LOMSetOfResources_t* pSetResources )
{
    const char *p_msg;

    if (pSetResources == NULL) {
        LOTRACE_ERR("encode_resources: failed, invalid parameters pSetResources=%p", pSetResources);
        return NULL;
    }
    if ((pSetResources->rsc_nb == 0) || (pSetResources->rsc_ptr == NULL)) {
        LOTRACE_WARN("encode_resources: Empty");
        return NULL;
    }

    if (from == 0) { // Called by the LiveObjects Client Thread.
        p_msg = LO_msg_encode_resources_buf(_LO_msg_buf, LOM_JSON_BUF_SZ , pSetResources);
    }
    else {
        // TODO: lock ? here it is called by application. And there is only one thread in this example !!
        // Use a local buffer to build JSON message
        if (MSG_MUTEX_LOCK()) {
             LOTRACE_ERR("Error to lock mutex");
             return NULL;
         }
        p_msg = LO_msg_encode_resources_buf(_LO_msg_buf_user, LOM_JSON_BUF_USER_SZ, pSetResources);
        if (p_msg) {
            p_msg = LO_msg_alloc(from, p_msg);
        }
        //TODO: unlock
        MSG_MUTEX_UNLOCK();
     }
     return p_msg;
}

//---------------------------------------------------------------------------------
//
const char* LO_msg_encode_params_all( uint8_t from, const LOMArrayOfParams_t* params_array, int32_t cid)
{
    const char *p_msg;
    if (params_array == NULL) {
        LOTRACE_ERR("encode_params_all: failed, invalid parameters params_array=%p", params_array);
        return NULL;
    }
    if ((params_array->param_nb == 0) || (params_array->param_ptr == NULL)) {
        LOTRACE_WARN("encode_params_all: Empty");
        return NULL;
    }
    if (from == 0) { // Called by the LiveObjects Client Thread.
        p_msg = LO_msg_encode_params_all_buf(_LO_msg_buf, LOM_JSON_BUF_SZ , params_array, cid);
    }
    else {
        // TODO: lock ? here it is called by application. And there is only one thread in this example !!
        // Use a local buffer to build JSON message
        if (MSG_MUTEX_LOCK()) {
             LOTRACE_ERR("Error to lock mutex");
             return NULL;
         }
        p_msg = LO_msg_encode_params_all_buf(_LO_msg_buf_user, LOM_JSON_BUF_USER_SZ, params_array, cid);
        if (p_msg) {
            p_msg = LO_msg_alloc(from, p_msg);
        }
        //TODO: unlock
        MSG_MUTEX_UNLOCK();
    }
    return p_msg;
}
