/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */
/**
  * @file  loc_msg_decode.c
  * @brief Decode and process the received JSON messages
  */

#include "loc_msg.h"
#include "loc_json_api.h"

#ifndef TRACE_GROUP
#define TRACE_GROUP "JMSG"
#endif
#include "liveobjects-sys/loc_trace.h"

#include "jsmn/jsmn.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "liveobjects-sys/LiveObjectsClient_Platform.h"

#define MSG_DBG       2
#define MSG_DUMP      1
#define SANITY_CHECK  0

//---------------------------------------------------------------------------------
//
static const char* conv_jsmntypeToString(jsmntype_t jtype)
{
    switch(jtype) {
    case JSMN_UNDEFINED : return "JSMN_UNDEFINED";
    case JSMN_OBJECT :    return "JSMN_OBJECT";
    case JSMN_ARRAY :     return "JSMN_ARRAY";
    case JSMN_STRING:     return "JSMN_STRING";
    case JSMN_PRIMITIVE : return "JSMN_PRIMITIVE";
    }
    return "JSMN_BAD_TYPE";
}

//---------------------------------------------------------------------------------
//
#ifdef SUPPORT_CMD_ARGS
static jsmntype_t conv_objTypeTojsmntype(LOMObjType_t objType)
{
    switch (objType) {
    case LOD_TYPE_INT32:
    case LOD_TYPE_INT16:
    case LOD_TYPE_INT8:

    case LOD_TYPE_UINT32:
    case LOD_TYPE_UINT16:
    case LOD_TYPE_UINT8:

    case LOD_TYPE_FLOAT:
    case LOD_TYPE_DOUBLE:
    case LOD_TYPE_BOOL:
        return JSMN_PRIMITIVE;

    case LOD_TYPE_STRING_C:
        return JSMN_STRING;


    case LOD_TYPE_UNKNOWN:
    case LOD_TYPE_MAX_NOT_USED:
        return JSMN_UNDEFINED;
    }
    return JSMN_UNDEFINED;
}
#endif

//---------------------------------------------------------------------------------
//
static int check_token(const char* payload_json, const jsmntok_t* token, const char* name)
{
    if ((payload_json == NULL) || (token == NULL) || (name == NULL) || (*name == 0)) {
        LOTRACE_ERR("check_token: Invalid parameters - payload=x%p token=x%p name=x%p (x%x)",
                payload_json, token, name, (name) ? *name : 0xFFFF);
        return -1;
    }
    if (token->type == JSMN_STRING) {
#if (SANITY_CHECK)
        int len = strlen(payload_json);
        if ((token->start > token->end) || (token->end >= len)) {
            LOTRACE_ERR("check_token: bad token - start=%d end=%d len=%d", token->start, token->end, len);
            return -1;
        }
#endif
        unsigned int tk_len = token->end - token->start;
        const char* tk_ptr = payload_json + token->start;
        if ((tk_len == strlen(name)) && !strncmp(tk_ptr, name, tk_len)) {
            LOTRACE_DBG("check_token: found %.*s", tk_len, tk_ptr);
            return 1;
        }
        LOTRACE_ERR("check_token: %s not found - token is %.*s", name, tk_len, tk_ptr);
    }
    else LOTRACE_ERR("check_token: token type (%d %s) is not JSMN_STRING", token->type, conv_jsmntypeToString(token->type));
    return 0;
}


//---------------------------------------------------------------------------------
//
static int isValidTokenPrimitive(const char* from, const char* payload_json, const jsmntok_t* token)
{
    if ((payload_json == NULL) || (token == NULL) ) {
        LOTRACE_ERR("%s: Invalid parameters - payload=x%p token=x%p", from, payload_json, token);
        return -1;
    }
#if (SANITY_CHECK)
    int len = strlen(payload_json);
    if ((token->start > token->end) || (token->end >= len)) {
        LOTRACE_ERR("%s: Bad token - start=%d end=%d len=%d", from, token->start, token->end, len);
        return -1;
    }
#endif
    if (token->type != JSMN_PRIMITIVE) {
        LOTRACE_WARN("%s: Unexpected type %d != %d", from,  token->type, JSMN_PRIMITIVE);
        return -1;
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
static int getValueINT32(int32_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueINT32", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIi32, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueINT32");
        return -1;
    }
    return 0;
}

#ifdef SUPPORT_CMD_ARGS
static int getValueINT16(int16_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueINT16", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIi16, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueINT16");
        return -1;
    }
    return 0;
}

static int getValueINT8(int8_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueINT8", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIi8, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueINT8");
        return -1;
    }
    return 0;
}
#endif

static int getValueUINT32(uint32_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueUINT32", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIu32, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueUINT32");
        return -1;
    }
    return 0;
}

#ifdef SUPPORT_CMD_ARGS
static int getValueUINT16(uint16_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueUINT16", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIu16, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueUINT16");
        return -1;
    }
    return 0;
}

static int getValueUINT8(uint8_t* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueUINT8", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%"PRIu8, value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueUINT8");
        return -1;
    }
    return 0;
}
#endif

static int getValueFLOAT(float* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueFLOAT", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%f", value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueFLOAT");
        return -1;
    }
    return 0;
}

static int getValueDOUBLE(double* value, const char* payload_json, const jsmntok_t* token) {
    if (isValidTokenPrimitive("getValueDOUBLE", payload_json, token)) return -1;
    if (1 != sscanf(payload_json + token->start, "%lf", value)) {
        LOTRACE_WARN("%s: Bad token value.", "getValueDOUBLE");
        return -1;
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
static int get_CorrelationId(
        int32_t*         pCid,
        const char*      payload_data,
        const jsmntok_t* tokens,
        int32_t          token_cnt)
{
    int idx;
    if ((payload_data == NULL) || (tokens == NULL) || (pCid == NULL) ) {
        LOTRACE_ERR("get_CorrelationId: Invalid parameters - payload=x%p tokens=x%p pCid=x%p", payload_data, tokens, pCid);
        return -1;
    }

    if (token_cnt < 2) {
        LOTRACE_ERR("get_CorrelationId:  require at least 2 tokens (cnt=%"PRIi32")", token_cnt);
        return -1;
    }
    token_cnt--;
    for (idx=0; idx < token_cnt; idx++) {
#if (MSG_DBG > 3)
        LOTRACE_DBG("get_CorrelationId: TK[%d] type=%d %s size=%d start=%d end=%d (len=%d)",
                idx, tokens[idx].type, conv_jsmntypeToString(tokens[idx].type), tokens[idx].size,
                tokens[idx].start, tokens[idx].end, tokens[idx].end - tokens[idx].start);
#endif
        if ( (tokens[idx].type == JSMN_STRING)
            && (tokens[idx].size == 1)
            && (3 == (tokens[idx].end - tokens[idx].start))
            && (!strncmp("cid",payload_data+tokens[idx].start, 3)) ) {

            LOTRACE_DBG("get_CorrelationId: FOUND at TK[%d]", idx);

            // Get next. Must be a primitive value (implicit, it is an integer)
            idx++;
            if ( (tokens[idx].type == JSMN_PRIMITIVE) && (tokens[idx].size == 0)) {
                int ret = getValueINT32(pCid, payload_data, &tokens[idx]);
                return ret;
            }
            LOTRACE_WARN("get_CorrelationId: Unexpected VALUE token TK[%d] type=%d %s size=%d",
                        idx, tokens[idx].type, conv_jsmntypeToString(tokens[idx].type), tokens[idx].size);
            return -1;
        }
    }
    return -1;
}

//---------------------------------------------------------------------------------
//
static int updateCnfParam(
        const char* payload_json, const jsmntok_t* token,
        const LiveObjectsD_Param_t* param_ptr,
        LiveObjectsD_CallbackParams_t cfgCB)
{
    int ret ;
    if ((payload_json == NULL) || (token == NULL) || (param_ptr == NULL)) {
        LOTRACE_ERR("updateCnfParam: Invalid parameters - payload=x%p token=x%p param_ptr=x%p", payload_json, token, param_ptr);
        return -1;
    }

    if (param_ptr->parm_data.data_type == LOD_TYPE_STRING_C) {
        if (token->type != JSMN_STRING) {
            LOTRACE_ERR("updateCnfParam:  bad token type  %d != %d (STRING)", token->type, JSMN_STRING);
            return -1;
        }
        ret = cfgCB(param_ptr, (const void*) (payload_json+token->start), token->end - token->start);
    }
    else {
        if (token->type != JSMN_PRIMITIVE) {
            LOTRACE_ERR("updateCnfParam (%s): bad token type %d != %d (PRIMITIVE) ", param_ptr->parm_data.data_name, token->type, JSMN_PRIMITIVE);
            return -1;
        }

        if (param_ptr->parm_data.data_type == LOD_TYPE_UINT32) {
            uint32_t value;
            ret = getValueUINT32(&value, payload_json, token);
            if ((ret == 0)  &&  (param_ptr->parm_data.data_value)) {
                ret = cfgCB(param_ptr, (const void*) &value, sizeof(uint32_t));
                if (ret == 0)
                    *((uint32_t*)param_ptr->parm_data.data_value) = value;
            }
        }
        else if (param_ptr->parm_data.data_type == LOD_TYPE_INT32) {
            int32_t value;
            ret = getValueINT32(&value, payload_json, token);
            if ((ret == 0)  &&  (param_ptr->parm_data.data_value)) {
                ret = cfgCB(param_ptr, (const void*) &value, sizeof(int32_t));
                if (ret == 0)
                    *((int32_t*)param_ptr->parm_data.data_value) = value;
            }
        }
        else if (param_ptr->parm_data.data_type == LOD_TYPE_FLOAT) {
            float value;
            ret = getValueFLOAT(&value, payload_json, token);
            if ((ret == 0)  &&  (param_ptr->parm_data.data_value)) {
                ret = cfgCB(param_ptr, (const void*) &value, sizeof(float));
                if (ret == 0)
                    *((float*)param_ptr->parm_data.data_value) = value;
            }
        }
        else if (param_ptr->parm_data.data_type == LOD_TYPE_DOUBLE) {
            double value;
            ret = getValueDOUBLE(&value, payload_json, token);
            if ((ret == 0)  &&  (param_ptr->parm_data.data_value)) {
                ret = cfgCB(param_ptr, (const void*) &value, sizeof(double));
                if (ret == 0)
                    *((double*)param_ptr->parm_data.data_value) = value;
            }
        }
        else {
            LOTRACE_ERR("updateCnfParam (%s): unsupported type %d ", param_ptr->parm_data.data_name, param_ptr->parm_data.data_type);
            ret = -1;
        }
    }
    return ret;
}

//---------------------------------------------------------------------------------
//
#if (MSG_DUMP)
static void dump_json_msg(
        const char*      from,
        const char*      payload_data,
        const jsmntok_t* tokens,
        int32_t          token_cnt)
{
    int idx;
    int len;
    LOTRACE_DBG("%s: %"PRIi32" tokens", from, token_cnt);
    for (idx=0; idx < token_cnt; idx++) {
        len = tokens[idx].end - tokens[idx].start;
        LOTRACE_DBG("TK[%d] type=%d %s size=%d start=%d end=%d (len=%d)",
                idx, tokens[idx].type, conv_jsmntypeToString(tokens[idx].type), tokens[idx].size,
                tokens[idx].start, tokens[idx].end, len);
        if (len > 0) LOTRACE_DBG("TK[%d]  ---> [%.*s]", idx, len, payload_data + tokens[idx].start);
    }
}
#endif


//---------------------------------------------------------------------------------
//
static int get_md5FromString( const unsigned char *s, unsigned char *buf_ptr,  uint32_t buf_len )
{
    uint32_t i, j, k;
    if ((s == NULL) || (buf_ptr == NULL) || (buf_len == 0)) {
        LOTRACE_ERR("get_md5FromString: Invalid parameters, s=x%p buf_ptr=x%p buf_len=%"PRIu32,
                s, buf_ptr, buf_len);
         return -1;
    }
    memset( buf_ptr, 0, buf_len );
    for( i = 0; i < buf_len * 2; i++, s++ ) {
        if( *s >= '0' && *s <= '9' ) j = *s - '0'; else
        if( *s >= 'A' && *s <= 'F' ) j = *s - '7'; else
        if( *s >= 'a' && *s <= 'f' ) j = *s - 'W'; else // 'a' (97) - 10 =
            return -1 ;

        k = ( ( i & 1 ) != 0 ) ? j : j << 4;
        buf_ptr[i >> 1] = (unsigned char)( buf_ptr[i >> 1] | k );
    }
    return( 0 );
}


//---------------------------------------------------------------------------------
// Decode a received JSON message to download resource
//
LiveObjectsD_ResourceRespCode_t LO_msg_decode_rsc_req(
        const char* payload_data, uint32_t payload_len,
        const LOMSetOfResources_t* pSetRsc,
        LOMSetOfUpdatedResource_t* pRscUpd,
        int32_t* pCid)
{
    int ret;
    int token_cnt;
    jsmn_parser parser;
    jsmntok_t   tokens[20];
    int idx;
    int len;
    int size;

    if ( (pSetRsc == NULL) || (payload_data == NULL) || (payload_len == 0) || (pRscUpd == NULL) || (pCid == NULL) ) {
        LOTRACE_ERR("decode_rsc: Invalid parameters, pSetCfg=x%p payload_data=x%p (%"PRIu32")",
                pSetRsc, payload_data, payload_len);
        return RSC_RSP_ERR_INTERNAL_ERROR;
    }

    *pCid = 0;

    memset(&tokens, 0, sizeof(tokens));
    jsmn_init(&parser);
    token_cnt = jsmn_parse(&parser, payload_data, payload_len, tokens, 20);
    if (token_cnt < 0) {
        LOTRACE_ERR("decode_rsc: ERROR %d returned by jsmn_parse", token_cnt);
        LOTRACE_ERR("decode_rsc: '%s'", payload_data);
        return RSC_RSP_ERR_INTERNAL_ERROR;
    }
    if (token_cnt == 0) {
        LOTRACE_ERR("decode_cfg: EMPTY !!!");
        return RSC_RSP_OK;
    }

#if (MSG_DUMP)
    dump_json_msg("decode_rsc", payload_data, tokens, token_cnt);
#endif

    if (token_cnt < 1)  {
        LOTRACE_ERR("decode_rsc: Bad format - token_cnt=%d < 1 too short !!", token_cnt);
        return RSC_RSP_ERR_INTERNAL_ERROR;
    }

    if ((tokens[0].type != JSMN_OBJECT) || (tokens[0].size <= 0)) {
        LOTRACE_ERR("decode_rsc: unexpected  first token - type=%d size=%d", tokens[0].type, tokens[0].size);
        return RSC_RSP_ERR_INTERNAL_ERROR;
    }

    // Get the Correlation Id
    ret = get_CorrelationId(pCid, payload_data, &tokens[1], token_cnt);
    if (ret) {
        LOTRACE_ERR("decode_rsc: Error to get the correlation id");
        return RSC_RSP_ERR_INTERNAL_ERROR;
    }
    LOTRACE_DBG("decode_rsc: cid= %"PRIi32, *pCid);

    if (pRscUpd->ursc_cid) {
        LOTRACE_ERR("decode_rsc: Error - Busy with cid=%"PRIi32, pRscUpd->ursc_cid);
        return RSC_RSP_ERR_NOT_AUTHORIZED; // RSC_RSP_ERR_BUSY
    }

    memset(pRscUpd,0,sizeof(LOMSetOfUpdatedResource_t));

    pRscUpd->ursc_cid = *pCid;

    // get resource id
    for (idx=0; idx < (token_cnt-1); idx++) {
        if ( (tokens[idx].type == JSMN_STRING)
            && (tokens[idx].size == 1)
            && (2 == (tokens[idx].end - tokens[idx].start))
            && (!strncmp("id",payload_data+tokens[idx].start, 2)) ) {

            LOTRACE_DBG("TK[%d]: Found JSON TAG %.*s", idx, tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start);

            // Get next. Must be a string value
            idx++;
            if ( (tokens[idx].type != JSMN_STRING) || (tokens[idx].size != 0)) {
                LOTRACE_ERR("decode_rsc: Unexpected VALUE token TK[%d] type=%d %s size=%d",
                            idx, tokens[idx].type, conv_jsmntypeToString(tokens[idx].type), tokens[idx].size);
                return RSC_RSP_ERR_INTERNAL_ERROR;
            }
            // found
            int jw;
            const LiveObjectsD_Resource_t* rsc_ptr = pSetRsc->rsc_ptr;
            len = tokens[idx].end - tokens[idx].start;
            for (jw=0;jw < pSetRsc->rsc_nb; jw++, rsc_ptr++) {
                if ((len == (int)strlen(rsc_ptr->rsc_name)) && (!strncmp(rsc_ptr->rsc_name, payload_data + tokens[idx].start, len))) {
                    LOTRACE_DBG("decode_rsc: Resource %.*s attached", tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start);
                    pRscUpd->ursc_obj_ptr = rsc_ptr;
                    break;
                }
            }
            if (pRscUpd->ursc_obj_ptr == NULL)
                LOTRACE_ERR("decode_rsc: Resource %.*s unknown", tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start);
            break;
        }
    }
    if (pRscUpd->ursc_obj_ptr == NULL) {
        if (idx == token_cnt) LOTRACE_WARN("decode_rsc: Json tag \"id\" not found");
        return RSC_RSP_ERR_INVALID_RESOURCE;
    }

    // Now, get each  parameter
    size = tokens[0].size;
    idx = 1;

    while ((size > 0) && (token_cnt > 0)) {
        int8_t   val_type;
        char*    val_ptr;
        uint32_t val_len;
        int len = tokens[idx].end - tokens[idx].start;
        if ((tokens[idx].type != JSMN_STRING)  || (tokens[idx].size != 1)) {
            // error;
            LOTRACE_ERR("decode_rsc: ERROR TK[%d] type=%d %s size=%d", idx, tokens[idx].type, conv_jsmntypeToString(tokens[idx].type), tokens[idx].size);
            return RSC_RSP_ERR_INTERNAL_ERROR;
        }
        size--;

        if ((len == 1) && !strncmp("m", payload_data + tokens[idx].start, len)) {
            if ((tokens[idx+1].type != JSMN_OBJECT)  || (tokens[idx+1].size < 3)) {
                LOTRACE_ERR("decode_rsc: TK[%d] METADATA - unexpected token after \"m\" - type=%d size=%d", idx+1, tokens[idx+1].type, tokens[idx+1].size);
                return RSC_RSP_ERR_INTERNAL_ERROR;
            }
            int ms = tokens[idx+1].size;
            LOTRACE_DBG("decode_rsc: TK[%d] --- METADATA - %d elements ...", idx, ms);

            idx += 2;
            token_cnt -= 2;
            while (ms > 0) {
                if ((tokens[idx].type != JSMN_STRING)  || (tokens[idx].size != 1)
                        || (tokens[idx+1].type != JSMN_STRING)  ||  (tokens[idx+1].size != 0)) {
                    LOTRACE_ERR("decode_rsc: ERROR TK[%d] in metadata section", idx);
                    return RSC_RSP_ERR_INTERNAL_ERROR;
                }
                len = tokens[idx].end - tokens[idx].start;
                ms--;
                val_type = 0;
                if ((len == 4) && !strncmp("size", payload_data + tokens[idx].start, len)) {
                    val_type = 3;
                    val_ptr = (char*)&pRscUpd->ursc_size;
                    val_len = 0;
                }
                else if ((len == 3) && !strncmp("uri", payload_data + tokens[idx].start, len)) {
                    val_type = 2;
                    val_ptr = pRscUpd->ursc_uri;
                    val_len = sizeof(pRscUpd->ursc_uri) - 1;
                }
                else if ((len == 3) && !strncmp("md5", payload_data + tokens[idx].start, len)) {
                    val_type = 4;
                    val_ptr = pRscUpd->ursc_md5;
                    val_len = sizeof(pRscUpd->ursc_md5);
                }
                else  {
                    LOTRACE_WARN("decode_rsc: TK[%d] %.*s - unknown field in metadata section", idx, tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start);
                }


                if (val_type) {
                    LOTRACE_DBG("decode_rsc: TK[%d] %.*s - %.*s", idx,
                            tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start,
                            tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start);
                    if (val_ptr) {
                        if (val_type == 2) {
                            len = tokens[idx+1].end - tokens[idx+1].start;
                            if (len > val_len) {
                                len = val_len;
                            }
                            strncpy(val_ptr, payload_data + tokens[idx+1].start, len);
                            val_ptr[len] = 0;
                        }
                        else if (val_type == 3) {
                            if ( 1 != sscanf(payload_data + tokens[idx+1].start, "%"PRIu32, (uint32_t*)val_ptr) ) {
                                LOTRACE_ERR("decode_rsc: TK[%d] %.*s , bad value", idx+1, tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start);
                                return RSC_RSP_ERR_INTERNAL_ERROR;
                            }
                        }
                        else if (val_type == 4) {
                            if ((tokens[idx+1].end - tokens[idx+1].start) == (val_len*2)) {
                                if (get_md5FromString((const unsigned char*)(payload_data + tokens[idx+1].start), (unsigned char*)val_ptr, val_len)) {
                                    LOTRACE_ERR("decode_rsc: TK[%d] mdq5= %.*s , bad value", idx+1, tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start);
                                    //return 2;
                                }
                            }
                            else {
                                LOTRACE_ERR("decode_rsc: TK[%d] mdq5= %.*s, bad length %d", idx+1,
                                        tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start,
                                        tokens[idx+1].end - tokens[idx+1].start);
                                //return 2;
                            }
                        }
                        else {
                            LOTRACE_ERR("decode_rsc: TK[%d] %.*s , bad type", idx+1, tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start);
                            return RSC_RSP_ERR_INTERNAL_ERROR;
                        }
                    }
                }
                idx +=2;
                token_cnt -= 2;
            }
        }
        else {
            if ((tokens[idx].type != JSMN_STRING)  || (tokens[idx].size != 1)
                    ||  (tokens[idx+1].size != 0)
                    || ((tokens[idx+1].type != JSMN_STRING) && (tokens[idx+1].type != JSMN_PRIMITIVE))) {
                LOTRACE_ERR("decode_rsc: ERROR TK[%d] in main section", idx);
                return RSC_RSP_ERR_INTERNAL_ERROR;
            }

            val_type = 0;
            if ((len == 2) && !strncmp("id", payload_data + tokens[idx].start, len)) {
                // skip, already processed
                val_type = 1;
            }
            else if ((len == 3) && !strncmp("old", payload_data + tokens[idx].start, len)) {
                val_type = 2;
                val_ptr = pRscUpd->ursc_vers_old;
                val_len = sizeof(pRscUpd->ursc_vers_old) - 1;
            }
            else if ((len == 3) && !strncmp("new", payload_data + tokens[idx].start, len)) {
                val_type = 2;
                val_ptr = pRscUpd->ursc_vers_new;
                val_len = sizeof(pRscUpd->ursc_vers_new) - 1;
            }
            else if ((len == 3) && !strncmp("cid", payload_data + tokens[idx].start, len)) {
                // skip, already processed
                val_type = 1;
            }
            else {
                // error;
                LOTRACE_WARN("decode_rsc: TK[%d] %.*s - unknown field in core section", idx, tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start);
            }
            if (val_type) {
                LOTRACE_DBG("decode_rsc: TK[%d] %.*s - %.*s", idx,
                        tokens[idx].end - tokens[idx].start, payload_data + tokens[idx].start,
                        tokens[idx+1].end - tokens[idx+1].start, payload_data + tokens[idx+1].start);
                if ((val_type == 2) && (val_ptr)) {
                    int len = tokens[idx+1].end - tokens[idx+1].start;
                    if (len > val_len) {
                        len = val_len;
                    }
                    strncpy(val_ptr, payload_data + tokens[idx+1].start, len);
                    val_ptr[len] = 0;
                }
            }
            idx +=2;
            token_cnt -= 2;
        }
    }



    if (pSetRsc->rsc_cb_ntfy) { // User callback function
        LiveObjectsD_ResourceRespCode_t rsc_resp_code;
        rsc_resp_code = pSetRsc->rsc_cb_ntfy(0, pRscUpd->ursc_obj_ptr, pRscUpd->ursc_vers_old, pRscUpd->ursc_vers_new, pRscUpd->ursc_size);
        if (rsc_resp_code) { // Refused by user
            pRscUpd->ursc_cid = 0;
            pRscUpd->ursc_obj_ptr = NULL;
            return rsc_resp_code;
        }
    }

    LOTRACE_INF("decode_rsc: md5= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             pRscUpd->ursc_md5[0],  pRscUpd->ursc_md5[1],  pRscUpd->ursc_md5[2],  pRscUpd->ursc_md5[3] ,  pRscUpd->ursc_md5[4],  pRscUpd->ursc_md5[5],  pRscUpd->ursc_md5[6],  pRscUpd->ursc_md5[7],
             pRscUpd->ursc_md5[8],  pRscUpd->ursc_md5[9],  pRscUpd->ursc_md5[10],  pRscUpd->ursc_md5[11] ,  pRscUpd->ursc_md5[12],  pRscUpd->ursc_md5[13],  pRscUpd->ursc_md5[14],  pRscUpd->ursc_md5[15]);

    pRscUpd->ursc_connected = 0;
    pRscUpd->ursc_offset =  0;

    return RSC_RSP_OK; // OK
}

//---------------------------------------------------------------------------------
// Decode a received JSON message to update configuration parameters
//
int LO_msg_decode_params_req(
        const char* payload_data, uint32_t payload_len,
        const LOMSetOfParams_t*  pSetCfg,
        LOMSetofUpdatedParams_t* pSetCfgUpdate )
{
    int ret;
    int token_cnt;
    jsmn_parser parser;
    jsmntok_t   tokens[25];
    int idx;
    int size;
    const char* pc;
    int len;

    if ( (pSetCfg == NULL) || (payload_data == NULL) || (payload_len == 0) || (pSetCfgUpdate == NULL) ) {
        LOTRACE_ERR("decode_cfg: Invalid parameters, pSetCfg=x%p payload_data=x%p (%"PRIu32") pSetCfgUpdate=x%p",
                pSetCfg, payload_data, payload_len, pSetCfgUpdate);
        return -1;
    }

    pSetCfgUpdate->cid = 0;
    pSetCfgUpdate->nb_of_params = 0;

    memset(&tokens, 0, sizeof(tokens));
    jsmn_init(&parser);
    token_cnt = jsmn_parse(&parser, payload_data, payload_len, tokens, 25);
    if (token_cnt < 0) {
        LOTRACE_ERR("decode_cfg: ERROR %d returned by jsmn_parse", token_cnt);
        LOTRACE_ERR("decode_cfg: '%s'", payload_data);
        return -1;
    }
    if (token_cnt == 0) {
        LOTRACE_ERR("decode_cfg: EMPTY !!!");
        return 0;
    }

#if (MSG_DUMP)
    dump_json_msg("decode_cfg", payload_data, tokens, token_cnt);
#endif

    if (token_cnt < 2)  {
        LOTRACE_ERR("decode_cfg: Bad format - token_cnt=%d < 2 too short !!", token_cnt);
        return -1;
    }

    if ( (tokens[0].type != JSMN_OBJECT) || (tokens[0].size <= 0) ) {
        LOTRACE_ERR("decode_cfg: Bad format - %d [0]=(%d,%d)", token_cnt, tokens[0].type, tokens[0].size);
        return -1;
    }

    // Get the Correlation Id
    ret = get_CorrelationId(&pSetCfgUpdate->cid, payload_data, &tokens[1], token_cnt);
    if (ret) {
        LOTRACE_ERR("decode_cfg: Error to get the correlation id");
        return -1;
    }

    if ( (tokens[1].type != JSMN_STRING) || (tokens[1].size != 1)             // should be 'cfg'
            || (tokens[2].type != JSMN_OBJECT) || (tokens[2].size < 0) )    // should be {
    {
        LOTRACE_ERR("decode_cfg: Bad header format - [1]=(%d,%d) [2]=(%d,%d)" ,
                tokens[1].type, tokens[1].size, tokens[2].type, tokens[2].size);
        return -1;
    }

    ret = check_token(payload_data,  &tokens[1], "cfg");
    if (ret <= 0) {
        LOTRACE_ERR("decode_cfg: Bad format, expected 'cfg'");
        return -1;
    }
    // skip the first tokens '{ "cfg" : {'
    idx = 3;
    token_cnt -= 3;

    // Get the number of parameters
    size = tokens[2].size;
    LOTRACE_DBG("decode_cfg:  %d parameters (token_cnt=%d) ...", size, token_cnt);

    // Now, get each configuration parameter
    while (size > 0) {
        if ( (token_cnt < 6)
                || (tokens[idx].type != JSMN_STRING)   // 0: should be the Parameter Name
                || (tokens[idx+1].type != JSMN_OBJECT) // 1: should be {
                || (tokens[idx+2].type != JSMN_STRING) // 2: Should be equal to "t"
                || (tokens[idx+3].type != JSMN_STRING) // 3: Should be the parameter type : "u32" , "u16", ...
                || (tokens[idx+4].type != JSMN_STRING) // 4: Should be equal to "v"
                                                       // 5: Value : either JSMN_PRIMITIVE or JSMN_STRING
                || !((tokens[idx+5].type == JSMN_PRIMITIVE)  || (tokens[idx+5].type == JSMN_STRING))
            ) {
            LOTRACE_ERR("decode_cfg: Bad param format, at idx=%d (param[%d] token_cnt=%d)", idx, tokens[2].size-size, token_cnt);
            return -2;
        }

        ret = check_token(payload_data,  &tokens[idx+2], "t");
        if (ret <= 0) {
            LOTRACE_ERR("decode_cfg: Bad param format at idx=%d - expected 't'", idx+2);
            return -2;
        }

        ret = check_token(payload_data,  &tokens[idx+4], "v");
        if (ret <= 0) {
            LOTRACE_WARN("decode_cfg: Bad param format at idx=%d - expected 'v'", idx+4);
            return -2;
        }

        // Parameter Name
        len = tokens[idx].end - tokens[idx].start;
        pc = payload_data + tokens[idx].start;

#if (MSG_DBG > 1)
        if (len > 0) printf("   *** param name = %.*s\r\n", len, pc);
#endif

        if (pSetCfg->param_set.param_nb) {
            int i;
            const LiveObjectsD_Param_t* param_ptr = pSetCfg->param_set.param_ptr;
            for (i=0; i < pSetCfg->param_set.param_nb; i++, param_ptr++) {
                int param_name_len = strlen(param_ptr->parm_data.data_name);
                if ((len == param_name_len) && (!strncmp(pc, param_ptr->parm_data.data_name, param_name_len))) {
                    // Config Parameter Name is found in the user list
                    // Get the type of this config parameter
                    LiveObjectsD_Type_t type = LO_getDataTypeFromStrL(payload_data + tokens[idx+3].start, tokens[idx+3].end - tokens[idx+3].start);
                    if (type == LOD_TYPE_UNKNOWN) {
                        LOTRACE_WARN("LOM_msg_decode_cfg: param %s - Unknown received type", param_ptr->parm_data.data_name);
                    }
                    else if (type != param_ptr->parm_data.data_type) {
                        LOTRACE_WARN("decode_cfg: param %s - bad type - received %d != expected %d",
                                param_ptr->parm_data.data_name, type, param_ptr->parm_data.data_type);
                    }
                    else if ((type ==  LOD_TYPE_STRING_C) && (tokens[idx+5].type != JSMN_STRING)) {
                        LOTRACE_WARN("decode_cfg: param %s - string type with unexpected jsmntype %d != %d",
                                param_ptr->parm_data.data_name, tokens[idx+5].type, JSMN_STRING);
                    }
                    else  {
#if (MSG_DBG > 1)
                        printf("   *** param value = %.*s\r\n", tokens[idx+5].end - tokens[idx+5].start, payload_data + tokens[idx+5].start);
#endif
                        ret = updateCnfParam(payload_data, &tokens[idx+5], param_ptr, pSetCfg->param_callback);

                        if (pSetCfgUpdate->nb_of_params < LOC_MAX_OF_COMMAND_ARGS) {
                            pSetCfgUpdate->tab_of_param_ptr[pSetCfgUpdate->nb_of_params++] = param_ptr;
                        }
                    }
                    break;
                }
            }
        }
        size--;
        token_cnt -= 6;
        idx += 6;
    }

    return 0;
}

//---------------------------------------------------------------------------------
//
//
int LO_msg_decode_cmd_req(
        const char* payload_data, uint32_t payload_len,
        const LOMSetofCommands_t* pSetCmd,
        int32_t* pCid )
{
    int ret;
    int token_cnt;
    jsmn_parser parser;
    jsmntok_t   tokens[20];
    int idx;
    int size;
    const LiveObjectsD_Command_t*  cmd_ptr;

    if ( (pSetCmd == NULL) || (payload_data == NULL) || (pCid == NULL) ) {
        LOTRACE_ERR("decode_cmd: Invalid parameters, pSetCmd=x%p payload_data=x%p pCid=x%p", pSetCmd, payload_data, pCid);
        return -1;
    }

    *pCid = 0;

    memset(&tokens, 0, sizeof(tokens));
    jsmn_init(&parser);
    token_cnt = jsmn_parse(&parser, payload_data, payload_len, tokens, 20);
    if (token_cnt < 0) {
        LOTRACE_ERR("decode_cmd: ERROR %d returned by jsmn_parse", token_cnt);
        LOTRACE_ERR("decode_cmd: '%.*s'", (int)payload_len, payload_data);
        return -1;
    }
    if (token_cnt == 0) {
        LOTRACE_WARN("decode_cmd: EMPTY !!!");
        return 0;
    }

#if (MSG_DUMP)
    dump_json_msg("decode_cmd", payload_data, tokens, token_cnt);
#endif

    if (token_cnt < 5) {
        LOTRACE_ERR("decode_cmd: Bad format - token_cnt=%d < 5 too short !! ", token_cnt);
        return -1;
    }

    if ( (tokens[0].type != JSMN_OBJECT) || (tokens[0].size <= 0)  ) {
        LOTRACE_ERR("decode_cmd: Bad format: Empty !!  %d [0]=(%d,%d)",
                token_cnt, tokens[0].type, tokens[0].size);
        return -1;
    }

    // Get the Correlation Id.
    ret = get_CorrelationId(pCid, payload_data, &tokens[1], token_cnt - 1);
    if (ret) {
        LOTRACE_ERR("decode_cmd: Error to get the correlation id (cid)");
        return -1;
    }

    // Now, Check the first tokens
    // Note: suppose that token[1]= "req" and token[3]= "arg", and so cid at the end !!
    if ( (tokens[0].type != JSMN_OBJECT) || (tokens[0].size < 3) // at least 3 items : "req", "arg" and "cid"
            || (tokens[1].type != JSMN_STRING)  || (tokens[1].size != 1) // expected : "req"
            || (tokens[2].type != JSMN_STRING)  || (tokens[2].size != 0) // expected : name of request
            ) {
        LOTRACE_ERR("decode_cmd: Bad format (cid=%"PRIi32") - %d [0]=(%d,%d) [1]=(%d,%d) [2]=(%d,%d)", *pCid,
                token_cnt,
                tokens[0].type, tokens[0].size,
                tokens[1].type, tokens[1].size,
                tokens[2].type, tokens[2].size);
        //pCid = 0; // set cid=0 => no response, otherwise LiveObjects platform will send again this malformed command !!
        return -2;
    }

    ret = check_token(payload_data,  &tokens[1], "req");
    if (ret <= 0) {
        LOTRACE_ERR("decode_cmd: Bad format (cid=%"PRIi32") - expected=req", *pCid);
        return -2;
    }

    // Is it registered by user ?
    cmd_ptr = NULL;
    size = tokens[2].end - tokens[2].start;
    LOTRACE_INF("decode_cmd: command \"%.*s\"  (NumberOfCommands=%d) ..", size, payload_data+tokens[2].start, pSetCmd->cmd_nb);
    for(idx=0; idx < pSetCmd->cmd_nb; idx++) {
        LOTRACE_DBG("   [%d] %s ?", idx, pSetCmd->cmd_ptr[idx].cmd_name);
        if ((size == (int)strlen(pSetCmd->cmd_ptr[idx].cmd_name))
                && !strncmp (pSetCmd->cmd_ptr[idx].cmd_name, payload_data+tokens[2].start, size)) {
            cmd_ptr = &pSetCmd->cmd_ptr[idx];
            break;
        }
    }
    if (cmd_ptr == NULL) { // not found in the set of commands
        LOTRACE_ERR("decode_cmd: cid=%"PRIi32" - command \"%.*s\" not registered ", *pCid, size, payload_data+tokens[2].start);
        return -3;
    }
    if (pSetCmd->cmd_callback == NULL) { // No callback function !!!
        LOTRACE_ERR("decode_cmd: cid=%"PRIi32" - command \"%.*s\" - No function to process command", *pCid, size, payload_data+tokens[2].start);
        return -4;
    }
    // Check the second token :  "arg" : { ... }
    // TODO: position of 'arg' should be anywhere. (after or before 'cid')
    if ( (tokens[3].type != JSMN_STRING)  || (tokens[3].size != 1) // expected : "arg"
            || (tokens[4].type != JSMN_OBJECT)  // expected :  ': {'
            ) {
        LOTRACE_ERR("decode_cmd: Bad format - [3]=(%d,%d) [4]=(%d,%d)",
                tokens[3].type, tokens[3].size,
                tokens[4].type, tokens[4].size);
        return -2;
    }
    ret = check_token(payload_data,  &tokens[3], "arg");
    if (ret <= 0) {
        LOTRACE_ERR("decode_cmd: Bad format - \"arg\" was expected");
        return -2;
    }

    // Get the number of arguments
    size = tokens[4].size;

    LOTRACE_DBG("decode_cmd: cid=%"PRIi32" - command \"%.*s\" with %d parameters ...", *pCid, tokens[2].end - tokens[2].start, payload_data+tokens[2].start, size);

    // Now, get each argument. Support only simple type - "name" : string or primitive value
    idx = 5;
    token_cnt -= 5;
    if ( size > 0) {
        char* pm;
        LiveObjectsD_CommandRequestBlock_t* pReqBlkWithArgs;
        LiveObjectsD_CommandArg_t*    pArgs;
        char*            pLine;

        int len = sizeof(LiveObjectsD_CommandRequestBlock_t)
                + (size-1)*sizeof(LiveObjectsD_CommandArg_t)
                + tokens[idx+(size*2)+1].end - tokens[idx].start + 1;
        pm = (char*)malloc(len);
        if (pm == NULL) {
            LOTRACE_ERR("decode_cmd: nb_params=%d args_sz=%d - MEM_ALLOC ERROR, len=%d", size, tokens[idx+(size*2)+1].end - tokens[idx].start, len);
            return -6;
        }

        LOTRACE_WARN("decode_cmd: nb_params=%d args_sz=%d - MEM_ALLOC %p len=%d", size, tokens[idx+(size*2)+1].end - tokens[idx].start, pm, len);

        //memset(pm, 0, len);

        pReqBlkWithArgs = (LiveObjectsD_CommandRequestBlock_t*)pm;
        pArgs =  (LiveObjectsD_CommandArg_t*)pReqBlkWithArgs->args_array;
        pLine = (char*)(pm + sizeof(LiveObjectsD_CommandRequestBlock_t) + (size-1)*sizeof(LiveObjectsD_CommandArg_t));

        pReqBlkWithArgs->hd.cmd_blk_len = len;
        pReqBlkWithArgs->hd.cmd_ptr = cmd_ptr;
        pReqBlkWithArgs->hd.cmd_cid = *pCid;
        pReqBlkWithArgs->hd.cmd_args_nb = 0;

        while ((token_cnt >= 2) && (size > 0)) {
            if ( (tokens[idx].type != JSMN_STRING)
                    || (tokens[idx].size != 1)
                    || (tokens[idx+1].size != 0)
                    || ( (tokens[idx+1].type != JSMN_STRING) && (tokens[idx+1].type != JSMN_PRIMITIVE) )
                ) {
                LOTRACE_ERR("decode_cmd: format not supported for arg[%d]= (%d,%d):(%d,%d)",
                        idx, tokens[idx].type, tokens[idx].size, tokens[idx+1].type, tokens[idx+1].size );
                return -2;
            }
            LOTRACE_INF("decode_cmd: arg \"%.*s\" = (%s) %.*s",
                    tokens[idx].end-tokens[idx].start, payload_data+tokens[idx].start,
                    conv_jsmntypeToString(tokens[idx+1].type),
                    tokens[idx+1].end-tokens[idx+1].start, payload_data+tokens[idx+1].start);

            {
                pArgs->arg_name = pLine;
                memcpy(pLine, payload_data+tokens[idx].start, tokens[idx].end-tokens[idx].start);
                pLine +=  tokens[idx].end-tokens[idx].start;
                *pLine++ = 0;

                pArgs->arg_value = pLine;
                memcpy(pLine, payload_data+tokens[idx+1].start, tokens[idx+1].end-tokens[idx+1].start);
                pLine +=  tokens[idx+1].end-tokens[idx+1].start;
                *pLine++ = 0;

                pArgs->arg_type= (tokens[idx+1].type == JSMN_STRING) ? 1 : 0;

                pArgs++;
                pReqBlkWithArgs->hd.cmd_args_nb++;
            }
            size --;
            idx += 2;
            token_cnt -= 2;
        }

        if (size) {
            LOTRACE_ERR("decode_cmd:  bad JSON format - remain= %d != 0 - arg_nb=%d  token_cnt=%d", size, tokens[4].size, token_cnt);
            return -2;
        }

       //TODO: Must be fixed - How to pass arguments to user ?
#if (MSG_DBG > 1)
        {
            int i;
            LOTRACE_INF("decode_cmd: process command with %d args: ", pReqBlkWithArgs->hd.cmd_args_nb);
            for (i = 0; i < pReqBlkWithArgs->hd.cmd_args_nb; i++) {
                LOTRACE_INF("decode_cmd:  arg[%d] (%d)  %s %s", i,  pReqBlkWithArgs->args_array[i].arg_type,
                        pReqBlkWithArgs->args_array[i].arg_name, pReqBlkWithArgs->args_array[i].arg_value);
            }
        }
#endif

        ret = pSetCmd->cmd_callback(pReqBlkWithArgs);

        LOTRACE_WARN("decode_cmd: args - MEM_FREE %p",  pReqBlkWithArgs);

        free (pReqBlkWithArgs);
    }
    else {
        LiveObjectsD_CommandRequestHeader_t* pReqWithoutArg = (LiveObjectsD_CommandRequestHeader_t* ) malloc(sizeof(LiveObjectsD_CommandRequestHeader_t));
        if (pReqWithoutArg == NULL) {
            LOTRACE_ERR("decode_cmd: no arg - MEM_ALLOC ERROR, len=%d", sizeof(LiveObjectsD_CommandRequestHeader_t));
            return -6;
        }
        LOTRACE_WARN("decode_cmd: no arg - MEM_ALLOC %p len=%d",  pReqWithoutArg, sizeof(LiveObjectsD_CommandRequestHeader_t));

        pReqWithoutArg->cmd_blk_len = sizeof(LiveObjectsD_CommandRequestHeader_t);
        pReqWithoutArg->cmd_ptr = cmd_ptr;
        pReqWithoutArg->cmd_cid = *pCid;
        pReqWithoutArg->cmd_args_nb = 0;

        LOTRACE_INF("decode_cmd: process command with empty arg");
        ret = pSetCmd->cmd_callback((LiveObjectsD_CommandRequestBlock_t* )pReqWithoutArg);

        LOTRACE_WARN("decode_cmd: no arg - MEM_FREE %p len=%d",  pReqWithoutArg, sizeof(LiveObjectsD_CommandRequestHeader_t));
        free (pReqWithoutArg);
    }

    return ret;
}
