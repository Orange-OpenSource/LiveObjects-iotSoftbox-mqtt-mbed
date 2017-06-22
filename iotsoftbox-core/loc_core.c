/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  loc_core.c
  * @brief Implementation of LiveOject Client Interface
  */

#include "liveobjects_dev_params.h"

#include "paho-mqttclient-embedded-c/MQTTClient.h"


#include <stdio.h>
#include <string.h>

#include "liveobjects-client/LiveObjectsClient_Config.h"

#include "liveobjects-client/LiveObjectsClient_Core.h"
#include "liveobjects-client/LiveObjectsClient_Security.h"
#include "liveobjects-client/LiveObjectsClient_Toolbox.h"

#include "netw_wrapper.h"

#include "loc_json_api.h"
#include "loc_msg.h"
#include "loc_wget.h"

#include "loc_sys.h"

#include "liveobjects-sys/loc_trace.h"
#include "liveobjects-sys/LiveObjectsClient_Platform.h"

//---------------------------------------------------------------------------------
// Definitions
// -----------

#define LOC_MQTT_USER_NAME            "json+device"

#ifndef LOC_SERV_HOST_NAME
#define LOC_SERV_HOST_NAME           "liveobjects.orange-business.com"
#endif

#ifndef LOC_SERV_IP_ADDRESS
#define LOC_SERV_IP_ADDRESS           LOC_SERV_HOST_NAME
#endif

#ifndef LOC_SERV_PORT
#if SECURITY_ENABLED && LOC_FEATURE_MBEDTLS
#define LOC_SERV_PORT                  8883
#else
#define LOC_SERV_PORT                  1883
#endif
#endif


#ifndef LOC_CLIENT_DEV_ID
#define LOC_CLIENT_DEV_ID             "LomDev"
#endif

#ifndef LOC_CLIENT_DEV_NAME_SPACE
#define LOC_CLIENT_DEV_NAME_SPACE     "LomSK"
#endif

// Version of MQTT to be used : 4 = 3.1.1  (3 is for  3.1)
#define MQTTPacket_connectData_initializer { \
    {'M', 'Q', 'T', 'C'}, \
    0, 4, {NULL, {0, NULL}}, \
    60, 1, 0, \
    MQTTPacket_willOptions_initializer, \
    {NULL, {0, NULL}}, {NULL, {0, NULL}} \
    }


#define MTYPE_PUB_USR_MSG        0x11

#define MTYPE_PUB_STATUS         0x21
#define MTYPE_PUB_DATA           0x22
#define MTYPE_PUB_RSC            0x23
#define MTYPE_PUB_PARAM          0x24

#define MTYPE_PUB_CMD_RSP        0x27


//---------------------------------------------------------------------------------
// Type definitions
// ----------------

typedef struct {
    uint8_t        subscribed;
    char           topicName[LOC_MQTT_DEF_TOPIC_NAME_SZ];
    messageHandler callback;
} LOMTopicSub_t;


//---------------------------------------------------------------------------------
// Local variables
// ---------------

static char              _LOClient_dev_id[LOC_MQTT_DEF_DEV_ID_SZ] = LOC_CLIENT_DEV_ID;
static char              _LOClient_dev_name_space[LOC_MQTT_DEF_NAME_SPACE_SZ] = LOC_CLIENT_DEV_NAME_SPACE;

static Network           _LOClient_MQTTClient_network;

static volatile int8_t   _LOClient_state_run = 0;
static volatile uint8_t  _LOClient_state_connected  = 0;

static int8_t            _LOClient_cfg_first;

static MQTTClient        _LOClient_mqtt_ctx;

static unsigned char     _LOClient_mqtt_buffer_snd[LOC_MQTT_DEF_SND_SZ+10];
static unsigned char     _LOClient_mqtt_buffer_rcv[LOC_MQTT_DEF_RCV_SZ+10];

static struct {
    int iwrite;
    int iread;
    const char* msg[LOC_MQTT_DEF_PENDING_MSG_MAX];
} _LOClient_queue;


#if SECURITY_ENABLED

static LiveObjectsSecurityParams_t _LOClient_params_security = {
    { 0, SERVER_CERT },
    { 0, CLIENT_CERT },
    { 0, CLIENT_PKEY },
    SERVER_CERTIFICATE_COMMON_NAME,
    VERIFY_MODE
};

#endif

static LiveObjectsNetConnectParams_t _LOClient_params_connect = {
    LOC_SERV_IP_ADDRESS,
    LOC_SERV_PORT,
    LOC_SERV_TIMEOUT
};


#if LOC_FEATURE_LO_PARAMS
#define LOCC_NTFDEVCFGUDP  LOCC_ntfDevCfgUpd
static void LOCC_ntfDevCfgUpd(MessageData* msg);
#else
#define LOCC_NTFDEVCFGUDP  NULL
#endif


#if LOC_FEATURE_LO_COMMANDS
#define LOCC_NTFDEVCMD  LOCC_ntfDevCmd
static void LOCC_ntfDevCmd(MessageData* msg);
#else
#define LOCC_NTFDEVCMD    NULL
#endif

#if LOC_FEATURE_LO_RESOURCES
#define LOCC_NTFDEVRSCUDP  LOCC_ntfDevRscUpd
static void LOCC_ntfDevRscUpd(MessageData* msg);
#else
#define LOCC_NTFDEVRSCUDP  NULL
#endif


#define TOPIC_CFG_UPD  0
#define TOPIC_COMMAND  1
#define TOPIC_RSC_UPD  2

LOMTopicSub_t  _LOClient_TopicSub[3] = {
    { 0, "dev/cfg/upd", LOCC_NTFDEVCFGUDP },
    { 0, "dev/cmd",     LOCC_NTFDEVCMD },
    { 0, "dev/rsc/upd", LOCC_NTFDEVRSCUDP }
};

#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
static LOMSetOfStatus_t           _LOClient_Set_Status[LOC_MAX_OF_STATUS_SET];
#endif
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
static LOMSetOfData_t             _LOClient_Set_Data[LOC_MAX_OF_DATA_SET];
#endif
#if LOC_FEATURE_LO_PARAMS
static LOMSetOfParams_t           _LOClient_Set_Params;
static LOMSetofUpdatedParams_t    _LOClient_Set_UpdatedParams;
#endif
#if LOC_FEATURE_LO_COMMANDS
static LOMSetofCommands_t         _LOClient_Set_Cmd;
#endif
#if LOC_FEATURE_LO_RESOURCES
static LOMSetOfResources_t        _LOClient_Set_Rsc;
static LOMSetOfUpdatedResource_t  _LOClient_Set_UpdatedRsc;
#endif

static int LOCC_MqttPublish(enum QoS qos, const char* topic_name, const char* payload_data);

#if LOC_MQTT_DUMP_MSG

static uint16_t _LOClient_dump_mqtt_publish = 0;

//=================================================================================
// Private Functions

//---------------------------------------------------------------------------------
//
static void mqtt_dump_hex(const unsigned char* p_buf, int len)
{
    int i;
    for(i=0;i<len;i++) {
        LOTRACE_PRINTF("%02X ", p_buf[i]);
    }
    LOTRACE_PRINTF("\n");
}

//---------------------------------------------------------------------------------
//
static void mqtt_dump_msg(const unsigned char* p_buf)
{
    int i;
    const unsigned char* pc = p_buf;
    unsigned char digit;
    MQTTHeader header;
    int header_len = 1;
    int remain_len;
    int payload_len;
    int multiplier = 1;

    header.byte = *pc++;

    remain_len = 0;
    do {
        digit = *pc++;
        remain_len += (digit & 0x7f) * multiplier;
        multiplier *= 128;
        header_len++;
    } while ((digit&0x80) != 0);

    if (_LOClient_dump_mqtt_publish & 0x01) {
        LOTRACE_PRINTF("\n---\nHEADER  = %3d  x%02X ", header.byte , header.byte);
        LOTRACE_PRINTF(" (type= %d, qos= %d, dup= %d, retain = %d)\n",
                header.bits.type, header.bits.qos, header.bits.dup, header.bits.retain);
        LOTRACE_PRINTF("LEN     = %3d  x%04X (header_len=%d)\n", remain_len, remain_len, header_len);

        if (header.bits.type == PUBLISH) {
            int topic_len  = 256*(*pc) + (*(pc+1));
            pc += 2;

            LOTRACE_PRINTF("TOPIC(len=%2d): '", topic_len );
            for(i=0;i<topic_len;i++) {
                LOTRACE_PRINTF("%c", *pc++ );
            }
            LOTRACE_PRINTF("'\n");

            payload_len = remain_len - topic_len - 2;

            LOTRACE_PRINTF("PAYLOAD(%3d) : '",payload_len );
            for(i=0;i<payload_len;i++) {
                LOTRACE_PRINTF("%c", *pc++ );
            }
            LOTRACE_PRINTF("'\n");
        }
    }

    if (_LOClient_dump_mqtt_publish & 0x02) {
        remain_len += header_len;
        LOTRACE_PRINTF("MSG_LEN = %3d\n", remain_len);
        mqtt_dump_hex(p_buf, remain_len);
    }
}

#if (LOC_MQTT_DUMP_MSG & 0x02)
void LOCC_mqtt_dump_msg(const unsigned char* p_buf)
{
    if (_LOClient_dump_mqtt_publish & 0x08) {
        mqtt_dump_msg(p_buf);
    }
}
#endif

#endif // LOC_MQTT_DUMP_MSG

//=================================================================================
// Messages Queue
//---------------------------------------------------------------------------------
//
static int LOCC_mqInit(void)
{
    memset(&_LOClient_queue, 0, sizeof(_LOClient_queue));
    return 0;
}

//---------------------------------------------------------------------------------
//
static int LOCC_mqPut(const char* p_msg)
{
    int ret = -1;;
    //lock
    if (MQ_MUTEX_LOCK()) {
        LOTRACE_ERR("Error to lock mutex");
        return ret;
    }
    if (_LOClient_queue.msg[_LOClient_queue.iwrite] == NULL) {
        _LOClient_queue.msg[_LOClient_queue.iwrite] = p_msg;
        if (++_LOClient_queue.iwrite == LOC_MQTT_DEF_PENDING_MSG_MAX) _LOClient_queue.iwrite = 0;
        ret = 0;
    }
    else {
        //TODO: queue overflow -> release the oldest message ?
        ;
    }
    //unlock
    MQ_MUTEX_UNLOCK();
    return ret;
}

//---------------------------------------------------------------------------------
//
static const char* LOCC_mqGet()
{
    const char* p_msg = NULL;
    //lock
    if (MQ_MUTEX_LOCK()) {
        LOTRACE_ERR(" Error to lock mutex");
        return p_msg;
    }
    if (_LOClient_queue.iread != _LOClient_queue.iwrite)  {
        p_msg = _LOClient_queue.msg[_LOClient_queue.iread];
        _LOClient_queue.msg[_LOClient_queue.iread] = NULL;
        if (++_LOClient_queue.iread == LOC_MQTT_DEF_PENDING_MSG_MAX) _LOClient_queue.iread = 0;

    }
    //unlock
    MQ_MUTEX_UNLOCK();
    return p_msg;
}

//---------------------------------------------------------------------------------
//
static void LOCC_mqPurge(void)
{
    if (MQ_MUTEX_LOCK()) {
        LOTRACE_ERR(" Error to lock mutex");
        return;
    }
    while (_LOClient_queue.iread != _LOClient_queue.iwrite)  {
        const char* p_msg = _LOClient_queue.msg[_LOClient_queue.iread];
        if (p_msg) {
            LOTRACE_DBG("LOCC_mqPurge: MEM_FREE msg[%d]=%p x%x",_LOClient_queue.iread, p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
        else {
            LOTRACE_ERR("LOCC_mqPurge: msg[%d]=NULL !!!!",_LOClient_queue.iread);
        }
        _LOClient_queue.msg[_LOClient_queue.iread] = NULL;
        if (++_LOClient_queue.iread == LOC_MQTT_DEF_PENDING_MSG_MAX) _LOClient_queue.iread = 0;
    }
    _LOClient_queue.iread = _LOClient_queue.iwrite = 0;
    memset(_LOClient_queue.msg, 0, sizeof(_LOClient_queue.msg));
    MQ_MUTEX_UNLOCK();
}


//=================================================================================
// Callback functions called by MQTT (linked to subscribed topics)
//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_PARAMS
static void LOCC_ntfDevCfgUpd(MessageData* msg)
{
    int ret;
    LOTRACE_INF("topicName='%s' '%.*s'", msg->topicName->cstring, msg->topicName->lenstring.len,  msg->topicName->lenstring.data);
    LOTRACE_INF("msg: id=%d qos=%d '%.*s'", msg->message->id, msg->message->qos, msg->message->payloadlen, (const char*)msg->message->payload);

    ret = LO_msg_decode_params_req((const char*)msg->message->payload, msg->message->payloadlen,
            &_LOClient_Set_Params, &_LOClient_Set_UpdatedParams);
    if (ret) {
        LOTRACE_ERR("LO_msg_decode_params: failed, rc= %d",ret);
    }
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_RESOURCES
static void LOCC_ntfDevRscUpd(MessageData* msg)
{
    int ret;
    int32_t cid = 0;
    LOTRACE_INF("topicName='%s' '%.*s'", msg->topicName->cstring, msg->topicName->lenstring.len,  msg->topicName->lenstring.data);
    LOTRACE_INF("msg: id=%d qos=%d '%.*s'", msg->message->id, msg->message->qos, msg->message->payloadlen, (const char*)msg->message->payload);

    ret = LO_msg_decode_rsc_req((const char*)msg->message->payload, msg->message->payloadlen,
            &_LOClient_Set_Rsc, &_LOClient_Set_UpdatedRsc, &cid);
    if (cid == 0) {
        LOTRACE_ERR("LO_msg_decode_rsc: failed, NO CID !!  ret=%d", ret);
    }
    else {
        LOTRACE_DBG("LOCC_ntfDevRscUpd: publish rsc response, cid=%"PRIi32" with ret=%d ...", cid, ret);
        const char* pMsg = LO_msg_encode_rsc_result(cid, ret);
        if (pMsg) {
            LOCC_MqttPublish(QOS0, "dev/rsc/upd/res", pMsg);
        }
        else {
            LOTRACE_WARN("LOCC_ntfDevRscUpd: ERROR to build response, cid=%"PRIi32" with ret=%d", cid, ret);
        }
    }
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_COMMANDS
static void LOCC_ntfDevCmd(MessageData* msg)
{
    int ret;
    int32_t cid = 0;
    LOTRACE_INF("topicName='%s' '%.*s'", msg->topicName->cstring, msg->topicName->lenstring.len,  msg->topicName->lenstring.data);
    LOTRACE_INF("msg: id=%d qos=%d '%.*s'", msg->message->id, msg->message->qos, msg->message->payloadlen, (const char*)msg->message->payload);

    ret = LO_msg_decode_cmd_req((const char*)msg->message->payload, msg->message->payloadlen,
            &_LOClient_Set_Cmd, &cid);
    if (ret < 0) {
        LOTRACE_ERR("LO_msg_decode_cmd: failed, rc= %d, cid=%"PRIi32, ret, cid);
    }

    if ((cid) && (ret)) {
        // send immediately a command response
        LOTRACE_INF("Send command response cid=%"PRIi32" ret= %d", cid, ret);
        const char* pMsg = LO_msg_encode_cmd_result(cid, ret);
        if (pMsg) {
            LOCC_MqttPublish(QOS0, "dev/cmd/res", pMsg);
        }
    }
    else LOTRACE_WARN(" !!! DELAYED CMD RESPONSE (ret=%d) - cid=%"PRIi32, ret, cid);
}
#endif

//=================================================================================
//
//---------------------------------------------------------------------------------
//
#if SECURITY_ENABLED
static int LOCC_EnableTLS(void)
{
    int rc;
    rc = netw_setSecurity(&_LOClient_MQTTClient_network, &_LOClient_params_security);
    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
static int LOCC_MqttConnect(void)
{
    int ret;
    char mqtt_client_id[80];

    MQTTPacket_connectData connectData = MQTTPacket_connectData_initializer;

    LOTRACE_DBG("MQTT Connecting...");

    ret = snprintf(mqtt_client_id, sizeof(mqtt_client_id),"urn:lo:nsid:%s:%s",
            _LOClient_dev_name_space, _LOClient_dev_id);

    connectData.MQTTVersion = (unsigned char) (4);
    connectData.clientID.cstring = mqtt_client_id;
    connectData.username.cstring = LOC_MQTT_USER_NAME;
    connectData.password.cstring = LOC_CLIENT_DEV_API_KEY;

    //connectData.will.topicName.cstring = ...;
    //connectData.will.message.cstring = ...;
    //connectData.will.qos = ...;
    //connectData.will.retained = ...;

    connectData.keepAliveInterval = LOC_MQTT_API_KEEPALIVEINTERVAL_SEC;

    ret = MQTTConnect(&_LOClient_mqtt_ctx, &connectData);
    if (ret) {
        LOTRACE_ERR("MQTTConnect failed, rc= %d",ret);
        netw_disconnect(&_LOClient_MQTTClient_network, 1);
        return -1;
    }
    LOTRACE_INF("MQTT Connected : OK %d", ret);
    _LOClient_state_connected = 1;
    return 0;
}


//---------------------------------------------------------------------------------
//
static int LOCC_MqttPublish(enum QoS qos, const char* topic_name, const char* payload_data)
{
    int rc;
    MQTTMessage mqtt_msg;

    mqtt_msg.qos = qos;
    mqtt_msg.retained = 0;
    mqtt_msg.dup = 0;
    mqtt_msg.id = 0;
    mqtt_msg.payload = (void*)payload_data;
    mqtt_msg.payloadlen =  strlen(payload_data);

    LOTRACE_DBG("MQTTPublish len=%d ....", mqtt_msg.payloadlen);
    rc = MQTTPublish(&_LOClient_mqtt_ctx, topic_name, &mqtt_msg);
    if (rc) {
        LOTRACE_ERR("MQTTPublish failed, rc=%d", rc);
    }

#if (LOC_MQTT_DUMP_MSG & 0x01)
    if (_LOClient_dump_mqtt_publish & 0x04)
        mqtt_dump_msg(_LOClient_mqtt_buffer_snd);
#endif

    return rc;
}

//---------------------------------------------------------------------------------
//
static int LOCC_SubscibeTopic(int i)
{
    int rc;
    if ((i >= 0) && (i < 3)) {
        if (_LOClient_TopicSub[i].subscribed) {
            LOTRACE_ERR("Subscribe[%d] %s already done", i, _LOClient_TopicSub[i].topicName);
            return 0;
        }
        if (_LOClient_TopicSub[i].callback == NULL) {
            LOTRACE_ERR("Subscribe[%d] %s  - NO CALLBACK FUNCTION !!!", i, _LOClient_TopicSub[i].topicName);
            return 0;
        }
        LOTRACE_WARN("Subscribe[%d] %s , granted_qos=%d .... ", i, _LOClient_TopicSub[i].topicName, QOS0);
        rc = MQTTSubscribe(&_LOClient_mqtt_ctx, _LOClient_TopicSub[i].topicName, QOS0, _LOClient_TopicSub[i].callback);
        if (rc < 0)  {
            LOTRACE_ERR("Subscribe[%d] %s failed, rc=%d", i, _LOClient_TopicSub[i].topicName,  rc);
        }
        else if (rc == 0x80) {
            LOTRACE_ERR("Subscribe[%d] %s failed, rc=x%x", i, _LOClient_TopicSub[i].topicName,  rc);
        }
        else {
            LOTRACE_WARN("Subscribe[%d] %s , qos=%d (granted_qos=%d)", i, _LOClient_TopicSub[i].topicName,  rc, QOS0);
            _LOClient_TopicSub[i].subscribed = 1;
        }
    }
    else {
        LOTRACE_WARN("Subscribe[%d]: ERROR, bad number [0,2]", i);
    }
    return 0;
}
//---------------------------------------------------------------------------------
//
static int LOCC_UnsubscibeTopic(int i)
{
    int rc;
    if ((i >= 0) && (i < 3)) {
        if (!_LOClient_TopicSub[i].subscribed) {
            LOTRACE_ERR("Unsubscribe[%d] %s already done", i, _LOClient_TopicSub[i].topicName);
            return 0;
        }
        LOTRACE_WARN("Unsubscribe[%d] %s .... ", i, _LOClient_TopicSub[i].topicName);
        rc = MQTTUnsubscribe(&_LOClient_mqtt_ctx, _LOClient_TopicSub[i].topicName);
        if (rc == 0)  {
            LOTRACE_WARN("Unsubscribe[%d] %s", i, _LOClient_TopicSub[i].topicName);
                  _LOClient_TopicSub[i].subscribed = 0;
        }
        else {
            LOTRACE_ERR("Unsubscribe[%d] %s failed, rc=%d", i, _LOClient_TopicSub[i].topicName,  rc);
        }
    }
    else {
        LOTRACE_WARN("Unsubscribe[%d]: ERROR, bad number [0,2]", i);
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
static int LOCC_processStatus(uint8_t force)
{
    int rc = 0;
    int status_hdl;
    for (status_hdl=0; status_hdl < LOC_MAX_OF_STATUS_SET; status_hdl++) {
        LOMSetOfStatus_t* p_satusSet = &_LOClient_Set_Status[status_hdl];
        if ((p_satusSet->data_set.data_ptr) && (p_satusSet->data_set.data_nb)
                && ((force) || (p_satusSet->pushtoLOServer))) {
            const char* pMsg;
            LOTRACE_INF("LOCC_processStatus: force=%d  push=%d => PUBLISH STATUS ...", force , p_satusSet->pushtoLOServer);
            p_satusSet->pushtoLOServer = 1;
            pMsg = LO_msg_encode_status(0, &p_satusSet->data_set);
            if (pMsg) {
                rc = LOCC_MqttPublish(QOS0, "dev/info", pMsg);
                if (rc == 0) {
                    p_satusSet->pushtoLOServer = 0;
                }
            }
        }
    }
    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_RESOURCES

static int LOCC_processResources(uint8_t force)
{
    int rc = 0;
    if ((_LOClient_Set_Rsc.rsc_ptr)  && ((force) || (_LOClient_Set_Rsc.pushtoLOServer))) {
        const char* pMsg;
        LOTRACE_INF("LOCC_processResources: force=%d  push=%d => PUBLISH RESOURCES ...", force , _LOClient_Set_Rsc.pushtoLOServer);
        _LOClient_Set_Rsc.pushtoLOServer = 1;
        pMsg = LO_msg_encode_resources(0, &_LOClient_Set_Rsc);
        if (pMsg) {
            rc = LOCC_MqttPublish(QOS0, "dev/rsc", pMsg);
            if (rc == 0) {
                _LOClient_Set_Rsc.pushtoLOServer = 0;
            }
        }
    }
    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_RESOURCES
static int LOCC_processGetRsc(void)
{
    int rc = 0;
    if ((_LOClient_Set_UpdatedRsc.ursc_cid) && (_LOClient_Set_UpdatedRsc.ursc_obj_ptr)) {
        if (_LOClient_Set_Rsc.rsc_cb_data) {
            if (_LOClient_Set_UpdatedRsc.ursc_connected) {
                rc = _LOClient_Set_Rsc.rsc_cb_data(_LOClient_Set_UpdatedRsc.ursc_obj_ptr, _LOClient_Set_UpdatedRsc.ursc_offset);
                if (rc < 0) {
                    LOTRACE_INF("LOCC_processGetRsc: ERROR returned by User callback function");
                    rc = -1;
                }
                else if (rc == 0) {
                    LOTRACE_INF("LOCC_processGetRsc: 0 byte => ERROR !!! offset=%"PRIu32"/%"PRIu32, _LOClient_Set_UpdatedRsc.ursc_offset, _LOClient_Set_UpdatedRsc.ursc_size);
                    rc = -50;
                }

                if (_LOClient_Set_UpdatedRsc.ursc_offset == _LOClient_Set_UpdatedRsc.ursc_size) {
                    //
                    int i;
                    unsigned char output[16];
                    memset(output ,0, 16);
                    mbedtls_md5_finish( &_LOClient_Set_UpdatedRsc.md5_ctx,  output);

                    //TODO: Check md5 value with the value given by the LO server
                    for (i=0; i < sizeof(output); i++) {
                        if (output[i] != _LOClient_Set_UpdatedRsc.ursc_md5[i]) {
                            LOTRACE_INF("LOCC_processGetRsc:  Computed MD5  %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                    output[0], output[1], output[2], output[3] , output[4], output[5], output[6], output[7],
                                    output[8], output[9], output[10], output[11] , output[12], output[13], output[14], output[15]);
                            LOTRACE_INF("LOCC_processGetRsc: LO Server MD5  %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                    _LOClient_Set_UpdatedRsc.ursc_md5[0], _LOClient_Set_UpdatedRsc.ursc_md5[1], _LOClient_Set_UpdatedRsc.ursc_md5[2], _LOClient_Set_UpdatedRsc.ursc_md5[3],
                                    _LOClient_Set_UpdatedRsc.ursc_md5[4], _LOClient_Set_UpdatedRsc.ursc_md5[5], _LOClient_Set_UpdatedRsc.ursc_md5[6], _LOClient_Set_UpdatedRsc.ursc_md5[7],
                                    _LOClient_Set_UpdatedRsc.ursc_md5[8], _LOClient_Set_UpdatedRsc.ursc_md5[9], _LOClient_Set_UpdatedRsc.ursc_md5[10], _LOClient_Set_UpdatedRsc.ursc_md5[11] ,
                                    _LOClient_Set_UpdatedRsc.ursc_md5[12], _LOClient_Set_UpdatedRsc.ursc_md5[13], _LOClient_Set_UpdatedRsc.ursc_md5[14], _LOClient_Set_UpdatedRsc.ursc_md5[15]);
                            LOTRACE_ERR("LOCC_processGetRsc: MD5 ERROR - [%d] x%x != x%x", i, output[i], _LOClient_Set_UpdatedRsc.ursc_md5[i]);
                            break;
                        }
                    }

                    if (_LOClient_Set_Rsc.rsc_cb_ntfy) {
                        _LOClient_Set_Rsc.rsc_cb_ntfy((i==sizeof(output)) ? 1 : 2,
                                _LOClient_Set_UpdatedRsc.ursc_obj_ptr,
                                _LOClient_Set_UpdatedRsc.ursc_vers_old,
                                _LOClient_Set_UpdatedRsc.ursc_vers_new,
                                _LOClient_Set_UpdatedRsc.ursc_size);
                    }
                    rc = -1;
                }
            }
            else {
                LOTRACE_INF("PROCESS PENDING RESOURCE %s - cid=%"PRIi32" retry=%d offset=%"PRIu32" => connect to %s ...",
                        _LOClient_Set_UpdatedRsc.ursc_obj_ptr->rsc_name,
                        _LOClient_Set_UpdatedRsc.ursc_cid, _LOClient_Set_UpdatedRsc.ursc_retry, _LOClient_Set_UpdatedRsc.ursc_offset,
                        _LOClient_Set_UpdatedRsc.ursc_uri);
                rc = LO_wget_start(_LOClient_Set_UpdatedRsc.ursc_uri, _LOClient_Set_UpdatedRsc.ursc_size, _LOClient_Set_UpdatedRsc.ursc_offset);
                if (rc == 0) {
                    LOTRACE_WARN("PROCESS RESOURCE %s - cid=%"PRIi32"  uri='%s'",
                            _LOClient_Set_UpdatedRsc.ursc_obj_ptr->rsc_name, _LOClient_Set_UpdatedRsc.ursc_cid, _LOClient_Set_UpdatedRsc.ursc_uri);
                    _LOClient_Set_UpdatedRsc.ursc_connected = 1;
                    if (_LOClient_Set_UpdatedRsc.ursc_offset == 0) {
                         mbedtls_md5_init( &_LOClient_Set_UpdatedRsc.md5_ctx );
                         mbedtls_md5_starts( &_LOClient_Set_UpdatedRsc.md5_ctx );
                    }
                }
            }
        }
        else {
            LOTRACE_WARN("LOCC_processGetRsc: PROCESS PENDING RESOURCE cid=%"PRIi32" - %s => NO USER Callback => ABORT !!!",
                    _LOClient_Set_UpdatedRsc.ursc_cid, _LOClient_Set_UpdatedRsc.ursc_obj_ptr->rsc_name);
        }

        if (rc < 0) {
            if (_LOClient_Set_UpdatedRsc.ursc_connected) {
                LOTRACE_DBG("LOCC_processGetRsc: close TCP connection used for HTTP GET");
                LO_wget_close();
                if ((rc == -50) && (_LOClient_Set_UpdatedRsc.ursc_retry < 4)) {
                    _LOClient_Set_UpdatedRsc.ursc_retry ++;
                    _LOClient_Set_UpdatedRsc.ursc_connected = 0;
                    LOTRACE_WARN("LOCC_processGetRsc: retry=%u => partial content from %"PRIu32,
                            _LOClient_Set_UpdatedRsc.ursc_retry, _LOClient_Set_UpdatedRsc.ursc_offset);
                    return 0;
                }
                LOTRACE_DBG("LOCC_processGetRsc: Free MD5 Context");
                mbedtls_md5_free( &_LOClient_Set_UpdatedRsc.md5_ctx );
            }

            _LOClient_Set_UpdatedRsc.ursc_cid = 0;
            _LOClient_Set_UpdatedRsc.ursc_obj_ptr = NULL;
            _LOClient_Set_UpdatedRsc.ursc_connected = 0;
            _LOClient_Set_UpdatedRsc.ursc_retry = 0;

            _LOClient_Set_Rsc.pushtoLOServer = 1;
        }
    }

    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_LO_PARAMS
static int LOCC_processConfig(void)
{
    int rc = 0;

    if (_LOClient_Set_Params.param_set.param_ptr) {
        const char* pMsg;

        if (_LOClient_Set_UpdatedParams.cid) {
            if ((_LOClient_Set_UpdatedParams.nb_of_params) && (_LOClient_Set_UpdatedParams.tab_of_param_ptr[0])) {
                LOTRACE_INF("LOCC_processConfig: cid=%"PRIi32" => PUBLISH CFG_UPDATE response...", _LOClient_Set_UpdatedParams.cid);
                pMsg = LO_msg_encode_params_update( &_LOClient_Set_UpdatedParams);
                if (pMsg) {
                    rc = LOCC_MqttPublish(QOS0, "dev/cfg", pMsg);
                    if (rc == 0) {
                        _LOClient_Set_UpdatedParams.cid = 0;
                    }
                }
                else {
                    _LOClient_Set_UpdatedParams.cid = 0;
                }
            }
            else {
                LOTRACE_INF("LOCC_processConfig: EMPTY => PUBLISH all CFG parameters with cid=%"PRIi32" ...", _LOClient_Set_UpdatedParams.cid);
                pMsg = LO_msg_encode_params_all( 0, &_LOClient_Set_Params.param_set, _LOClient_Set_UpdatedParams.cid);
                if (pMsg) {
                    rc = LOCC_MqttPublish(QOS0, "dev/cfg", pMsg);
                    if (rc == 0) {
                        _LOClient_Set_UpdatedParams.cid = 0;
                    }
                }
                else {
                    _LOClient_Set_UpdatedParams.cid = 0;
                }
            }
        }

        if ((_LOClient_cfg_first) || (_LOClient_Set_Params.pushtoLOServer)) {
            LOTRACE_INF("LOCC_processConfig: first=%d  push=%d => PUBLISH CFG parameters ...", _LOClient_cfg_first , _LOClient_Set_Params.pushtoLOServer);
            pMsg = LO_msg_encode_params_all( 0, &_LOClient_Set_Params.param_set, 0);
            if (pMsg) {
                rc = LOCC_MqttPublish(QOS0, "dev/cfg", pMsg);
                if (rc == 0) {
                    _LOClient_Set_Params.pushtoLOServer = 0;
                    if (_LOClient_cfg_first) {
#if 1
                        rc = LOCC_SubscibeTopic(TOPIC_CFG_UPD);
                        if (rc == 0) {
                            _LOClient_cfg_first = 0;
                        }
#else
                        _LOClient_cfg_first = 0;
#endif
                    }
                }
            }
        }
    }
    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
#if LOM_PUSH_ASYNC &&  LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
static int LOCC_processData(uint8_t force)
{
    int rc = 0;
    int data_hdl;
    for (data_hdl=0; data_hdl < LOC_MAX_OF_DATA_SET; data_hdl++) {
        LOMSetOfData_t* p_dataSet = &_LOClient_Set_Data[data_hdl];
        if ((p_dataSet->data_set.data_ptr)  && ((force) || p_dataSet->pushtoLOServer)) {
            const char* pMsg;
            p_dataSet->pushtoLOServer = 1;
            LOTRACE_DBG("LOCC_processData: force=%d  pushtoLom=%d => PUBLISH DATA ...", force , p_dataSet->pushtoLOServer);
            // TODO: set timestamp only tif the board has the good date/time  !
            // tbx_GetDateTimeStr(_LOClient_Set_Data.timestamp, sizeof(_LOClient_Set_Data.timestamp));
            pMsg = LO_msg_encode_data(0, p_dataSet);
            if (pMsg) {
                rc = LOCC_MqttPublish(QOS0, "dev/data", pMsg);
                if (rc == 0) {
                    p_dataSet->pushtoLOServer = 0;
                }
            }
        }
    }
    return rc;
}
#endif

//---------------------------------------------------------------------------------
//
static void LOCC_processPendingMesssage()
{
    const char* p_msg;
    while ((p_msg = LOCC_mqGet()) != NULL) {
        if (*p_msg == MTYPE_PUB_DATA) {
               LOTRACE_DBG("LOCC_processPendingMesssage: Publish DATA  %p...", p_msg);
               LOCC_MqttPublish(QOS0, "dev/data", p_msg + 1);
        }
        else if (*p_msg == MTYPE_PUB_CMD_RSP) {
            LOTRACE_INF("LOCC_processPendingMesssage: Publish Command Response %p...", p_msg);
            LOCC_MqttPublish(QOS0, "dev/cmd/res", p_msg + 1);
        }
        else if (*p_msg == MTYPE_PUB_STATUS) {
            LOTRACE_INF("LOCC_processPendingMesssage: Publish STATUS  %p...", p_msg);
            LOCC_MqttPublish(QOS0, "dev/info", p_msg + 1);
        }
        else if (*p_msg == MTYPE_PUB_PARAM) {
            LOTRACE_INF("LOCC_processPendingMesssage: Publish PARAMS  %p...", p_msg);
            LOCC_MqttPublish(QOS0, "dev/cfg", p_msg + 1);
        }
        else if (*p_msg == MTYPE_PUB_RSC) {
            LOTRACE_INF("LOCC_processPendingMesssage: Publish RESOURCES  %p...", p_msg);
            LOCC_MqttPublish(QOS0, "dev/rsc", p_msg + 1);
        }
        else if (*p_msg == MTYPE_PUB_USR_MSG) {
            const char* pc = p_msg + 1;
            short tlen;
            memcpy((char*)&tlen, pc, 2);
            if (tlen > 0) {
                pc += 2;
                LOTRACE_INF("LOCC_processPendingMesssage: Publish t=%s msg='%s' ...", pc, pc + tlen + 1);
                LOCC_MqttPublish(QOS0, pc, pc + tlen + 1);
            }
        }
        else {
            LOTRACE_ERR("LOCC_processPendingMesssage: ERROR -  UNKNOW msg %p x%x", p_msg, *p_msg);
        }
        LOTRACE_DBG("LOCC_processPendingMesssage: MEM_FREE msg %p x%x", p_msg, *p_msg);
        MEM_FREE(p_msg);
    }
}

//---------------------------------------------------------------------------------
//
static int LOCC_setStreamId( uint8_t stream_prefix , LOMSetOfData_t* p_dataSet, const char* stream_id )
{
     if (stream_prefix == 1) {
         int len = snprintf(p_dataSet->stream_id, sizeof(p_dataSet->stream_id)-1,"urn:lo:nsid:%s:%s!%s",
                 _LOClient_dev_name_space, _LOClient_dev_id, stream_id);
         if (len > 0) p_dataSet->stream_id[len] = 0;
     }
     else if (stream_prefix == 2) {
         int len = snprintf(p_dataSet->stream_id, sizeof(p_dataSet->stream_id)-1,"%s:%s!%s",
                 _LOClient_dev_name_space, _LOClient_dev_id, stream_id);
         if (len > 0) p_dataSet->stream_id[len] = 0;
     }
     else {
         strlcpy(p_dataSet->stream_id, stream_id, sizeof(p_dataSet->stream_id));
     }
     return 0;
}


//---------------------------------------------------------------------------------
//
static void LOCC_controlFeature(uint8_t* enable_ptr, int topic_num)
{
    int ret;
    if (*enable_ptr == 0x01)  {
        LOTRACE_INF("LOCC_controlFeature: ENABLE topic_num=%d", topic_num);
        ret = LOCC_SubscibeTopic(topic_num);
        if (ret == 0) {
            LOTRACE_WARN("LOCC_controlFeature: OK to enable topic_num=%d", topic_num);
            *enable_ptr = 0x11;
        }
    }
    else if (*enable_ptr == 0x10)  {
        LOTRACE_WARN("LOCC_controlFeature: DISABLE topic_num=%d", topic_num);
        ret = LOCC_UnsubscibeTopic(topic_num);
        if (ret == 0) {
            *enable_ptr = 0x00;
        }
    }
}

//---------------------------------------------------------------------------------
//
static void LOCC_connectInit( uint8_t mode )
{
    _LOClient_cfg_first = 1;
    if (mode == 0) {
        _LOClient_TopicSub[TOPIC_CFG_UPD].subscribed = 0;
        _LOClient_TopicSub[TOPIC_COMMAND].subscribed = 0;
        _LOClient_TopicSub[TOPIC_RSC_UPD].subscribed = 0;

#if LOC_FEATURE_LO_PARAMS
        memset(&_LOClient_Set_UpdatedParams,0,sizeof(_LOClient_Set_UpdatedParams));
#endif

        LOCC_mqPurge();
    }
}

//---------------------------------------------------------------------------------
//
static int LOCC_connectStart( void )
{
    int rc;

    rc = netw_connect(&_LOClient_MQTTClient_network, &_LOClient_params_connect);
    if (rc) {
        LOTRACE_ERR("Connection failed, rc=%d", rc);
        return rc;
    }

    rc = LOCC_MqttConnect();
    if (rc) {
        LOTRACE_ERR("MqttConnect failed, rc=%d", rc);
        return rc;
    }

    return 0;
}

//---------------------------------------------------------------------------------
//
static void LOCC_connectOK( void )
{
    int ret;
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
    LOTRACE_DBG("Device Status ....");
    ret = LOCC_processStatus(1);
    LOTRACE_DBG("Device Status, ret=%d", ret);
#endif

#if LOC_FEATURE_LO_RESOURCES
    LOTRACE_DBG("Device Resources ....");
    ret = LOCC_processResources(1);
    LOTRACE_DBG("Device Resources, ret=%d", ret);
#endif

#if LOC_FEATURE_LO_PARAMS_1
    LOTRACE_DBG("Device Config ....");
    ret = LOCC_processConfig();
    LOTRACE_DBG("Device Config, ret=%d", ret);
#endif

#if LOC_FEATURE_LO_RESOURCES
    if (_LOClient_Set_Rsc.rsc_ptr) {
        LOTRACE_DBG("Subcribe TOPIC_RSC_UPD=%d....", TOPIC_RSC_UPD);
        ret = LOCC_SubscibeTopic(TOPIC_RSC_UPD);
        LOTRACE_DBG("Subcribe TOPIC_RSC_UPD, ret=%d", ret);
    }
#endif
}


//=================================================================================
// Public Functions : services provided to upper application
//---------------------------------------------------------------------------------
//

//---------------------------------------------------------------------------------
//
void  LiveObjectsClient_InitDbgTrace(lotrace_level_t level)
{
    LOTRACE_INIT(level);
}


//---------------------------------------------------------------------------------
//
void  LiveObjectsClient_SetDbgLevel(lotrace_level_t level)
{
    LOTRACE_LEVEL(level);
}

//---------------------------------------------------------------------------------
//
void  LiveObjectsClient_SetDbgMsgDump(uint16_t mode)
{
#if LOC_MQTT_DUMP_MSG
    _LOClient_dump_mqtt_publish = mode;
#endif
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_CheckApiKey(const char* apikey)
{
    if ((apikey) && (*apikey)) {
        unsigned int i;
        for (i=0; i < strlen(apikey); i++) {
            if ( 0 == ( ((apikey[i] >= '0') && (apikey[i] <= '9'))
                || ((apikey[i] >= 'a') && (apikey[i] <= 'f'))
                || ((apikey[i] >= 'A') && (apikey[i] <= 'F')) ) )
                return -1;
        }
        return 0;
    }
    return -1;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_Init(void* net_iface_handler)
{
    int rc;
    if (LiveObjectsClient_CheckApiKey(LOC_CLIENT_DEV_API_KEY)) {
        LOTRACE_ERR("LiveObjectsClient_Init: A correct  APIKEY is mandatory - apikey= '%s' ", LOC_CLIENT_DEV_API_KEY);
        return -1;
    }

    LO_sys_init();

    LOCC_mqInit();

#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
    memset(&_LOClient_Set_Status,0,sizeof(_LOClient_Set_Status));
#endif
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    memset(&_LOClient_Set_Data,0,sizeof(_LOClient_Set_Data));
#endif
#if LOC_FEATURE_LO_PARAMS
    memset(&_LOClient_Set_Params,0,sizeof(_LOClient_Set_Params));
    memset(&_LOClient_Set_UpdatedParams,0,sizeof(_LOClient_Set_UpdatedParams));
#endif
#if LOC_FEATURE_LO_COMMANDS
    memset(&_LOClient_Set_Cmd,0,sizeof(_LOClient_Set_Cmd));
#endif
#if LOC_FEATURE_LO_RESOURCES
    memset(&_LOClient_Set_Rsc,0,sizeof(_LOClient_Set_Rsc));
    memset(&_LOClient_Set_UpdatedRsc,0,sizeof(_LOClient_Set_UpdatedRsc));
#endif

    rc = netw_init(&_LOClient_MQTTClient_network, net_iface_handler);
    if (rc) {
        LOTRACE_ERR("LiveObjectsClient_Init: Error to initialize the network wrapper, rc=%d", rc);
        return rc;
    }

    MQTTClientInit(&_LOClient_mqtt_ctx, &_LOClient_MQTTClient_network,
            LOC_MQTT_DEF_COMMAND_TIMEOUT,
            _LOClient_mqtt_buffer_snd, LOC_MQTT_DEF_SND_SZ,
            _LOClient_mqtt_buffer_rcv, LOC_MQTT_DEF_RCV_SZ);

#if SECURITY_ENABLED && ((LOC_SERV_PORT  == 1884) || (LOC_SERV_PORT  == 8883))
    rc = LOCC_EnableTLS();
    if (rc) {
        return rc;
    }
#endif

    LOTRACE_DBG("LiveObjectsClient_Init: OK");

    return 0;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_SetDevId(const char* dev_id)
{
    int ret, len;
    if ((dev_id) && (*dev_id)) {
        len = strlen(dev_id);
        ret = strlcpy(_LOClient_dev_id, dev_id, sizeof(_LOClient_dev_id) - 1);
        if (ret != len) {
            LOTRACE_ERR("Error to set dev_id, rc=%d != %d ", ret, len);
            return -1;
        }
    }
    LOTRACE_WARN("dev_id=\"%s\"", _LOClient_dev_id);
    return 0;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_SetNameSpace(const char* name_space)
{
    int ret, len;
    if ((name_space) && (*name_space)) {
        len = strlen(name_space);
        ret = strlcpy(_LOClient_dev_name_space, name_space, sizeof(_LOClient_dev_name_space) - 1);
        if (ret != len) {
            LOTRACE_ERR("Error to set name_space, rc=%d != %d ", ret, len);
            return -1;
        }
    }
    LOTRACE_WARN("name_space=\"%s\"", _LOClient_dev_name_space);
    return 0;
}


//---------------------------------------------------------------------------------
//
int LO_sock_dnsSetFQDN(const char* full_name, const char* ip_address);

int LiveObjectsClient_DnsSetFQDN(const char* full_name, const char* ip_address)
{
    if ((full_name == NULL) || (*full_name == 0)) {
        LOTRACE_ERR("LiveObjectsClient_DnsSetFQDN: ERROR - Invalid parameter ");
        return -1;
    }
    return LO_sock_dnsSetFQDN(full_name, ip_address);
}

int LiveObjectsClient_DnsResolve(void)
{
    int ret;
    const char* ip = LOC_SERV_IP_ADDRESS;
    if ((*ip >= '0') && (*ip <= '9')) {
        LOTRACE_INF("LiveObjectsClient_DnsResolve: ip=%s (fqdn=%s) ", ip , LOC_SERV_HOST_NAME);
        ret = LO_sock_dnsSetFQDN(LOC_SERV_HOST_NAME, ip);
        if (ret < 0)  LOTRACE_ERR("ERROR returned by LO_sock_dnsSetFQDN(%s,%s)", LOC_SERV_HOST_NAME, ip);
    }
    else {
        LOTRACE_INF("LiveObjectsClient_DnsResolve: ip=%s => Call DNS Resolver ...", ip);;
        ret = LO_sock_dnsSetFQDN(ip, NULL);
        if (ret < 0)  LOTRACE_ERR("ERROR returned by LO_sock_dnsSetFQDN(%s,NULL)", ip);
    }

    if (ret > 0)  LOTRACE_INF("LiveObjectsClient_DnsResolve: Would blocked");
    return ret;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_AttachCfgParams (
        const LiveObjectsD_Param_t* param_ptr, int32_t param_nb,
        LiveObjectsD_CallbackParams_t callback)
{
#if LOC_FEATURE_LO_PARAMS
    _LOClient_Set_Params.param_set.param_ptr = param_ptr;
    _LOClient_Set_Params.param_set.param_nb = param_nb;
    _LOClient_Set_Params.param_callback = callback;

    LOTRACE_INF("LiveObjectsClient_AttachCfgParams: nb=%"PRIi32" callback=%p",  param_nb, callback);

    return 0;
#else
    return -1;
#endif
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_AttachStatus (const LiveObjectsD_Data_t* data_ptr, int32_t data_nb)
{
    if ((data_ptr == NULL) || (data_nb == 0)) {
        return -1;
    }
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
    int status_hdl;
    for (status_hdl=0; status_hdl < LOC_MAX_OF_STATUS_SET; status_hdl++) {
        if (_LOClient_Set_Status[status_hdl].data_set.data_ptr == NULL) {
            break;
        }
    }

    if (status_hdl < LOC_MAX_OF_STATUS_SET) {
        _LOClient_Set_Status[status_hdl].data_set.data_ptr = data_ptr;
        _LOClient_Set_Status[status_hdl].data_set.data_nb = data_nb;
        _LOClient_Set_Status[status_hdl].pushtoLOServer = 1;

        LOTRACE_INF("LiveObjectsClient_AttachStatus: nb=%"PRIi32, data_nb);
        return status_hdl;
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_AttachData (uint8_t stream_prefix, const char* stream_id, const char* model, const char* tags,
        const LiveObjectsD_GpsFix_t* gps_ptr,
        const LiveObjectsD_Data_t*   data_ptr,
        int32_t data_nb)
{
    if ((stream_id == NULL) || (*stream_id == 0) || (data_ptr == NULL) || (data_nb == 0)) {
        return -1;
    }
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    int data_hdl;
    for (data_hdl=0; data_hdl < LOC_MAX_OF_DATA_SET; data_hdl++) {
        if (_LOClient_Set_Data[data_hdl].stream_id[0] == 0) {
            break;
        }
    }

    if (data_hdl < LOC_MAX_OF_DATA_SET) {
        LOMSetOfData_t* p_dataSet = &_LOClient_Set_Data[data_hdl];

        int ret = LOCC_setStreamId(stream_prefix, p_dataSet, stream_id);
        if (ret != 0) {
            return -1;
        }
        if ((model) && (*model)) {
            strlcpy(p_dataSet->model, model, sizeof(p_dataSet->model));
        }
        else p_dataSet->model[0] = 0;

        if ((tags) && (*tags)) {
            strlcpy(p_dataSet->tags, tags, sizeof(p_dataSet->tags));
        }
        else p_dataSet->tags[0] = 0;

        p_dataSet->gps_ptr = gps_ptr;

        p_dataSet->data_set.data_ptr = data_ptr;
        p_dataSet->data_set.data_nb = data_nb;

        LOTRACE_INF("LiveObjectsClient_AttachData: handle=%d nb=%"PRIi32" id=%s m=%s t=%s", data_hdl, data_nb, stream_id, model, tags);
        return data_hdl;
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_AttachCommands (
        const LiveObjectsD_Command_t* cmd_ptr, int32_t cmd_nb,
        LiveObjectsD_CallbackCommand_t callback)
{
#if LOC_FEATURE_LO_COMMANDS
    _LOClient_Set_Cmd.cmd_enable = 0;
    _LOClient_Set_Cmd.cmd_ptr = cmd_ptr;
    _LOClient_Set_Cmd.cmd_nb = cmd_nb;
    _LOClient_Set_Cmd.cmd_callback = callback;

    LOTRACE_INF("AttachCommands: nb=%"PRIi32, cmd_nb);

    return 0;
#else
    return -1;
#endif
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_ControlCommands (bool enable)
{
#if LOC_FEATURE_LO_COMMANDS
    LOTRACE_INF("LiveObjectsClient_ControlCommands: enable=%u (current state 0x%x)",
            enable, _LOClient_Set_Cmd.cmd_enable);
    if (enable)
        _LOClient_Set_Cmd.cmd_enable = 0x01;
    else {
        if (_LOClient_Set_Cmd.cmd_enable & 0x10)
            _LOClient_Set_Cmd.cmd_enable = 0x10;
    }
#endif
    return 0;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_AttachResources (
        const LiveObjectsD_Resource_t* rsc_ptr, int32_t rsc_nb,
        LiveObjectsD_CallbackResourceNotify_t ntfyCB,
        LiveObjectsD_CallbackResourceData_t   dataCB)
{
#if LOC_FEATURE_LO_RESOURCES
    _LOClient_Set_Rsc.rsc_enable = 0x01;
    _LOClient_Set_Rsc.rsc_ptr = rsc_ptr;
    _LOClient_Set_Rsc.rsc_nb = rsc_nb;
    _LOClient_Set_Rsc.rsc_cb_ntfy = ntfyCB;
    _LOClient_Set_Rsc.rsc_cb_data = dataCB;

    LOTRACE_INF("LiveObjectsClient_AttachResources: nb=%"PRIi32, rsc_nb);

    return 0;
#else
    return -1;
#endif
}

//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_ControlResources(bool enable)
{
#if LOC_FEATURE_LO_RESOURCES
    LOTRACE_INF("LiveObjectsClient_ControlResources: enable=%u (current state 0x%x)",
            enable, _LOClient_Set_Rsc.rsc_enable);
    if (enable)
        _LOClient_Set_Rsc.rsc_enable = 0x01;
    else if (_LOClient_Set_Rsc.rsc_enable & 0x01)
        _LOClient_Set_Rsc.rsc_enable = 0x10;
#endif
    return 0;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_ChangeDataStreamId(uint8_t prefix, int data_hdl, const char* stream_id)
{
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    if ((data_hdl >= 0) && (data_hdl < LOC_MAX_OF_DATA_SET)
            && _LOClient_Set_Data[data_hdl].stream_id[0]
            && (stream_id) && (*stream_id)) {
        int ret = LOCC_setStreamId(prefix, &_LOClient_Set_Data[data_hdl], stream_id);
        return ret;
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_RemoveData(int data_hdl)
{
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    if ((data_hdl >= 0) && (data_hdl < LOC_MAX_OF_DATA_SET)  && _LOClient_Set_Data[data_hdl].stream_id[0]) {
        _LOClient_Set_Data[data_hdl].data_set.data_ptr = NULL;
        memset(&_LOClient_Set_Data[data_hdl], 0, sizeof(LOMSetOfData_t));
        return 0;
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_RemoveCommands(void)
{
#if LOC_FEATURE_LO_COMMANDS
    memset(&_LOClient_Set_Cmd, 0, sizeof(_LOClient_Set_Cmd));
#endif
    return 0;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_RemoveResources(void)
{
#if LOC_FEATURE_LO_RESOURCES
    memset(&_LOClient_Set_Rsc, 0, sizeof(_LOClient_Set_Rsc));
#endif
    return 0;
}


//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Connect( void )
{
    int rc;

    LOCC_connectInit( 0 );

    rc = LOCC_connectStart();
    if (rc) {
        LOTRACE_ERR("LiveObjectsClient_Connect: connection failed, rc=%d", rc);
    }
    else {
        LOCC_connectOK();
    }
    return rc;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Disconnect(void)
{
    int rc;
    rc = MQTTDisconnect(&_LOClient_mqtt_ctx);
    if (rc) LOTRACE_ERR("MQTTDisconnect failed, rc=%d", rc);
    netw_disconnect(&_LOClient_MQTTClient_network, 0);
    _LOClient_state_connected = 0;
    return 0;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Yield(int timeout_ms)
{
    int ret = -1;
    if (_LOClient_state_connected) {
        LOTRACE_DBG_VERBOSE("LiveObjectsClient_Yield: CONNECTED => MQTTYield(%d ms)...", timeout_ms);
        ret = MQTTYield(&_LOClient_mqtt_ctx, timeout_ms);
        LOTRACE_DBG_VERBOSE("LiveObjectsClient_Yield: CONNECTED => MQTTYield(%d ms) ========> ret=%d.", timeout_ms, ret);
        if ((ret < 0) || netw_isLost(&_LOClient_MQTTClient_network)) {
            LOTRACE_WARN("LiveObjectsClient_Yield: ret=%d or LOST !!!", ret);
            netw_disconnect(&_LOClient_MQTTClient_network, 0);
            _LOClient_state_connected = 0;
            ret = -1;
        }
    }
    else LOTRACE_DBG_VERBOSE("LiveObjectsClient_Yield: NOT CONNECTED !!!");
    return ret;
}


//---------------------------------------------------------------------------------
//
int  LiveObjectsClient_PushResources(void)
{
#if LOC_FEATURE_LO_RESOURCES
    if  ((_LOClient_state_connected) && (_LOClient_Set_Rsc.rsc_ptr)) {
#if LOM_PUSH_ASYNC
        _LOClient_Set_Rsc.pushtoLOServer = 1;
        return 0;
#else
        uint8_t from = LO_sys_threadIsLiveObjectsClient() ? 0 : MTYPE_PUB_RSC;
        const char *p_msg = LO_msg_encode_resources(from, &_LOClient_Set_Rsc);
        if (p_msg) {
            if (from == 0) {
                // Publish now because it is LiveObjects Client thread
                return LOCC_MqttPublish(QOS0, "dev/rsc", p_msg);
            }
            // otherwise put it in the queue
            if (LOCC_mqPut(p_msg) == 0) {
                LOTRACE_INF("LiveObjectsClient_PushStatus: msg is put in queue !!!");
                return 0;
            }
            LOTRACE_ERR("LiveObjectsClient_PushStatus: ERROR to put in queue - MEM_FREE %p x%x", p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
#endif
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_PushStatus(int handle)
{
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
    if ((_LOClient_state_connected)
            && (handle >= 0) && (handle < LOC_MAX_OF_STATUS_SET)
            && (_LOClient_Set_Status[handle].data_set.data_ptr)) {
#if LOM_PUSH_ASYNC
        _LOClient_Set_Status[handle].pushtoLOServer = 1;
        return 0;
#else
        uint8_t from = LO_sys_threadIsLiveObjectsClient() ? 0 : MTYPE_PUB_STATUS;
        const char *p_msg = LO_msg_encode_status(from, &_LOClient_Set_Status[handle].data_set);
        if (p_msg) {
            if (from == 0) {
                // Publish now because it is LiveObjects Client thread
                return LOCC_MqttPublish(QOS0, "dev/info", p_msg);
            }
            // otherwise put it in the queue
            if (LOCC_mqPut(p_msg) == 0) {
                LOTRACE_INF("LiveObjectsClient_PushStatus: msg is put in queue !!!");
                return 0;
            }
            LOTRACE_ERR("LiveObjectsClient_PushStatus: ERROR to put in queue - MEM_FREE %p x%x", p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
#endif
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_PushData(int data_hdl)
{
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    if  (_LOClient_state_connected
            && (data_hdl >= 0) && (data_hdl < LOC_MAX_OF_DATA_SET)
            && _LOClient_Set_Data[data_hdl].stream_id[0]
            && _LOClient_Set_Data[data_hdl].data_set.data_ptr) {
#if LOM_PUSH_ASYNC
        _LOClient_Set_Data[data_hdl].pushtoLOServer = 1;
        return 0;
#else
        uint8_t from = LO_sys_threadIsLiveObjectsClient() ? 0 : MTYPE_PUB_DATA;
        const char *p_msg = LO_msg_encode_data(from, &_LOClient_Set_Data[data_hdl]);
        if (p_msg) {
            if (from == 0) {
                // Publish now because it is LiveObjects Client thread
                return LOCC_MqttPublish(QOS0, "dev/data", p_msg);
            }
            // otherwise put it in the queue
            if (LOCC_mqPut(p_msg) == 0) {
                LOTRACE_DBG("LiveObjectsClient_PushData: msg is put in queue !!!");
                return 0;
            }
            LOTRACE_ERR("LiveObjectsClient_PushData: ERROR to put in queue - MEM_FREE %p x%x", p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
#endif
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_PushCfgParams(void)
{
#if LOC_FEATURE_LO_PARAMS
    if  ((_LOClient_state_connected) && (_LOClient_Set_Params.param_set.param_ptr)) {
#if LOM_PUSH_ASYNC
        _LOClient_Set_Params.pushtoLOServer = 1;
        return 0;
#else
        uint8_t from =  LO_sys_threadIsLiveObjectsClient() ? 0 : MTYPE_PUB_PARAM;
        const char *p_msg = LO_msg_encode_params_all(from, &_LOClient_Set_Params.param_set, 0);
        if (p_msg) {
            if (from == 0) {
                // Publish now because it is LiveObjects Client thread
                return LOCC_MqttPublish(QOS0, "dev/cfg", p_msg);
            }
            // otherwise put it in the queue
            if (LOCC_mqPut(p_msg) == 0) {
                LOTRACE_INF("LiveObjectsClient_PushData: msg is put in queue !!!");
                return 0;
            }
            LOTRACE_ERR("LiveObjectsClient_PushData: ERROR to put in queue - MEM_FREE %p x%x", p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
#endif
    }
#endif
    return -1;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_CommandResponse(int32_t cid, const LiveObjectsD_Data_t* data_ptr, int data_nb)
{
#if LOC_FEATURE_LO_COMMANDS
    if  (_LOClient_state_connected) {
        uint8_t from = LO_sys_threadIsLiveObjectsClient()  ? 0 : MTYPE_PUB_CMD_RSP;
        LOTRACE_INF("LiveObjectsClient_CommandResponse: from=x%x cid= %"PRIi32" obj_ptr=x%p  obj_nb=%d ...", from, cid , data_ptr, data_nb);
        const char *p_msg = LO_msg_encode_cmd_resp(from, cid, data_ptr, data_nb);
        if (p_msg) {
            if (from == 0) {
                // Publish now because it is LOM Client thread (negative response ...)
                return LOCC_MqttPublish(QOS0, "dev/cmd/res", p_msg);
            }
            // otherwise put it in the queue
            if (LOCC_mqPut(p_msg) == 0) {
                LOTRACE_INF("LiveObjectsClient_CommandResponse: msg is put in queue !!!");
                return 0;
            }
            LOTRACE_ERR("LiveObjectsClient_CommandResponse: ERROR to put in queue - MEM_FREE %p x%x", p_msg, *p_msg);
            MEM_FREE(p_msg);
        }
    }
#endif
    return -1;
}


//---------------------------------------------------------------------------------
//
int LiveObjectsClient_RscGetChunck(
        const LiveObjectsD_Resource_t* rsc_ptr,
        char* data_ptr, int data_len)
{
#if LOC_FEATURE_LO_RESOURCES
    int ret;
    // see code in LOCC_processGetRsc() function
    //:
    if ( (_LOClient_Set_UpdatedRsc.ursc_cid) && (_LOClient_Set_UpdatedRsc.ursc_obj_ptr == rsc_ptr)) {
        ret = LO_wget_data(data_ptr, data_len);
        if (ret > 0) {
            // Update checksum md5 and offset
            mbedtls_md5_update( &_LOClient_Set_UpdatedRsc.md5_ctx , (const unsigned char *)data_ptr, (size_t)ret);
            _LOClient_Set_UpdatedRsc.ursc_offset += ret;
            LOTRACE_DBG("LiveObjectsClient_RscGetChunck(len=%d): read len=%d => new offset=%"PRIu32"/%"PRIu32, data_len, ret,
                    _LOClient_Set_UpdatedRsc.ursc_offset, _LOClient_Set_UpdatedRsc.ursc_size);
        }
        else if (ret == 0) {
            LOTRACE_WARN("LiveObjectsClient_RscGetChunck: No byte while reading %d bytes (offset=%"PRIu32"/%"PRIu32" of  %s)",
                    data_len , _LOClient_Set_UpdatedRsc.ursc_offset, _LOClient_Set_UpdatedRsc.ursc_size, rsc_ptr->rsc_name);
        }
        else {
            //TODO: implement a procedure to retry the operation. at the last offset/md5
            LOTRACE_ERR("LiveObjectsClient_RscGetChunck: ERROR(%d) while reading %d bytes (offset=%"PRIu32"/%"PRIu32" of  %s)",  ret,
                    data_len , _LOClient_Set_UpdatedRsc.ursc_offset, _LOClient_Set_UpdatedRsc.ursc_size, rsc_ptr->rsc_name);
        }
    }
    else {
        LOTRACE_ERR("LiveObjectsClient_RscGetChunck: ERROR - No running resource download !");
        LO_wget_close();
        ret = -1;
    }
    return ret;
#else
    return -1;
#endif
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Cycle( int timeout_ms )
{
    int ret;

    if (!_LOClient_state_connected){
        LOTRACE_INF("LiveObjectsClient_Cycle (tms=%d): ERROR - Not connected !!!.", timeout_ms);
        return -1;
    }

    LOTRACE_DBG("LiveObjectsClient_Cycle (tms=%d) ...", timeout_ms);

    //  -- Pending user messages ? (command responses, ...)
    LOCC_processPendingMesssage();

#if LOC_FEATURE_LO_PARAMS
    // Something to publish ?
    //  -- Config Parameters ?
    ret = LOCC_processConfig();
#endif

#if LOM_PUSH_ASYNC
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
    //  -- 'Info' ?
    ret = LOCC_processStatus(0);
#endif
#if  LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
    //  -- 'Collected data' ?
    ret = LOCC_processData(0);
#endif
#endif // LOM_PUSH_ASYNC

#if LOC_FEATURE_LO_RESOURCES
    LOCC_processResources(0);

    LOCC_processGetRsc();
#endif

    // Get and process some MQTT messages received from the LiveObject Server
    ret = LiveObjectsClient_Yield(timeout_ms);
    if (ret) {
        LOTRACE_ERR("Device Yield, ret=%d", ret);
        LOTRACE_WARN("Device Disconnecting ...");
        ret = LiveObjectsClient_Disconnect();
        if (ret) {
            LOTRACE_ERR("Device Disconnect, ret=%d", ret);
        }
        return -1;
    }

#if LOC_FEATURE_LO_COMMANDS
    LOCC_controlFeature(&_LOClient_Set_Cmd.cmd_enable, TOPIC_COMMAND);
#endif
#if LOC_FEATURE_LO_RESOURCES
    LOCC_controlFeature(&_LOClient_Set_Rsc.rsc_enable, TOPIC_RSC_UPD);
#endif
    return 0;
}


//---------------------------------------------------------------------------------
//
//---------------------------------------------------------------------------------
//
int8_t LiveObjectsClient_ThreadState(void)
{
    return _LOClient_state_run;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Stop(void)
{
    if (_LOClient_state_run > 0) {
        _LOClient_state_run = -1;
        return 0;
    }
    return -1;
}

//---------------------------------------------------------------------------------
//
void LiveObjectsClient_Run(LiveObjectsD_CallbackState_t callback)
{
    int ret;
    uint32_t loop_cnt;

    LO_sys_threadRun();
    _LOClient_state_run = 1;

    while(_LOClient_state_run > 0)
    {
        ret = -1;
        loop_cnt = 0;

        LOCC_connectInit(0) ;

        while (_LOClient_state_run > 0) {
            LOTRACE_DBG("Try connection ...");
            if (callback) callback(CSTATE_CONNECTING);
            ret = LOCC_connectStart();
            if (ret == 0) {
                break;
            }
            WAIT_MS(5000);
        }

        if  ((_LOClient_state_run > 0) && (_LOClient_state_connected)) {

            LO_sys_threadCheck();

            if (callback) callback(CSTATE_CONNECTED);

            LOCC_connectOK();

        }

        while ((_LOClient_state_run > 0) &&  (_LOClient_state_connected)) {

            ++loop_cnt;
            if ((loop_cnt%10) == 0) {
                LOTRACE_DBG("I am alive - %"PRIu32, loop_cnt);
            }

            //  -- Pending user messages ? (command responses, ...)
            LOCC_processPendingMesssage();

#if LOC_FEATURE_LO_PARAMS
            // Something to publish ?
            //  -- Config Parameters ?
            ret = LOCC_processConfig();
#endif

#if LOM_PUSH_ASYNC
#if LOC_FEATURE_LO_STATUS  && (LOC_MAX_OF_DATA_SET > 0)
            //  -- 'Info' ?
            ret = LOCC_processStatus(0);
#endif
#if LOC_FEATURE_LO_DATA && (LOC_MAX_OF_DATA_SET > 0)
            //  -- 'Collected data' ?
            ret = LOCC_processData(0);
#endif
#endif // LOM_PUSH_ASYNC

#if LOC_FEATURE_LO_RESOURCES
            LOCC_processResources(0);

            LOCC_processGetRsc();
#endif

            // Get and process some MQTT messages received from the LiveObject Server
            ret = LiveObjectsClient_Yield(100);
            if (ret) {
                LOTRACE_ERR("Device Yield, ret=%d", ret);
                break;
            }
#if LOC_FEATURE_LO_COMMANDS
            LOCC_controlFeature(&_LOClient_Set_Cmd.cmd_enable, TOPIC_COMMAND);
#endif
#if LOC_FEATURE_LO_RESOURCES
            LOCC_controlFeature(&_LOClient_Set_Rsc.rsc_enable, TOPIC_RSC_UPD);
#endif
            ret = 0;
        }
        LOTRACE_WARN("Device Disconnecting ...");
        ret = LiveObjectsClient_Disconnect();
        if (ret) {
            LOTRACE_ERR("Device Disconnect, ret=%d", ret);
        }
        if (callback) callback(CSTATE_DISCONNECTED);
        LOTRACE_WARN("WAIT 5 seconds ...");
        WAIT_MS(5000);
    }


    _LOClient_state_run = -2;

    if (callback) callback(CSTATE_DOWN);

}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_ThreadStart(LiveObjectsD_CallbackState_t callback)
{
    LOTRACE_INF("LiveObjectsClient_ThreadStart(x%p) ...", callback);
    int ret = LO_sys_threadStart((void const *)callback);
    if (ret)
        LOTRACE_ERR("LiveObjectsClient_ThreadStart(x%p) ret=%d", callback, ret);

    return ret;
}

//---------------------------------------------------------------------------------
//
int LiveObjectsClient_Publish(
        const char* topicName,
        const char* payload_data)
{
    char* p_msg;
    short tlen = strlen(topicName);
    int len = 1 + 2 + tlen + 1 + strlen(payload_data) + 2;
    p_msg = (char*) MEM_ALLOC(len);
    if (p_msg) {
        char *pc = p_msg;
        *pc++ = MTYPE_PUB_USR_MSG;     // 1- Set the message type
        memcpy(pc, &tlen, 2);          // 2- Copy the topic length
        pc += 2;
        strcpy(pc, topicName);         // 3- Copy the topic
        pc += tlen;
        *pc++ = 0;
        strcpy(pc, payload_data);      // 4- Copy the payload
        LOTRACE_WARN("LiveObjectsClient_Publish: MEM_ALLOC msg=x%p msg_type=x%x", p_msg, *p_msg);
        if (LOCC_mqPut(p_msg) == 0) {  // 5- Put in the queue
            return 0;
        }
        LOTRACE_ERR("LiveObjectsClient_Publish: ERROR to enqueue msg -> MEM_FREE msg %p x%x", p_msg, *p_msg);
        MEM_FREE(p_msg);
    }
    else  LOTRACE_ERR("LiveObjectsClient_Publish: MALLOC ERROR");
    return -1;
}
