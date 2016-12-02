/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  loc_wget.c
  * @brief Very simple and dirty implementation of HTTP Get
  */

#include "loc_wget.h"

#include "loc_sock.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "liveobjects-sys/loc_trace.h"

#include "liveobjects-sys/LiveObjectsClient_Platform.h"


#define HTTP_USER_AGENT              "IotSoftbox-mqtt 1.0 (mbed)"

#define HTTP_HD_Server               "Server:"
#define HTTP_HD_CONTENT_TYPE         "Content-Type:"
#define HTTP_HD_CONTENT_LENGTH       "Content-Length:"
#define HTTP_HD_CONTENT_RANGE        "Content-Range:"
#define HTTP_HD_APPLICATION_CONTEXT  "X-Application-Context:"

static void*  _wget_sock_hdl;
static char   _wget_buffer[400];

//---------------------------------------------------------------------------------
//
static void wget_build_get_query(char* buf_ptr, int buf_len, const char* pURL, const char* pHost, uint32_t offset)
{
    int rc;
    char* pc=buf_ptr;
    const char *tpl = "GET /%s HTTP/1.0\r\n"
            "Host: %s\r\n"
#ifdef HTTP_USER_AGENT
            "User-Agent: " HTTP_USER_AGENT "\r\n"
#endif
            ;

  if(pURL[0] == '/'){
      pURL = pURL + 1;
  }

  rc = snprintf(pc, buf_len, tpl, pURL, pHost);
  pc += rc;
  buf_len -= rc;
  if (offset > 0) {
      rc = snprintf(pc, buf_len, "Range: bytes=%"PRIu32"-\r\n\r\n", offset);
  }
  else {
      rc = snprintf(pc, buf_len, "\r\n");
  }
  pc += rc;
  *pc = 0;
}


//---------------------------------------------------------------------------------
//
static int wget_query(const char* pURL, const char* pHost,  uint32_t rsc_size, uint32_t rsc_offset)
{
    int ret;
    int http_value;
    uint32_t http_content_length;
    char* pc;

    wget_build_get_query(_wget_buffer, sizeof(_wget_buffer)-1, pURL, pHost, rsc_offset);

    ret = LO_sock_send(_wget_sock_hdl, _wget_buffer);
    if (ret) {
        LOTRACE_ERR("Error while sending HTTP GET query to %s", pHost);
        return -1;
    }

    ret = LO_sock_read_line(_wget_sock_hdl, _wget_buffer, sizeof(_wget_buffer)-1);
    if (ret <= 0) {
        LOTRACE_ERR("Error while reading the HTTP GET response from %s", pHost);
        return -1;
    }

    //Parse HTTP response
    http_value = 0;
    ret = sscanf(_wget_buffer, "HTTP/%*d.%*d %d %*s", &http_value);
    if ( ret != 1 ) {
        //Cannot match string, error
        LOTRACE_ERR("Not a correct HTTP answer : %d <%s>", ret,  _wget_buffer);
        return -1;
    }

    LOTRACE_INF("rsp_code=%d <%s>", http_value, _wget_buffer);
    if ((http_value != 200) && ! ((http_value == 206) && (rsc_offset>0))) {
        LOTRACE_ERR("Unexpected HTTP Resp code %d", http_value);
        return -1;
    }

    http_content_length = 0;
    while (1) {
        ret = LO_sock_read_line(_wget_sock_hdl, _wget_buffer, sizeof(_wget_buffer)-1);
        if (ret < 0) {
            LOTRACE_WARN("Error while reading HTTP headers");
            return -1;
        }
        if (ret == 0) { // Body ...
            break;
        }

        LOTRACE_INF("http header: <%s>", _wget_buffer);
        pc = strstr(_wget_buffer,":");
        if (pc != NULL) {
            pc++;
            LOTRACE_DBG("value after ':' =  %s", pc);
            if (!strncasecmp(_wget_buffer, HTTP_HD_CONTENT_LENGTH, strlen(HTTP_HD_CONTENT_LENGTH))) {
                ret = sscanf(pc, "%"PRIu32, &http_content_length);
                LOTRACE_DBG("data len=%"PRIu32" {%s}", http_content_length,  _wget_buffer);
            }
            else if (!strncasecmp(_wget_buffer, HTTP_HD_CONTENT_RANGE, strlen(HTTP_HD_CONTENT_RANGE))) {
                LOTRACE_INF(" ---- byte range %s", pc);
            }
        }
        else {
            LOTRACE_WARN(" BAD HEADER FORMAT <%s>", _wget_buffer);
            return -1;
        }
    }

    if (http_content_length == 0) {
        LOTRACE_ERR("ERROR - content_length = 0");
        return -1;
    }

    if (http_content_length != (rsc_size - rsc_offset)) {
        LOTRACE_WARN("ERROR - content_length= %"PRIu32" != %"PRIu32" (expected size=%"PRIu32" offset=%"PRIu32")",
                http_content_length, (rsc_size - rsc_offset), rsc_size, rsc_offset);
        return -1;
    }

     LOTRACE_INF("HTTP_GET: BODY -> Get data (content_length= %"PRIu32")", http_content_length);

    return 0;
}

//---------------------------------------------------------------------------------
//
void LO_wget_close(void)
{
    if (_wget_sock_hdl) {
        LOTRACE_INF("LO_wget_close: CLOSE TCP connection");
        LO_sock_disconnect(&_wget_sock_hdl);
    }
}


//---------------------------------------------------------------------------------
//
int LO_wget_start(const char* uri, uint32_t rsc_size, uint32_t rsc_offset)
{
    int ret;
    const char* pc = uri;
    const char* ps;

    char     host_name[40];
    uint16_t host_port = 80;

    if ((pc == NULL) || (*pc == 0) || (rsc_size == 0) || (rsc_offset >= rsc_size)) {
        LOTRACE_ERR("LO_wget_start: Invalid parameters uri=%p, size=%"PRIu32", offset=%"PRIu32,
                uri, rsc_size, rsc_offset);
        return -1;
    }
    LOTRACE_INF("LO_wget_start: uri='%s' rsc_size=%"PRIu32" rsc_offset=%"PRIu32" ....", uri, rsc_size, rsc_offset);

    if (strncasecmp(pc, "http", 4)) {
        LOTRACE_ERR("LO_wget_start: URI ERROR - expected http");
        return -1;
    }
    pc += 4;
    if ( (*pc == 's') || (*pc == 'S')) {
        LOTRACE_ERR("LO_wget_start: HTTPS not supported");
        return -1;
    }
    if (strncmp(pc,"://",3)) {
        LOTRACE_ERR("LO_wget_start: URI ERROR - host not found");
        return -1;
    }
    pc += 3;
    ps = pc;
    while ((*pc != ':') && (*pc != '/') && (*pc != 0)) pc ++;
    memcpy (host_name, ps, pc - ps);
    host_name[pc - ps] = 0;

    if (*pc == ':') { // get port
        ps = ++pc;
        while ((*pc != '/') && (*pc != 0)) pc ++;
        if (sscanf(ps, "%hu", &host_port) != 1) {
            LOTRACE_ERR("LO_wget_start: ERROR - could not find port");
            return -1;
        }
    }
    if (*pc != '/') {
        LOTRACE_ERR("LO_wget_start: ERROR - could not find URL");
        return -1;
    }

    LOTRACE_DBG("Connect to %s:%d ....", host_name, host_port);
    _wget_sock_hdl = LO_sock_connect(2, host_name, host_port);
    if (_wget_sock_hdl == NULL) {
        LOTRACE_ERR("Error while connecting to %s:%d", host_name, host_port);
        return -1;
    }

    ret = wget_query(pc, host_name, rsc_size, rsc_offset);
    if (ret < 0)  {
        LOTRACE_ERR("Error while processing HTTP GET query to %s:%d", host_name, host_port);
        LO_sock_disconnect(&_wget_sock_hdl);
        return -1;
    }

    return 0;
}

//---------------------------------------------------------------------------------
//
int LO_wget_data(char* pData, int len)
{
    int ret;

    if (_wget_sock_hdl == NULL) {
        LOTRACE_ERR("LO_wget_data(len=%d) -> NO SOCKET !!!", len);
        return -1;
    }

    LOTRACE_DBG("LO_wget_data(len=%d) ....", len);

    ret = LO_sock_recv(_wget_sock_hdl, pData, len);
    if(ret < 0){
        LOTRACE_ERR("LO_wget_data(len=%d) -> ERROR %d",  len, ret);
        LO_sock_disconnect(&_wget_sock_hdl);
        return -1;
    }

    if (ret == 0) {
        LOTRACE_ERR("LO_wget_data(len=%d) ->  ret=0 !!!", len);
        pData[ret] = 0;
        return 0;
    }

    LOTRACE_DBG("LO_wget_data(len=%d) ->  ret=%d", len, ret );
    pData[ret] = 0;
    LOTRACE_DBG("%s", pData );

    return ret;
}
