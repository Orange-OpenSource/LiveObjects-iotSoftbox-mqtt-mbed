/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  toolbox.cpp
  * @brief
  */
#include "liveobjects-client/LiveObjectsClient_Toolbox.h"


#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

#include "liveobjects-sys/LiveObjectsClient_Platform.h"

#include "mbed.h"
#include "rtos.h"

static time_t   _tbx_date_time = 9;
Ticker          _tbx_date_ticker;

static void tbx_date_tick(void) {
    _tbx_date_time++;
}

#if 0
static void tbx_InitDateTime(void)
{
    struct tm  s_tm;
    struct tm* p_tm = &s_tm;

    memset(p_tm, 0, sizeof(struct tm));
    p_tm->tm_year = 116;
    p_tm->tm_mon = 8;
    p_tm->tm_mday = 1;
    p_tm->tm_hour = 0;
    p_tm->tm_min = 0;
    p_tm->tm_sec = 0;

    tbx_SettDateTime(p_tm);
}
#endif


extern "C" void LiveObjectsClient_ToolboxInit(void)
{
    _tbx_date_time = 0;

    // Date Ticker at 1 second
    _tbx_date_ticker.attach_us(tbx_date_tick, 1000000);
}


extern "C" void tbx_SettDateTime(struct tm * p_tm) {
    _tbx_date_time = mktime(p_tm);
}

extern "C" void tbx_GetLocalTime(struct tm * p_tm)
{
    memset(p_tm, 0, sizeof(struct tm));
    localtime_r(&_tbx_date_time, p_tm);
}

extern "C" int32_t tbx_GetDateTimeStr(char* str, uint32_t sz)
{
    int32_t rc = -1;
    if ((str) && (sz > 20)) {
        struct tm s_tm ;
        tbx_GetLocalTime(&s_tm);
        //2016-08-30T09:18:01Z
        rc = snprintf(str, sz, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                s_tm.tm_year + 1900,
                s_tm.tm_mon + 1,
                s_tm.tm_mday,
                s_tm.tm_hour,
                s_tm.tm_min,
                s_tm.tm_sec);
        if (rc == 20) {
            return 0;
        }
    }
    if (str) *str = 0;
    return rc;
}
