/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  MQTTLog.c
  * @brief Wrapper for MQTTPacket logs
  *        (see MQQTTPacket/StackTrace.h)
  */

#include "mbed-trace/mbed_trace.h"

#ifndef TRACE_GROUP
#define TRACE_GROUP "MQTT"
#endif

//#define TR_OUPUT tr_info

void StackTrace_entry(const char* name, int line, int trace)
{
#ifdef TR_OUPUT
    TR_OUPUT("MQTT_ENTRY:%s:%d",name, line);
#endif
}

void StackTrace_exit(const char* name, int line, void* return_value, int trace)
{
#ifdef TR_OUPUT
    TR_OUPUT("MQTT_EXIT :%s:%d: return=%d", name,line , (return_value) ? * (int*)return_value : 0 );
#endif
}

#if 0
void StackTrace_printStack(FILE* dest)
{

}
char* StackTrace_get(unsigned long)
{

}
#endif
