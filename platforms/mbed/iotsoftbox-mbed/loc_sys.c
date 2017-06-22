/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  loc_sys.c
  * @brief System Interface : Mutex , Thread, ..
  */

#ifndef MBED_CONF_RTOS_PRESENT
#error "NO RTOS"
#endif

#include "loc_sys.h"

#include "liveobjects-client/LiveObjectsClient_Config.h"
#include "liveobjects-client/LiveObjectsClient_Core.h"

#include "liveobjects-sys/loc_trace.h"

#include "cmsis.h"
#include "cmsis_os.h"

#define WORD_STACK_SIZE   (256*5) // * 4

static osThreadId    _lo_sys_thread_id = NULL;
static osThreadDef_t _lo_sys_thread_def;
static uint32_t      _lo_sys_thread_stack[WORD_STACK_SIZE+2];
static uint32_t      _lo_sys_thread_max = 0;

static struct {
    int32_t      mutex_data[4];
    osMutexDef_t mutex_def;
    osMutexId    mutex_id;
} _lo_sys_mutex[LO_SYS_MUTEX_NB];

//=================================================================================
// Private Functions
//---------------------------------------------------------------------------------
//
static void _LO_sys_threadExec(void const *argument)
{
    LOTRACE_DBG(" _LO_sys_threadExec: go %p...", argument);

    LiveObjectsClient_Run((LiveObjectsD_CallbackState_t)argument);

    LOTRACE_WARN(" _LO_sys_threadExec: EXIT");
}


//=================================================================================
// Public Functions
//---------------------------------------------------------------------------------
// Initialization
void  LO_sys_init( void )
{
    _lo_sys_thread_id = NULL;
    _lo_sys_thread_max = 0;

    memset(_lo_sys_mutex, 0, sizeof(_lo_sys_mutex));

    for(int i=0; i < LO_SYS_MUTEX_NB; i++) {
#ifdef CMSIS_OS_RTX
        memset(_lo_sys_mutex[i].mutex_data, 0, sizeof(_lo_sys_mutex[i].mutex_data));
        _lo_sys_mutex[i].mutex_def.mutex = _lo_sys_mutex[i].mutex_data;
#endif
        _lo_sys_mutex[i].mutex_id = osMutexCreate(&_lo_sys_mutex[i].mutex_def);
        if ( _lo_sys_mutex[i].mutex_id == NULL) {
        }
    }

}
//=================================================================================
// MUTEX
//---------------------------------------------------------------------------------
//
uint8_t  LO_sys_mutex_lock( uint8_t idx )
{
    if (idx) LOTRACE_DBG(" => LO_sys_mutex_lock(%u)", idx);
    if (idx < LO_SYS_MUTEX_NB) {
        osStatus ret = osMutexWait(_lo_sys_mutex[idx].mutex_id, -1);
        if (ret != osOK) LOTRACE_ERR(" !!!! LO_sys_mutex_lock(%u): ERROR %x", idx, ret);
        return (ret == osOK) ? 0 : -1;
    }
    return -2;
}

void  LO_sys_mutex_unlock( uint8_t idx )
{
    if (idx) LOTRACE_DBG(" <= LO_sys_mutex_unlock(%u)", idx);
    if (idx < LO_SYS_MUTEX_NB)
        osMutexRelease(_lo_sys_mutex[idx].mutex_id);
}


//=================================================================================
// THREAD
//---------------------------------------------------------------------------------
//
void LO_sys_threadRun( void )
{
    osThreadId id = osThreadGetId();
    if ( (_lo_sys_thread_id) && (_lo_sys_thread_id !=  id)) {
        LOTRACE_WARN(" LO_sys_threadRun: %p %p", _lo_sys_thread_id, id);
    }
    else LOTRACE_WARN("LiveObjectsClient: thread_id= x%p (x%p)", id, _lo_sys_thread_id);
    _lo_sys_thread_id = id;
}

//---------------------------------------------------------------------------------
//
uint8_t LO_sys_threadIsLiveObjectsClient( void )
{
    osThreadId id = osThreadGetId();
    return (_lo_sys_thread_id ==  id) ? 1 : 0;
}

//---------------------------------------------------------------------------------
//
int LO_sys_threadStart(void const *argument)
{
    LOTRACE_DBG(" LO_sys_threadStart:  arg=x%p stacksize= %u * %u = %u bytes ...",
            argument, WORD_STACK_SIZE, sizeof(uint32_t),  WORD_STACK_SIZE * sizeof(uint32_t));

     memset(&_lo_sys_thread_def, 0, sizeof(_lo_sys_thread_def));

     _lo_sys_thread_def.pthread = _LO_sys_threadExec;
     _lo_sys_thread_def.instances = 1;
     _lo_sys_thread_def.stacksize = WORD_STACK_SIZE * sizeof(uint32_t);
     _lo_sys_thread_def.tpriority = osPriorityNormal;
     _lo_sys_thread_def.stack_pointer = &_lo_sys_thread_stack[1];

    for (uint32_t i = 0; i < (sizeof(_lo_sys_thread_stack) / sizeof(uint32_t)); i++) {
        _lo_sys_thread_stack[i] = 0xE25A2EA5;
    }

    _lo_sys_thread_id = osThreadCreate(&_lo_sys_thread_def, argument);
    if (_lo_sys_thread_id == NULL) {
        LOTRACE_ERR("Error while creating LiveObjects Client Thread ..");
        return -1;
    }

    LOTRACE_WARN("LiveObjects Client Thread x%p is running !!!", _lo_sys_thread_id);
    return 0;
}

//---------------------------------------------------------------------------------
//
void LO_sys_threadCheck( void )
{
    if (_lo_sys_thread_id) {
        if (( _lo_sys_thread_stack[0] != 0xE25A2EA5) ||
            (_lo_sys_thread_stack[WORD_STACK_SIZE+1] != 0xE25A2EA5)) {
            LOTRACE_ERR("LO_sys_threadCheck : STACK CORRUPTED !!");
            LOTRACE_ERR("LO_sys_threadCheck stack_pointer[%u] =  x%x", 0, _lo_sys_thread_stack[0]);
            LOTRACE_ERR("LO_sys_threadCheck stack_pointer[%u] =  x%x", WORD_STACK_SIZE+1, _lo_sys_thread_stack[WORD_STACK_SIZE+1]);
            return ;
        }
        if (_lo_sys_thread_max == 0) {
            LOTRACE_WARN("LO_sys_threadCheck stack_pointer[%u] =  x%x", 1, _lo_sys_thread_stack[1]);
            LOTRACE_WARN("LO_sys_threadCheck stack_pointer[%u] =  x%x", WORD_STACK_SIZE-1, _lo_sys_thread_stack[WORD_STACK_SIZE-1]);
            LOTRACE_WARN("LO_sys_threadCheck stack_pointer[%u] =  x%x", WORD_STACK_SIZE, _lo_sys_thread_stack[WORD_STACK_SIZE]);
        }
        for (uint32_t i = 1; i < (sizeof(_lo_sys_thread_stack) / sizeof(uint32_t)); i++) {
            if (_lo_sys_thread_stack[i] != 0xE25A2EA5) {
                if (i != _lo_sys_thread_max) {
                    LOTRACE_WARN("LO_sys_threadCheck free=%u used=%u/%u", i, WORD_STACK_SIZE-i, WORD_STACK_SIZE);
                    _lo_sys_thread_max = i;
                }
                break;
            }
        }
    }
}

