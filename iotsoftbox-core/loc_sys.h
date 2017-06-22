/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_sys.h
  * @brief  System Interface wrapper
  *
  */

#ifndef __loc_sys_H_
#define __loc_sys_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define LO_SYS_MUTEX_NB    2

#define MQ_MUTEX_LOCK()     LO_sys_mutex_lock(0)
#define MQ_MUTEX_UNLOCK()   LO_sys_mutex_unlock(0)

#define MSG_MUTEX_LOCK()    LO_sys_mutex_lock(1)
#define MSG_MUTEX_UNLOCK()  LO_sys_mutex_unlock(1)


void  LO_sys_init( void );

void  LO_sys_threadRun( void );

uint8_t  LO_sys_threadIsLiveObjectsClient( void );

int  LO_sys_threadStart(void const *argument);

void LO_sys_threadCheck();

uint8_t LO_sys_mutex_lock( uint8_t idx );
void    LO_sys_mutex_unlock(uint8_t idx);

void  LO_sys_mutex_unlock( uint8_t idx );

#if defined(__cplusplus)
}
#endif

#endif /* __loc_sys_H_ */
