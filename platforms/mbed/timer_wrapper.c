/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file  timer_wrapper.c
 * @brief Timer Interface (used by MQTT library)
 */

//#define TIMER_DEBUG
#ifdef TIMER_DEBUG
#include <stdio.h>
#endif


#include "paho-mqttclient-c/timer_interface.h"

#include "liveobjects-sys/LiveObjectsClient_Platform.h"

#define GET_TIME_MS  rt_time_get()


unsigned int rt_time_get (void);


void TimerInit(Timer* timer)
{
    timer->end_time = 0 ;
}

char TimerIsExpired(Timer* timer)
{
    char expired;
    unsigned long now = GET_TIME_MS;
    expired = ((timer->end_time) && (timer->end_time < now)) ? 1 : 0;
#ifdef TIMER_DEBUG
    if (expired) printf("T%p: TimerIsExpired  %lu < %lu)\n", timer, timer->end_time,  now);
#endif
    return expired;
}


void TimerCountdownMS(Timer* timer, unsigned int timeout)
{
    unsigned long now = GET_TIME_MS;
    timer->end_time = now + timeout;
#ifdef TIMER_DEBUG
    printf("T%p: TimerCountdownMS %u ms (%lu -> %lu)\n", timer, timeout, now,  timer->end_time);
#endif
}


void TimerCountdown(Timer* timer, unsigned int timeout)
{
    unsigned long now = GET_TIME_MS;
    timer->end_time = now + timeout * 1000;
#ifdef TIMER_DEBUG
    printf("T%p: TimerCountdown %u s (%lu  -> %lu)\n", timer, timeout, now, timer->end_time);
#endif
}


int TimerLeftMS(Timer* timer)
{
    unsigned long now = GET_TIME_MS;
    long left = timer->end_time - now;
#ifdef TIMER_DEBUG_1
    printf("T%p: TimerLeftMS %ld ms (%lu %lu)\n", timer, left, timer->end_time, now);
#endif
    return (left <= 0) ? 0 : left;
}
