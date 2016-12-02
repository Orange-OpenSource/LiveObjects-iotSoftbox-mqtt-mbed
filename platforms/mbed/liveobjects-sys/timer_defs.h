/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file timer_defs.h
 * @brief Timer struct definition for MQTT client.
 *
 */

#ifndef __TIMER_DEFS_H_
#define __TIMER_DEFS_H_

#if defined(__cplusplus)
 extern "C" {
#endif

struct Timer {
    unsigned long  end_time;
};


#if defined(__cplusplus)
 }
#endif

#endif //__TIMER_DEFS_H_
