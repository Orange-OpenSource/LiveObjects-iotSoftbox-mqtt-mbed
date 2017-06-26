/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_trace.h
  * @brief  Plug LiveObjects traces onto mbed traces
  */

#ifndef __loc_trace_H_
#define __loc_trace_H_

#ifndef TRACE_GROUP
#define TRACE_GROUP "LOC"
#endif

#include "mbed-trace/mbed_trace.h"

#define LOTRACE_INIT(...)            ((void)0)
#define LOTRACE_LEVEL(...)           ((void)0)

#define LOTRACE_ERR                   tr_err
#define LOTRACE_WARN                  tr_warn
#define LOTRACE_NOTICE                tr_warn
#define LOTRACE_INF                   tr_info
#define LOTRACE_DBG                   tr_debug
#define LOTRACE_DBG1                  tr_debug
#define LOTRACE_DBG2                  tr_debug

#define LOTRACE_DBG_VERBOSE(...)      ((void)0)
//#define LOTRACE_DBG_VERBOSE           tr_info

#define LOTRACE_PRINTF                printf

#endif /* __loc_trace_H_ */
