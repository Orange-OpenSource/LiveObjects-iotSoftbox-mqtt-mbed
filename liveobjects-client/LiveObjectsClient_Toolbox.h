/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  LiveObjectClient_Toolbox.h
  * @brief toolbox
  */

#ifndef __LiveObjectClient_toolbox_H_
#define __LiveObjectClient_toolbox_H_


#include <stdint.h>


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Initialize LiveObjects Toolbox
 */
void   LiveObjectsClient_ToolboxInit(void);


/**
 * @brief Get the date/time in string format "<YYYY>-<MM>-<DD>T<HH>:<MM>:<SS>Z".
 *
 * @param str Pointer to user buffer
 * @param sz  Size of this buffer (at least 20 bytes)
 *
 */
int32_t tbx_GetDateTimeStr(char* str, uint32_t sz);


#if defined(__cplusplus)
}
#endif

#endif /* __LiveObjectClient_toolbox_H_ */
