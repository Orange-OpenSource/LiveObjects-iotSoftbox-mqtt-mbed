/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_wget.h
  * @brief  Interface to get a resource using HTTP GET request
  *
  */

#ifndef __loc_wget_H_
#define __loc_wget_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

int  LO_wget_start(const char* uri, uint32_t size, uint32_t offset);

int  LO_wget_data(char* pData, int len);

void LO_wget_close(void);


#if defined(__cplusplus)
}
#endif

#endif /* __loc_wget_H_ */
