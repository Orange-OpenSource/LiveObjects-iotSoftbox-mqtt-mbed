/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file   loc_json_api.h
  * @brief  JSON interface
  *
  */

#ifndef __loc_json_api_H_
#define __loc_json_api_H_

#include "liveobjects-client/LiveObjectsClient_Defs.h"

#if defined(__cplusplus)
extern "C" {
#endif


const char*  LO_getDataTypeToStr(LiveObjectsD_Type_t objType);

LiveObjectsD_Type_t LO_getDataTypeFromStrL(const char* p, uint32_t len);


int LO_json_begin(char *pbuf, uint32_t sz);

int LO_json_end(char *pbuf, uint32_t sz);

int LO_json_begin_section(char *pbuf, uint32_t sz, const char* name);

int LO_json_end_section(char *pbuf, uint32_t sz);

int LO_json_add_section_start(const char* section_name, char *pbuf, uint32_t sz);

int LO_json_add_section_end(char *pbuf, uint32_t sz);

int LO_json_add_name_int(const char* name, int32_t value, char *pbuf, uint32_t sz);

int LO_json_add_name_str(const char* name, const char* value, char *pbuf, uint32_t sz);

int LO_json_add_name_array(const char* name, const char* array, char *pbuf, uint32_t sz);

int LO_json_add_item(const LiveObjectsD_Data_t* p, char *pbuf, uint32_t sz);

int LO_json_add_param(const LiveObjectsD_Data_t* p, char *pbuf, uint32_t sz);

#if defined(__cplusplus)
}
#endif

#endif /* __loc_json_api_H_ */
