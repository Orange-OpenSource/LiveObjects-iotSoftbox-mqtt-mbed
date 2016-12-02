/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
  * @file  LiveObjectsClient_security.h
  * @brief LiveObjects Security Definitions
  */

#ifndef __LiveObjectsClient_security_defs_H_
#define __LiveObjectsClient_security_defs_H_

/**
 * @brief Define a Security Record: type and location
 */
typedef struct {
    unsigned char  type;  ///< location type: 0= memory 1= file
    const char*    pLoc;  ///< Location: memory address or file path
} LiveObjectsSecurityRecord_t;


/**
 * @brief Define the list of user security certificates (used by TLS)
 */
typedef struct{
    LiveObjectsSecurityRecord_t  rootCA;                    ///< Root/Server Certificate
    LiveObjectsSecurityRecord_t  deviceCert;                ///< Device Certificate
    LiveObjectsSecurityRecord_t  devicePrivateKey;          ///< Device Private Key
    const char*                  rootCertificateCommonName; ///< Root Certificate Common Name
    unsigned char                serverVerificationMode;    ///< Verification Mode
} LiveObjectsSecurityParams_t;

#endif /* __LiveObjectsClient_security_defs_H_ */
