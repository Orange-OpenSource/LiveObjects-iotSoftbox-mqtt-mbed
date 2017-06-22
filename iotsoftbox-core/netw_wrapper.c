/*
 * Copyright (C) 2016 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE.txt' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file  netw_wrapper.cp
 * @brief Network Interface.
 */

#include <stdbool.h>
#include <string.h>

#include "netw_wrapper.h"
#include "netw_sock.h"

#include "liveobjects-client/LiveObjectsClient_Config.h"

#include "liveobjects-sys/loc_trace.h"
#include "liveobjects-sys/LiveObjectsClient_Platform.h"

#if (LOC_MQTT_DUMP_MSG & 0x02)
void LOCC_mqtt_dump_msg(const unsigned char* p_buf);
#endif

#if !LOC_FEATURE_MBEDTLS

#warning "MBEDTLS DISABLED !!!"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"

#else

#define NETW_MBEDTLS_DBG   1

#include "mbedtls/config.h"

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy_poll.h"

//#include "mbedtls/timing.h"

#define MBEDTLS_VERIFY
//#define MBEDTLS_TIMER

#ifdef  MBEDTLS_TIMER
#include "paho-mqttclient-embedded-c/timer_interface.h"
#endif

#endif /* LOC_FEATURE_MBEDTLS */

static  uint8_t                  _netw_tls_enabled;

#if LOC_FEATURE_MBEDTLS
static const char*               _netw_passwd = "";

static  uint8_t                  _netw_tls_run;
static  bool                     _netw_ssl_verify = false;
static  mbedtls_ssl_config       _netw_conf;
static  mbedtls_ssl_context      _netw_ssl;
static  mbedtls_entropy_context  _netw_entropy;
static  mbedtls_ctr_drbg_context _netw_ctr_drbg;

static  mbedtls_x509_crt         _netw_cacert;
static  mbedtls_x509_crt         _netw_clicert;
static  mbedtls_pk_context       _netw_pkey;

#ifdef MBEDTLS_TIMER
static struct {
    uint8_t  timer_cancelled;
    Timer    timer_intermediate;
    Timer    timer_total;
} _netw_timer;
#endif

#endif

#if LOC_FEATURE_MBEDTLS
#define LOTRACE_MBEDTLS_ERR(err, fonc)   netw_mbedtls_err(err, __LINE__ , fonc)


//---------------------------------------------------------------------------------
//
static void netw_mbedtls_err(unsigned int ret, int line, const char* fonc)
{
    char buf[100];
    mbedtls_strerror(ret, buf, sizeof(buf));
    LOTRACE_ERR("NETWRAPPER:%d: MBEDTLS_ERR in %s()  0X%X -0X%X = '%s'", line, fonc, ret, -ret, buf);
}


//---------------------------------------------------------------------------------
//
#if defined(MBEDTLS_DEBUG_C) && (NETW_MBEDTLS_DBG > 0)
void netw_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *msg)
{
#ifdef ARDUINO
    const char* name = strrchr(file, '\\');
    if ((name) && (*name == '\\')) name++;
    else {
        name = strrchr(file, '/');
        if ((name) && (*name == '/')) name++;
        else name = file;
    }
    LOTRACE_INF("%d:%s:%d: %s", level, name, line, msg);
#else
    LOTRACE_INF("%d:%s:%d: %s", level, file, line, msg);
#endif
}
#endif

#ifdef MBEDTLS_TIMER
void f_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{

    if (data != &_netw_timer) {
        LOTRACE_ERR("f_timing_set_delay - BAD handle - intermediate: %u  final: %u", int_ms, fin_ms);
        return;
    }
    if( int_ms > 0 && fin_ms > 0 ){
        // start
        LOTRACE_INF("f_timing_set_delay - START - intermediate: %u  final: %u", int_ms, fin_ms);
        _netw_timer.timer_cancelled = 0;
        TimerCountdownMS(&_netw_timer.timer_intermediate, int_ms);
        TimerCountdownMS(&_netw_timer.timer_total, fin_ms);
    }
    else  {
        // stop
        LOTRACE_INF("f_timing_set_delay - STOP");
        _netw_timer.timer_cancelled = 1;
        TimerInit(&_netw_timer.timer_intermediate);
        TimerInit(&_netw_timer.timer_total);
    }
}

int f_timing_get_delay( void *data  )
{
    if (data != &_netw_timer) {
        LOTRACE_ERR("f_timing_get_delay: BAD handle !!");
        return 0;
    }
    if(_netw_timer.timer_cancelled) {
        LOTRACE_DBG_VERBOSE("f_timing_get_delay - ret -1 : CANCELLED");
        return -1;
    }
    if( TimerIsExpired( &_netw_timer.timer_total) ){
        LOTRACE_INF("f_timing_get_delay - ret 2");
        return 2;
    }
    if( TimerIsExpired( &_netw_timer.timer_intermediate) ){
        LOTRACE_INF("f_timing_get_delay - ret 1");
        return 1;
    }

    LOTRACE_DBG("mbedtls_timing_get_delay - ret 0");
    return 0;
}
#endif

#endif

//---------------------------------------------------------------------------------
//
void netw_disconnect(Network *pNetwork, int mode)
{
    if (f_netw_sock_isOpen(pNetwork)) {
#if LOC_FEATURE_MBEDTLS
        if (_netw_tls_run) {
            int ret;
            LOTRACE_INF("netw_disconnect: mbedtls_ssl_close_notify ...");
            do {
                ret = mbedtls_ssl_close_notify(&_netw_ssl);
            } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
            LOTRACE_INF("netw_disconnect: mbedtls_ssl_close_notify ret=%d", ret);
        }
        if (_netw_tls_enabled) {
            LOTRACE_INF("netw_disconnect: SSL RESET ...");
            mbedtls_ssl_session_reset(&_netw_ssl);
        }
#endif
        f_netw_sock_close(pNetwork);
    }
    LOTRACE_INF("netw_disconnect: RESET");
#if LOC_FEATURE_MBEDTLS
    _netw_tls_run = 0;
#endif
}

//---------------------------------------------------------------------------------
//
unsigned char netw_isLost(Network *pNetwork)
{
    if (pNetwork)  {
        return f_netw_sock_isLost( pNetwork );
    }
    return 0;
}

//---------------------------------------------------------------------------------
//
int netw_mqtt_write(Network *pNetwork, unsigned char *pMsg, int len, int timeout_ms)
{
    int written = 0;
    LOTRACE_DBG("netw_mqtt_write(%p/%p, len=%d,timeout_ms=%d, tsl=%d) ...", pNetwork, pNetwork->my_socket, len, timeout_ms, _netw_tls_enabled);

#if (LOC_MQTT_DUMP_MSG & 0x02)
    LOCC_mqtt_dump_msg(pMsg);
#endif

    if (_netw_tls_enabled) {
#if LOC_FEATURE_MBEDTLS
        int frags;
        int ret;
        for (written = 0, frags = 0; written < len; written += ret, frags++) {
            while ((ret = mbedtls_ssl_write(&_netw_ssl, pMsg + written, len - written)) <= 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_write");
                    return ret;
                }
                LOTRACE_DBG("netw_mqtt_write(%d): ret=%d  -> continue, frags=%d ...", len, ret, frags);
            }
        }
#else
        LOTRACE_ERR("Error while writting bytes: TLS required but not supported");
        written = -1;
#endif
    }
    else {
        written = f_netw_sock_send(pNetwork, pMsg, len);
        if(written < 0){
            LOTRACE_ERR("netw_mqtt_write(len=%d,timeout_ms=%d) ERROR %d", len, timeout_ms, written);
            return written;
        }
    }
    LOTRACE_DBG("netw_mqtt_write(len=%d,timeout_ms=%d) -> written=%d", len, timeout_ms, written);
    return written;
}


//---------------------------------------------------------------------------------
//
int netw_mqtt_read(Network *pNetwork, unsigned char *pMsg, int len, int timeout_ms)
{
    int ret = -1;

    //LOTRACE_DBG_VERBOSE("netw_mqtt_read(%p/%p, len=%d,timeout_ms=%d, tsl=%d) ...",  pNetwork, pNetwork->my_socket, len, timeout_ms, _netw_tls_enabled);

    if (_netw_tls_enabled) {
#if LOC_FEATURE_MBEDTLS
        int rxLen = 0;
        bool isErrorFlag = false;
        bool isCompleteFlag = false;

        if (timeout_ms >= 0)
            mbedtls_ssl_conf_read_timeout(&_netw_conf, timeout_ms);

        LOTRACE_DBG_VERBOSE("netw_mqtt_read(len=%d,timeout_ms=%d) ...",  len, timeout_ms);

        do {
            ret = mbedtls_ssl_read(&_netw_ssl, pMsg, len);
            if (ret > 0) {
                rxLen += ret;
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                LOTRACE_DBG_VERBOSE("netw_mqtt_read(len=%d,timeout_ms=%d) - ret=x%X = MBEDTLS_ERR_SSL_WANT_READ",  len, timeout_ms, ret);
                isErrorFlag = true;
            } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                LOTRACE_DBG_VERBOSE("netw_mqtt_read(len=%d,timeout_ms=%d) - ret=x%X = MBEDTLS_ERR_SSL_TIMEOUT",  len, timeout_ms, ret);
                isErrorFlag = true;
            }
            else {
                LOTRACE_DBG("netw_mqtt_read(len=%d,timeout_ms=%d) - ret= x%X",  len, timeout_ms, ret);
                LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_read");
                isErrorFlag = true;
            }
            if (rxLen >= len) {
                isCompleteFlag = true;
            }
        } while (!isErrorFlag && !isCompleteFlag);

#else
        LOTRACE_ERR("Error while reading bytes: TLS required but not supported");
        ret = -1;
#endif
    }
    else {
        ret= f_netw_sock_recv_timeout(pNetwork, pMsg, len, timeout_ms);
        if(ret < 0){
             if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_TIMEOUT))
                LOTRACE_ERR("f_netw_sock_recv_timeout(len=%d) -> ERROR %d x%x", len, ret, ret);
             return ret;
         }
    }

    LOTRACE_DBG_VERBOSE("netw_mqtt_read(len=%d,timeout_ms=%d) ret=%d", len, timeout_ms, ret);

    return ret;
}

//---------------------------------------------------------------------------------
//
#if 0
void netw_mqtt_disconnect(Network *pNetwork)
{
#if LOC_FEATURE_MBEDTLS
    int ret;
    do {
        ret = mbedtls_ssl_close_notify(&_netw_ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
#endif
}
#endif

//---------------------------------------------------------------------------------
//
#if LOC_FEATURE_MBEDTLS
/*
 * This is a function to do further verification if needed on the cert received
 */
#ifdef MBEDTLS_VERIFY
static int myCertVerify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *ssl_flags) {
    char buf[1024];
    ((void) data);

    LOTRACE_DBG_VERBOSE("===> Verify requested for (Depth %d) (ssl_flags(x%p)=0X%X):",
            depth, ssl_flags, (ssl_flags) ? *ssl_flags  : 0);

    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);

    LOTRACE_DBG_VERBOSE("%s", buf);

    if ((*ssl_flags) == 0) {
        LOTRACE_INF(" -> No verification issue for this certificate");
    } else {
        mbedtls_x509_crt_verify_info(buf, sizeof (buf), "  ! ", *ssl_flags);
        LOTRACE_DBG_VERBOSE("  -> (ssl_flags=0X%X):\n%s", *ssl_flags, buf);
        if (*ssl_flags & 0x010000) {
            // ! The certificate is signed with an unacceptable key (eg bad curve, RSA too short).
            *ssl_flags &= ~0x010000;
        }
        if (*ssl_flags & 0x08) {
            // ! The certificate is not correctly signed by the trusted CA
            *ssl_flags &= ~0x08;;
        }
        if (*ssl_flags) {
            LOTRACE_ERR("ERROR - 0x%x", *ssl_flags);
            // ! The certificate Common Name (CN) does not match with the expected CN
            if (*ssl_flags & 0x04)  LOTRACE_ERR("ERROR - UNEXPECTED CERTIFICATE COMMON NAME");
            return -1;
        }
    }
    return (0);
}
#endif

#endif

//---------------------------------------------------------------------------------
//
int netw_init(Network *pNetwork,  void* net_iface_handler)
{
#if LOC_FEATURE_MBEDTLS
    int ret;
    const char *pers = "lom_tls_wrapper";
#endif

    LOTRACE_DBG("netw_init(%p,%p)", pNetwork, net_iface_handler);

    f_netw_sock_init(pNetwork, net_iface_handler);

    _netw_tls_enabled = 0;

#if LOC_FEATURE_MBEDTLS
    _netw_tls_run = 0;
    _netw_ssl_verify = false;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(0);
#endif

    mbedtls_ssl_init(&_netw_ssl);
    mbedtls_ssl_config_init(&_netw_conf);
    mbedtls_x509_crt_init(&_netw_cacert);
    mbedtls_x509_crt_init(&_netw_clicert);
    mbedtls_pk_init(&_netw_pkey);

    mbedtls_ctr_drbg_init(&_netw_ctr_drbg);
    mbedtls_entropy_init(&_netw_entropy);

#if defined(MBEDTLS_DEBUG_C) && (NETW_MBEDTLS_DBG > 0)
    mbedtls_debug_set_threshold(NETW_MBEDTLS_DBG);
    LOTRACE_INF("netw_init: SET DEBUG %p !!!", netw_mbedtls_debug);
    mbedtls_ssl_conf_dbg(&_netw_conf, netw_mbedtls_debug, &_netw_conf);
#endif

    ret = mbedtls_ctr_drbg_seed(&_netw_ctr_drbg, mbedtls_entropy_func, &_netw_entropy,
            (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ctr_drbg_seed");
        return -1;
    }
#endif // LOC_FEATURE_MBEDTLS

    LOTRACE_DBG("netw_init: OK");

    if (pNetwork) {
        pNetwork->my_socket = SOCKETHANDLE_NULL;
        pNetwork->mqttread = netw_mqtt_read;
        pNetwork->mqttwrite = netw_mqtt_write;
        //pNetwork->disconnect = netw_mqtt_disconnect;
    }

    return 0;
}


//---------------------------------------------------------------------------------
//
int netw_setSecurity(Network *pNetwork, const LiveObjectsSecurityParams_t* params)
{
#if LOC_FEATURE_MBEDTLS
    int ret;

    if (params->rootCA.pLoc) {
        LOTRACE_DBG("Loading the CA Certificate ...");
        if (!params->rootCA.type) {
            ret = mbedtls_x509_crt_parse( &_netw_cacert, (const unsigned char*) params->rootCA.pLoc,  strlen(params->rootCA.pLoc)+1);
        }
        else {
#if defined(MBEDTLS_FS_IO)
            ret = mbedtls_x509_crt_parse_file(&_netw_cacert,  params->rootCA.pLoc);
#else
            LOTRACE_ERR("mbedtls_x509_crt_parse_file (CA Certificate): NOT SUPPORTED !");
            return -1;
#endif
        }
        if (ret < 0) {
            LOTRACE_MBEDTLS_ERR(ret,"mbedtls_x509_crt_parse (CA Certificate)");
            return ret;
        }
        LOTRACE_INF("CA Certificate loaded: OK");
    }
    else LOTRACE_DBG("No CA Certificate");

    if ((params->deviceCert.pLoc) && (params->devicePrivateKey.pLoc)) {
        LOTRACE_DBG("Loading the Client Certificate ...");
        if (!params->deviceCert.type) {
            ret = mbedtls_x509_crt_parse( &_netw_clicert, (const unsigned char*) params->deviceCert.pLoc,  strlen(params->deviceCert.pLoc)+1);
        }
        else {
#if defined(MBEDTLS_FS_IO)
            ret = mbedtls_x509_crt_parse_file(&_netw_clicert, params->deviceCert.pLoc);
#else
            LOTRACE_ERR("mbedtls_x509_crt_parse_file (Client Certificate): NOT SUPPORTED !");
            return -1;
#endif
        }
        if (ret != 0) {
            LOTRACE_MBEDTLS_ERR(ret,"mbedtls_x509_crt_parse (Client Certificate)");
            return ret;
        }
        LOTRACE_INF("Client Certificate loaded: OK");

        LOTRACE_DBG("Loading the Client Key...");
        if (!params->devicePrivateKey.type) {
            ret = mbedtls_pk_parse_key( &_netw_pkey, (const unsigned char*) params->devicePrivateKey.pLoc,  strlen(params->devicePrivateKey.pLoc)+1,
                    (const unsigned char*) _netw_passwd, strlen(_netw_passwd));

        }
        else {
#if defined(MBEDTLS_FS_IO)
            ret = mbedtls_pk_parse_keyfile(&_netw_pkey,  params->devicePrivateKey.pLoc, _netw_passwd);
#else
            LOTRACE_ERR("mbedtls_pk_parse_keyfile (Private Key): NOT SUPPORTED !");
            return -1;
#endif
        }
        if (ret != 0) {
            LOTRACE_MBEDTLS_ERR(ret,"mbedtls_pk_parse_key (Private Key)");
            return ret;
        }
        LOTRACE_INF("Client Key loaded: OK");
    }
    LOTRACE_DBG("Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&_netw_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_config_defaults");
        return ret;
    }

#ifdef MBEDTLS_VERIFY
    _netw_ssl_verify = true;

    mbedtls_ssl_conf_verify(&_netw_conf, myCertVerify, NULL);
#if 0
    if (params->ServerVerificationMode) {
        mbedtls_ssl_conf_authmode(&_netw_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else
#endif
    {
        mbedtls_ssl_conf_authmode(&_netw_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
#else
    _netw_ssl_verify = false;
    mbedtls_ssl_conf_authmode(&_netw_conf, MBEDTLS_SSL_VERIFY_NONE);
#endif

    mbedtls_ssl_conf_rng(&_netw_conf, mbedtls_ctr_drbg_random, &_netw_ctr_drbg);

#if 1
    mbedtls_ssl_conf_ca_chain(&_netw_conf, &_netw_cacert, NULL);
#endif

#if 1
    if ((_netw_ssl_verify) && (params->deviceCert.pLoc) && (params->devicePrivateKey.pLoc)) {
        if (0 != (ret = mbedtls_ssl_conf_own_cert(&_netw_conf, &_netw_clicert, &_netw_pkey))) {
            LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_conf_own_cert");
            return ret;
        }
    }
#endif

    if ((ret = mbedtls_ssl_setup(&_netw_ssl, &_netw_conf)) != 0) {
        LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_setup");
        return ret;
    }

    if ((params->rootCertificateCommonName) && (*params->rootCertificateCommonName)) {
        if ((ret = mbedtls_ssl_set_hostname(&_netw_ssl, params->rootCertificateCommonName)) != 0) {
            LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_set_hostname");
            return ret;
        }
    }

    _netw_tls_enabled = 1;

    return 0;
#else // LOC_FEATURE_MBEDTLS
    _netw_tls_enabled = 0;
    return -1;
#endif // LOC_FEATURE_MBEDTLS
}

//---------------------------------------------------------------------------------
//
int netw_connect(Network* pNetwork, LiveObjectsNetConnectParams_t* params)
{
    int ret;
    LOTRACE_INF("Connecting to server %s:%d tmo=%u ...",
            params->RemoteHostAddress , params->RemoteHostPort, params->TimeoutMs);

    if (f_netw_sock_isOpen(pNetwork)) {
        netw_disconnect(pNetwork, 0);
    }
#if LOC_FEATURE_MBEDTLS
    _netw_tls_run = 0;
#endif
    ret = f_netw_sock_connect(pNetwork, params->RemoteHostAddress, params->RemoteHostPort, params->TimeoutMs);
    if (ret) {
        LOTRACE_ERR("Failed to create TCP socket");
        return -1;
    }
    LOTRACE_INF("Connected to server %s:%d OK", params->RemoteHostAddress, params->RemoteHostPort);

    ret = 0;
#if LOC_FEATURE_MBEDTLS
    if (_netw_tls_enabled)
    {
        LOTRACE_INF("Set SSL/TLS ...");

        //mbedtls_ssl_conf_read_timeout(&conf, params.timeout_ms);
        mbedtls_ssl_conf_read_timeout(&_netw_conf, 30000);

#ifdef MBEDTLS_TIMER
        mbedtls_ssl_conf_handshake_timeout( &_netw_conf, 10000, 29000 );
#endif

        mbedtls_ssl_conf_rng( &_netw_conf, mbedtls_ctr_drbg_random, &_netw_ctr_drbg );

#if 0
        if ((ret = mbedtls_ssl_set_hostname(&_netw_ssl, params->RemoteHostName)) != 0) {
            LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_set_hostname");
            netw_disconnect(pNetwork, 0);
            return ret;
        }
#endif

        if ((ret = mbedtls_ssl_setup(&_netw_ssl, &_netw_conf)) != 0) {
            LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_setup");
            netw_disconnect(pNetwork, 0);
            return ret;
        }

        mbedtls_ssl_set_bio( &_netw_ssl, (void*)pNetwork,
                f_netw_sock_send, f_netw_sock_recv, f_netw_sock_recv_timeout );

#ifdef MBEDTLS_TIMER
        LOTRACE_INF("Set timer callbacks ...");
        mbedtls_ssl_set_timer_cb( &_netw_ssl, &_netw_timer, f_timing_set_delay,  f_timing_get_delay );
#endif

        LOTRACE_INF("Performing the SSL/TLS handshake...");
        while ((ret = mbedtls_ssl_handshake(&_netw_ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                LOTRACE_MBEDTLS_ERR(ret, "mbedtls_ssl_handshake");
                netw_disconnect(pNetwork, 0);
                return ret;
            }
        }
        LOTRACE_INF(" SSL/TLS handshake: OK");

        LOTRACE_DBG("[ Protocol is %s ]", mbedtls_ssl_get_version(&_netw_ssl));
        LOTRACE_DBG("[ Ciphersuite is %s ]",  mbedtls_ssl_get_ciphersuite(&_netw_ssl));
        if ((ret = mbedtls_ssl_get_record_expansion(&_netw_ssl)) >= 0) {
            LOTRACE_DBG("[ Record expansion is %d ]", ret);
        } else {
            LOTRACE_DBG("[ Record expansion is unknown (compression) ]");
        }

        ret = 0;
        if (_netw_ssl_verify) {
            uint32_t ssl_flags;
            LOTRACE_INF("Verifying peer X.509 Certificate...");
            if (0 != (ssl_flags = mbedtls_ssl_get_verify_result(&_netw_ssl))) {
                char vrfy_buf[512];
                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", ssl_flags);
                LOTRACE_WARN("failed ssl_flags=0X%X\n%s", ssl_flags, vrfy_buf);
                netw_disconnect(pNetwork, 0);
                return -1;
            }
            else LOTRACE_INF("Certificate Verification: OK");
        }
        else LOTRACE_INF("peer X.509 Certificate Verification skipped");

        _netw_tls_run = 1;
    }
#endif // LOC_FEATURE_MBEDTLS

    f_netw_sock_setup(pNetwork);

    return ret;
}

//---------------------------------------------------------------------------------
//
int netw_tls_destroy(Network *pNetwork)
{
#if LOC_FEATURE_MBEDTLS
    mbedtls_x509_crt_free(&_netw_clicert);
    mbedtls_x509_crt_free(&_netw_cacert);
    mbedtls_pk_free(&_netw_pkey);
    mbedtls_ssl_free(&_netw_ssl);
    mbedtls_ssl_config_free(&_netw_conf);
    mbedtls_ctr_drbg_free(&_netw_ctr_drbg);
    mbedtls_entropy_free(&_netw_entropy);
#endif // LOC_FEATURE_MBEDTLS
    return 0;
}
