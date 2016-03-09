
/*
 * RTMPS supporting module
 * Copyright (C) Ilya Panfilov
 */

#ifndef _NGX_RTMP_SSL_MODULE_H_
#define _NGX_RTMP_SSL_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

typedef struct {
    ngx_flag_t                      enable;

    ngx_ssl_t                       ssl;

    ngx_uint_t                      protocols;

    ngx_str_t                       certificate;
    ngx_str_t                       certificate_key;
    ngx_str_t                       password_file;

    ngx_str_t                       ciphers;
    ngx_flag_t                      prefer_server_ciphers;

    ngx_str_t                       dhparam;
    ngx_str_t                       ecdh_curve;
} ngx_rtmp_ssl_srv_conf_t;

ngx_int_t ngx_rtmp_ssl_enable(ngx_conf_t *cf);
void ngx_rtmp_ssl_handshake(ngx_rtmp_session_t *c);


#endif /* _NGX_RTMP_SSL_MODULE_H_ */
