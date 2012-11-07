/*
 * Copyright (c) 2012 Neutron Soutmun
 *
 */

#ifndef _NGX_RTMP_AUTHEN_MODULE_H_INCLUDED_
#define _NGX_RTMP_AUTHEN_MODULE_H_INCLUDED_


#include "ngx_rtmp.h"


#define NGX_RTMP_AUTHEN_MAX_RESPONSE        1024


enum {
    NGX_RTMP_CONN_DENY = 0,
    NGX_RTMP_CONN_REJECT,
    NGX_RTMP_CONN_ALLOW
};


typedef struct {
    ngx_int_t    conn_status;
    ngx_str_t    conn_desc;
    ngx_str_t    user;
    ngx_str_t    authmod;
    ngx_str_t    resp;
    u_char       resp_data[NGX_RTMP_AUTHEN_MAX_RESPONSE];
} ngx_rtmp_authen_ctx_t;


extern ngx_module_t  ngx_rtmp_authen_module;


#endif /* _NGX_RTMP_AUTHEN_MODULE_H_INCLUDED_ */
