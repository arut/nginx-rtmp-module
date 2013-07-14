/*
 * Copyright (c) 2013 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_NOTIFY_H_INCLUDED_
#define _NGX_RTMP_NOTIFY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


extern ngx_str_t   ngx_rtmp_notify_urlencoded;


ngx_int_t ngx_rtmp_notify_parse_http_retcode(ngx_rtmp_session_t *s,
    ngx_chain_t *in);
ngx_int_t ngx_rtmp_notify_parse_http_header(ngx_rtmp_session_t *s, 
    ngx_chain_t *in, ngx_str_t *name, u_char *data, size_t len);
ngx_url_t * ngx_rtmp_notify_parse_url(ngx_conf_t *cf, ngx_str_t *url);


#endif /* _NGX_RTMP_NOTIFY_H_INCLUDED_ */
