/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_RELAY_H_INCLUDED_
#define _NGX_RTMP_RELAY_H_INCLUDED_
 

#include "ngx_rtmp.h"


typedef struct {
    ngx_url_t                       url;
    ngx_str_t                       app;
    ngx_str_t                       name;
    ngx_str_t                       tc_url;
    ngx_str_t                       page_url;
    ngx_str_t                       swf_url;
    ngx_str_t                       flash_ver;
    ngx_str_t                       play_path;
    ngx_int_t                       live;
    ngx_int_t                       start;
    ngx_int_t                       stop;
} ngx_rtmp_relay_target_t;


ngx_int_t ngx_rtmp_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
                              ngx_rtmp_relay_target_t *target);
ngx_int_t ngx_rtmp_relay_push(ngx_rtmp_session_t *s, ngx_str_t *name,
                              ngx_rtmp_relay_target_t *target);


#endif /* _NGX_RTMP_RELAY_H_INCLUDED_ */
