/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_NETCALL_H_INCLUDED_
#define _NGX_RTMP_NETCALL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


typedef ngx_chain_t * (*ngx_rtmp_netcall_create_pt)(ngx_rtmp_session_t *s,
        void *arg, ngx_pool_t *pool);
typedef ngx_int_t (*ngx_rtmp_netcall_handle_pt)(ngx_rtmp_session_t *s, 
        void *arg, ngx_chain_t *in);


typedef struct {
    ngx_url_t                      *url;
    ngx_rtmp_netcall_create_pt      create;
    ngx_rtmp_netcall_handle_pt      handle;
    void                           *arg;
    size_t                          argsize;
} ngx_rtmp_netcall_init_t;


ngx_int_t ngx_rtmp_netcall_create(ngx_rtmp_session_t *s, 
        ngx_rtmp_netcall_init_t *ci);


/* HTTP formatting */
ngx_chain_t * ngx_rtmp_netcall_http_format_session(ngx_rtmp_session_t *s, 
        ngx_pool_t *pool);
ngx_chain_t * ngx_rtmp_netcall_http_format_header(ngx_url_t *url, 
        ngx_pool_t *pool, size_t content_length);


#endif /* _NGX_RTMP_NETCALL_H_INCLUDED_ */
