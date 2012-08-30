/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_RECORD_H_INCLUDED_
#define _NGX_RTMP_RECORD_H_INCLUDED_


#include "ngx_rtmp.h"


typedef struct {
    ngx_uint_t                          flags;
    ngx_str_t                           path;
    size_t                              max_size;
    size_t                              max_frames;
    ngx_msec_t                          interval;
    ngx_str_t                           suffix;
    ngx_flag_t                          unique;
    ngx_url_t                          *url;
} ngx_rtmp_record_app_conf_t;


typedef struct {
    ngx_file_t                          file;
    ngx_uint_t                          nframes;
    uint32_t                            epoch;
    ngx_time_t                          last;
    time_t                              timestamp;
    u_char                              name[NGX_RTMP_MAX_NAME];
    u_char                              args[NGX_RTMP_MAX_ARGS];
} ngx_rtmp_record_ctx_t;

 
u_char * ngx_rtmp_record_make_path(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_record_open(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_record_close(ngx_rtmp_session_t *s);


extern ngx_module_t                     ngx_rtmp_record_module;


#endif /* _NGX_RTMP_RECORD_H_INCLUDED_ */
