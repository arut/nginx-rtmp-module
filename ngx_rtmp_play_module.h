/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_PLAY_H_INCLUDED_
#define _NGX_RTMP_PLAY_H_INCLUDED_


#include "ngx_rtmp.h"


typedef ngx_int_t (*ngx_rtmp_play_init_pt)  (ngx_rtmp_session_t *s, 
        ngx_file_t *f);
typedef ngx_int_t (*ngx_rtmp_play_done_pt)  (ngx_rtmp_session_t *s,
        ngx_file_t *f);
typedef ngx_int_t (*ngx_rtmp_play_start_pt) (ngx_rtmp_session_t *s, 
        ngx_file_t *f);
typedef ngx_int_t (*ngx_rtmp_play_seek_pt)  (ngx_rtmp_session_t *s, 
        ngx_file_t *f, ngx_uint_t offs);
typedef ngx_int_t (*ngx_rtmp_play_stop_pt)  (ngx_rtmp_session_t *s,
        ngx_file_t *f);
typedef ngx_int_t (*ngx_rtmp_play_send_pt)  (ngx_rtmp_session_t *s,
        ngx_file_t *f, ngx_uint_t *ts);


typedef struct {
    ngx_str_t               name;
    ngx_str_t               pfx;
    ngx_str_t               sfx;

    ngx_rtmp_play_init_pt   init;
    ngx_rtmp_play_done_pt   done;
    ngx_rtmp_play_start_pt  start;
    ngx_rtmp_play_seek_pt   seek;
    ngx_rtmp_play_stop_pt   stop;
    ngx_rtmp_play_send_pt   send;
} ngx_rtmp_play_fmt_t;


typedef struct {
    ngx_file_t              file;
    ngx_rtmp_play_fmt_t    *fmt;
    ngx_event_t             send_evt;
    unsigned                playing:1;
    ngx_uint_t              ncrs;
    ngx_str_t               name;
} ngx_rtmp_play_ctx_t;


typedef struct {
    ngx_str_t               root;
    ngx_str_t               temp_path;
    ngx_url_t              *url;
} ngx_rtmp_play_app_conf_t;


typedef struct {
    ngx_array_t             fmts; /* ngx_rtmp_play_fmt_t * */
} ngx_rtmp_play_main_conf_t;


extern ngx_module_t         ngx_rtmp_play_module;


#endif /* _NGX_RTMP_PLAY_H_INCLUDED_ */
