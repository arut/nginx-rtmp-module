
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_PLAY_H_INCLUDED_
#define _NGX_RTMP_PLAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


typedef ngx_int_t (*ngx_rtmp_play_init_pt)  (ngx_rtmp_session_t *s,
        ngx_file_t *f, ngx_int_t aindex, ngx_int_t vindex);
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


typedef struct ngx_rtmp_play_ctx_s ngx_rtmp_play_ctx_t;


struct ngx_rtmp_play_ctx_s {
    ngx_rtmp_session_t     *session;
    ngx_file_t              file;
    ngx_rtmp_play_fmt_t    *fmt;
    ngx_event_t             send_evt;
    unsigned                playing:1;
    unsigned                opened:1;
    unsigned                joined:1;
    ngx_uint_t              ncrs;
    ngx_uint_t              nheader;
    ngx_uint_t              nbody;
    size_t                  pfx_size;
    ngx_str_t               sfx;
    ngx_uint_t              file_id;
    ngx_int_t               aindex, vindex;
    ngx_uint_t              nentry;
    ngx_uint_t              post_seek;
    u_char                  name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_play_ctx_t    *next;
};


typedef struct {
    ngx_str_t              *root;
    ngx_url_t              *url;
} ngx_rtmp_play_entry_t;


typedef struct {
    ngx_str_t               temp_path;
    ngx_str_t               local_path;
    ngx_array_t             entries; /* ngx_rtmp_play_entry_t * */
    ngx_uint_t              nbuckets;
    ngx_rtmp_play_ctx_t   **ctx;
} ngx_rtmp_play_app_conf_t;


typedef struct {
    ngx_array_t             fmts; /* ngx_rtmp_play_fmt_t * */
} ngx_rtmp_play_main_conf_t;


extern ngx_module_t         ngx_rtmp_play_module;


#endif /* _NGX_RTMP_PLAY_H_INCLUDED_ */
