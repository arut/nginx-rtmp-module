/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_ROOM_H_INCLUDED_
#define _NGX_RTMP_ROOM_H_INCLUDED_


#include "ngx_rtmp.h"


typedef struct ngx_rtmp_room_ctx_s      ngx_rtmp_room_ctx_t;
typedef struct ngx_rtmp_room_s          ngx_rtmp_room_t;


struct ngx_rtmp_room_ctx_s {
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_room_t                    *room;
    ngx_rtmp_room_ctx_t                *next;
    unsigned                            weak:1;
};


struct ngx_rtmp_room_s {
    ngx_pool_t                         *pool;
    void                              **ctx;
    void                              **main_conf;
    void                              **srv_conf;
    void                              **app_conf;
    ngx_str_t                           name;
    ngx_rtmp_room_t                    *next;
    ngx_rtmp_room_ctx_t                *first_ctx;
    ngx_msec_t                          epoch;
    unsigned                            persistent:1;
};


typedef struct {
    ngx_flag_t                          active;
    ngx_int_t                           nbuckets;
    ngx_rtmp_room_t                   **rooms;
    ngx_log_t                          *log;
    ngx_rtmp_conf_ctx_t                *ctx;
    ngx_array_t                         persistent; /* ngx_str_t */
} ngx_rtmp_room_app_conf_t;


ngx_int_t ngx_rtmp_room_join(ngx_rtmp_session_t *s, ngx_str_t *name);
ngx_int_t ngx_rtmp_room_leave(ngx_rtmp_session_t *s);


typedef ngx_int_t (*ngx_rtmp_create_room_pt)(ngx_rtmp_room_t *);
typedef ngx_int_t (*ngx_rtmp_delete_room_pt)(ngx_rtmp_room_t *);
typedef ngx_int_t (*ngx_rtmp_join_room_pt)(ngx_rtmp_room_t *,
        ngx_rtmp_session_t *);
typedef ngx_int_t (*ngx_rtmp_leave_room_pt)(ngx_rtmp_room_t *,
        ngx_rtmp_session_t *);


extern ngx_rtmp_create_room_pt          ngx_rtmp_create_room;
extern ngx_rtmp_delete_room_pt          ngx_rtmp_delete_room;
extern ngx_rtmp_join_room_pt            ngx_rtmp_join_room;
extern ngx_rtmp_leave_room_pt           ngx_rtmp_leave_room;


extern ngx_module_t                     ngx_rtmp_room_module;


#endif /* _NGX_RTMP_ROOM_H_INCLUDED_ */
