/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#ifndef _NGX_RTMP_CMD_H_INCLUDED_
#define _NGX_RTMP_CMD_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_rtmp.h"


/* publish types */
#define NGX_RTMP_CMD_PUBLISH_RECORD   1
#define NGX_RTMP_CMD_PUBLISH_APPEND   2
#define NGX_RTMP_CMD_PUBLISH_LIVE     3


typedef ngx_int_t (*ngx_rtmp_cmd_connect_pt)(ngx_rtmp_session_t *s);
typedef ngx_int_t (*ngx_rtmp_cmd_publish_pt)(ngx_rtmp_session_t *s,
        ngx_str_t *name, ngx_int_t type);
typedef ngx_int_t (*ngx_rtmp_cmd_play_pt)(ngx_rtmp_session_t *s,
        ngx_str_t *name, uint32_t start, uint32_t duration, ngx_int_t reset);
typedef ngx_int_t (*ngx_rtmp_cmd_close_pt)(ngx_rtmp_session_t *s);


typedef struct {
    ngx_array_t         connect;
    ngx_array_t         publish;
    ngx_array_t         play;
    ngx_array_t         close;
} ngx_rtmp_cmd_main_conf_t;


extern ngx_module_t ngx_rtmp_cmd_module;


#endif /*_NGX_RTMP_CMD_H_INCLUDED_ */
