/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_CMD_H_INCLUDED_
#define _NGX_RTMP_CMD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_MAX_APP            128
#define NGX_RTMP_MAX_NAME           256
#define NGX_RTMP_MAX_URL            256


/* Basic RTMP call support */

typedef struct {
    double                          trans;
    u_char                          app[NGX_RTMP_MAX_APP];
    u_char                          flashver[32];
    u_char                          swf_url[NGX_RTMP_MAX_URL];
    u_char                          tc_url[NGX_RTMP_MAX_URL];
    double                          acodecs;
    double                          vcodecs;
    u_char                          page_url[NGX_RTMP_MAX_URL];
    double                          object_encoding;
} ngx_rtmp_connect_t;


typedef struct {
    double                          trans;
    double                          stream;
} ngx_rtmp_create_stream_t;


typedef struct {
    double                          stream;
} ngx_rtmp_delete_stream_t;


typedef struct {
    u_char                          name[NGX_RTMP_MAX_NAME];
    u_char                          type[16];
    int                             silent;
} ngx_rtmp_publish_t;


typedef struct {
    u_char                          name[NGX_RTMP_MAX_NAME];
} ngx_rtmp_fcpublish_t;


typedef ngx_rtmp_fcpublish_t ngx_rtmp_fcunpublish_t;
typedef ngx_rtmp_fcpublish_t ngx_rtmp_fcsubscribe_t;
typedef ngx_rtmp_fcpublish_t ngx_rtmp_fcunsubscribe_t;


typedef struct {
    u_char                          name[NGX_RTMP_MAX_NAME];
    double                          start;
    double                          duration;
    int                             reset;
    int                             silent;
} ngx_rtmp_play_t;


typedef ngx_int_t (*ngx_rtmp_connect_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_connect_t *v);
typedef ngx_int_t (*ngx_rtmp_create_stream_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_create_stream_t *v);
typedef ngx_int_t (*ngx_rtmp_delete_stream_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_delete_stream_t *v);

typedef ngx_int_t (*ngx_rtmp_publish_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_publish_t *v);
typedef ngx_int_t (*ngx_rtmp_fcpublish_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_fcpublish_t *v);
typedef ngx_int_t (*ngx_rtmp_fcunpublish_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_fcunpublish_t *v);

typedef ngx_int_t (*ngx_rtmp_play_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_play_t *v);
typedef ngx_int_t (*ngx_rtmp_fcsubscribe_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_fcsubscribe_t *v);
typedef ngx_int_t (*ngx_rtmp_fcunsubscribe_pt)(ngx_rtmp_session_t *s, 
        ngx_rtmp_fcunsubscribe_t *v);


extern ngx_rtmp_connect_pt          ngx_rtmp_connect;
extern ngx_rtmp_create_stream_pt    ngx_rtmp_create_stream;
extern ngx_rtmp_delete_stream_pt    ngx_rtmp_delete_stream;

extern ngx_rtmp_publish_pt          ngx_rtmp_publish;
extern ngx_rtmp_fcpublish_pt        ngx_rtmp_fcpublish;
extern ngx_rtmp_fcunpublish_pt      ngx_rtmp_fcunpublish;

extern ngx_rtmp_play_pt             ngx_rtmp_play;
extern ngx_rtmp_fcsubscribe_pt      ngx_rtmp_fcsubscribe;
extern ngx_rtmp_fcunsubscribe_pt    ngx_rtmp_fcunsubscribe;


#endif /*_NGX_RTMP_CMD_H_INCLUDED_ */
