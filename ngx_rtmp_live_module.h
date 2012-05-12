/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_LIVE_H_INCLUDED_
#define _NGX_RTMP_LIVE_H_INCLUDED_


#include "ngx_rtmp.h"
#include "ngx_rtmp_bandwidth.h"


/* session flags */
#define NGX_RTMP_LIVE_PUBLISHING        0x01


typedef struct {
    ngx_uint_t                          width;
    ngx_uint_t                          height;
    ngx_uint_t                          duration;
    ngx_uint_t                          frame_rate;
    ngx_uint_t                          video_data_rate;
    ngx_uint_t                          video_codec_id;
    ngx_uint_t                          audio_data_rate;
    ngx_uint_t                          audio_codec_id;
} ngx_rtmp_live_meta_t;


typedef struct ngx_rtmp_live_ctx_s ngx_rtmp_live_ctx_t;
typedef struct ngx_rtmp_live_stream_s ngx_rtmp_live_stream_t;


struct ngx_rtmp_live_ctx_s {
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_live_stream_t             *stream;
    ngx_rtmp_live_ctx_t                *next;
    ngx_uint_t                          flags;
    ngx_uint_t                          msg_mask;
    ngx_uint_t                          dropped;
    uint32_t                            csid;
    uint32_t                            next_push;
    uint32_t                            last_audio;
    uint32_t                            last_video;
};


struct ngx_rtmp_live_stream_s {
    u_char                              name[256];
    ngx_rtmp_live_stream_t             *next;
    ngx_rtmp_live_ctx_t                *ctx;
    ngx_uint_t                          flags;
    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_out;
    ngx_rtmp_live_meta_t                meta;
};


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_rtmp_live_stream_t            **streams;
    ngx_flag_t                          live;
    ngx_msec_t                          buflen;
    ngx_pool_t                         *pool;
    ngx_rtmp_live_stream_t             *free_streams;
} ngx_rtmp_live_app_conf_t;


extern ngx_module_t  ngx_rtmp_live_module;


#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
