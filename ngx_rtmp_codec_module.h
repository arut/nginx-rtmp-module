/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_CODEC_H_INCLUDED_
#define _NGX_RTMP_CODEC_H_INCLUDED_


#include "ngx_rtmp.h"


/* Audio codecs */
enum {
    /* Uncompressed codec id is actually 0,
     * but we use another value for consistency */
    NGX_RTMP_AUDIO_UNCOMPRESSED     = 16,
    NGX_RTMP_AUDIO_ADPCM            = 1,
    NGX_RTMP_AUDIO_MP3              = 2,
    NGX_RTMP_AUDIO_LINEAR_LE        = 3,
    NGX_RTMP_AUDIO_NELLY16          = 4,
    NGX_RTMP_AUDIO_NELLY8           = 5,
    NGX_RTMP_AUDIO_NELLY            = 6,
    NGX_RTMP_AUDIO_G711A            = 7,
    NGX_RTMP_AUDIO_G711U            = 8,
    NGX_RTMP_AUDIO_AAC              = 10,
    NGX_RTMP_AUDIO_SPEEX            = 11,
    NGX_RTMP_AUDIO_MP3_8            = 14,
    NGX_RTMP_AUDIO_DEVSPEC          = 15,
};


/* Video codecs */
enum {
    NGX_RTMP_VIDEO_JPEG             = 1,
    NGX_RTMP_VIDEO_SORENSON_H263    = 2,
    NGX_RTMP_VIDEO_SCREEN           = 3,
    NGX_RTMP_VIDEO_ON2_VP6          = 4,
    NGX_RTMP_VIDEO_ON2_VP6_ALPHA    = 5,
    NGX_RTMP_VIDEO_SCREEN2          = 6,
    NGX_RTMP_VIDEO_H264             = 7
};


u_char * ngx_rtmp_get_audio_codec_name(ngx_uint_t id);
u_char * ngx_rtmp_get_video_codec_name(ngx_uint_t id);


typedef struct {
    ngx_chain_t                *avc_header;
    ngx_chain_t                *aac_header;

    /* prepared headers (for live streaming) */
    ngx_chain_t                *avc_pheader;
    ngx_chain_t                *aac_pheader;
} ngx_rtmp_codec_ctx_t;


extern ngx_module_t  ngx_rtmp_codec_module;


#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
