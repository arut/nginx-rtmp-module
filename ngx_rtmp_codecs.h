/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_CODECS_H_INCLUDED_
#define _NGX_RTMP_CODECS_H_INCLUDED_


#include <ngx_core.h>


/* Audio codecs */
enum {
    NGX_RTMP_AUDIO_UNCOMPRESSED     = 0,
    NGX_RTMP_AUDIO_ADPCM            = 1,
    NGX_RTMP_AUDIO_MP3              = 2,
    NGX_RTMP_AUDIO_NELLY8           = 5,
    NGX_RTMP_AUDIO_NELLY            = 6,
    NGX_RTMP_AUDIO_HE_ACC           = 10,
    NGX_RTMP_AUDIO_SPEEX            = 11
};


/* Video codecs */
enum {
    NGX_RTMP_VIDEO_SORENSON_H263    = 2,
    NGX_RTMP_VIDEO_SCREEN           = 3,
    NGX_RTMP_VIDEO_ON2_VP6          = 4,
    NGX_RTMP_VIDEO_ON2_VP6_ALPHA    = 5,
    NGX_RTMP_VIDEO_H264             = 7
};


u_char * ngx_rtmp_get_audio_codec_name(ngx_uint_t id);
u_char * ngx_rtmp_get_video_codec_name(ngx_uint_t id);


#endif /* _NGX_RTMP_CODECS_H_INCLUDED_ */

