/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_int_t ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf);


static ngx_rtmp_module_t  ngx_rtmp_codec_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_codec_postconfiguration,       /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_codec_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_codec_module_ctx,             /* module context */
    NULL,                                   /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static const char * 
audio_codecs[] = {
    "",
    "ADPCM",
    "MP3",
    "LinearLE",
    "Nellymoser16",
    "Nellymoser8",
    "Nellymoser",
    "G711A",
    "G711U",
    "",
    "AAC",
    "Speex",
    "",
    "",
    "MP3-8K",
    "DeviceSpecific",
    "Uncompressed"
};


static const char * 
video_codecs[] = {
    "",
    "Jpeg",
    "Sorenson-H263",
    "ScreenVideo",
    "On2-VP6",
    "On2-VP6-Alpha",
    "ScreenVideo2",
    "H264",
};


u_char * 
ngx_rtmp_get_audio_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(audio_codecs) / sizeof(audio_codecs[0])
        ? audio_codecs[id]
        : "");
}


u_char * 
ngx_rtmp_get_video_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(video_codecs) / sizeof(video_codecs[0])
        ? video_codecs[id]
        : "");
}


static ngx_int_t
ngx_rtmp_codec_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_rtmp_core_srv_conf_t           *cscf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx->avc_header) {
        ngx_rtmp_free_shared_chain(cscf, ctx->avc_header);
        ctx->avc_header = NULL;
    }

    if (ctx->aac_header) {
        ngx_rtmp_free_shared_chain(cscf, ctx->aac_header);
        ctx->aac_header = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_chain_t                       **header;
    uint8_t                             fmt;
    ngx_rtmp_header_t                   ch, lh;

    /* save AVC/AAC header */
    if ((h->type != NGX_RTMP_MSG_AUDIO
        && h->type != NGX_RTMP_MSG_VIDEO)
        || in->buf->last - in->buf->pos < 2)
    {
        return NGX_OK;
    }

    /* no conf */
    if (in->buf->pos[1]) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_codec_module);
    }

    fmt =  in->buf->pos[0];
    header = NULL;
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        if (((fmt & 0xf0) >> 4) == NGX_RTMP_AUDIO_AAC) {
            header = &ctx->aac_header;
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "codec: AAC header arrived");
        }
    } else {
        if ((fmt & 0x0f) == NGX_RTMP_VIDEO_H264) {
            header = &ctx->avc_header;
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "codec: AVC/H264 header arrived");
        }
    }

    if (header == NULL) {
        return NGX_OK;
    }

    if (*header) {
        ngx_rtmp_free_shared_chain(cscf, *header);
    }

    /* equal headers; timeout diff is zero */
    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&lh, sizeof(lh));
    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_LIVE_MSID;
    ch.type = h->type;
    ch.csid = (h->type == NGX_RTMP_MSG_VIDEO
        ? NGX_RTMP_LIVE_CSID_VIDEO
        : NGX_RTMP_LIVE_CSID_AUDIO);
    lh = ch;
    *header = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    ngx_rtmp_prepare_message(s, &ch, &lh, *header);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_codec_disconnect;

    return NGX_OK;
}
