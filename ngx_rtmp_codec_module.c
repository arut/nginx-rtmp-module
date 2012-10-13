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


static ngx_uint_t
ngx_rtmp_codec_get_next_version()
{
    ngx_uint_t          v;
    static ngx_uint_t   version;

    do {
        v = ++version;
    } while (v == 0);

    return v;
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

    if (ctx->avc_pheader) {
        ngx_rtmp_free_shared_chain(cscf, ctx->avc_pheader);
        ctx->avc_pheader = NULL;
    }

    if (ctx->aac_pheader) {
        ngx_rtmp_free_shared_chain(cscf, ctx->aac_pheader);
        ctx->aac_pheader = NULL;
    }

    if (ctx->meta) {
        ngx_rtmp_free_shared_chain(cscf, ctx->meta);
        ctx->meta = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_chain_t                       **header, **pheader;
    uint8_t                             fmt;
    ngx_rtmp_header_t                   ch, lh;
    ngx_uint_t                         *version, idx;
    u_char                             *p;
    static ngx_uint_t                   sample_rates[] = 
                                        { 5512, 11025, 22050, 44100 };

    static ngx_uint_t                   aac_sample_rates[] = 
                                        { 96000, 88200, 64000, 48000,
                                          44100, 32000, 24000, 22050,
                                          16000, 12000, 11025,  8000,
                                           7350,     0,     0,    0 };

    if (h->type != NGX_RTMP_MSG_AUDIO && h->type != NGX_RTMP_MSG_VIDEO) {
        return NGX_OK;
    }
  
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_codec_module);
    }

    /* save codec */
    if (in->buf->last - in->buf->pos < 1) {
        return NGX_OK;
    }

    fmt =  in->buf->pos[0];
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_codec_id = (fmt & 0xf0) >> 4;
        ctx->audio_channels = (fmt & 0x01) + 1;
        ctx->sample_size = (fmt & 0x02) ? 2 : 1;

        if (ctx->aac_sample_rate == 0) {
            ctx->sample_rate = sample_rates[(fmt & 0x0c) >> 2];
        }
    } else {
        ctx->video_codec_id = (fmt & 0x0f);
    }

    /* save AVC/AAC header */
    if (in->buf->last - in->buf->pos < 2) {
        return NGX_OK;
    }

    /* no conf */
    if (in->buf->pos[1]) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    header = NULL;
    pheader = NULL;
    version = NULL;
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        if (ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC) {
            header = &ctx->aac_header;
            pheader = &ctx->aac_pheader;
            version = &ctx->aac_version;
            
            if (in->buf->last - in->buf->pos > 3) {
                p = in->buf->pos + 2;

                /* MPEG-4 Audio Specific Config

                   5 bits: object type
                   if (object type == 31)
                   6 bits + 32: object type
               --->4 bits: frequency index
                   if (frequency index == 15)
                   24 bits: frequency
                   4 bits: channel configuration
                   var bits: AOT Specific Config
                 */

                if ((p[0] >> 3) == 0x1f) {
                    idx = (p[1] >> 1) & 0x0f;
                } else {
                    idx = ((p[0] << 1) & 0x0f) | (p[1] >> 7);
                }

#ifdef NGX_DEBUG
                {
                    u_char buf[256], *p, *pp;
                    u_char hex[] = "01234567890abcdef";

                    for (pp = buf, p = in->buf->pos;
                         p < in->buf->last && pp < buf + sizeof(buf) - 1;
                         ++p)
                    {
                        *pp++ = hex[*p >> 4];
                        *pp++ = hex[*p & 0x0f];
                    }

                    *pp = 0;

                    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                            "codec: AAC header: %s", buf);
                }
#endif

                ctx->aac_sample_rate = aac_sample_rates[idx];
                ctx->sample_rate = ctx->aac_sample_rate;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "codec: AAC header arrived, sample_rate=%ui", 
                           ctx->aac_sample_rate);
        }
    } else {
        if (ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            header = &ctx->avc_header;
            pheader = &ctx->avc_pheader;
            version = &ctx->avc_version;
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

    if (*pheader) {
        ngx_rtmp_free_shared_chain(cscf, *pheader);
    }

    /* equal headers; timeout diff is zero */
    ngx_memzero(&ch, sizeof(ch));
    ch.msid = NGX_RTMP_LIVE_MSID;
    ch.type = h->type;
    ch.csid = (h->type == NGX_RTMP_MSG_VIDEO
        ? NGX_RTMP_LIVE_CSID_VIDEO
        : NGX_RTMP_LIVE_CSID_AUDIO);
    lh = ch;
    *header = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    *pheader = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    ngx_rtmp_prepare_message(s, &ch, &lh, *pheader);

    /* don't want zero as version value */
    *version = ngx_rtmp_codec_get_next_version();

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_update_meta(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_int_t                       rc;
    ngx_rtmp_header_t               h;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id;
        double                      audio_data_rate;
        double                      audio_codec_id;
        u_char                      profile[32];
        u_char                      level[32];
    }                               v;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("Server"),
          "NGINX RTMP (github.com/arut/nginx-rtmp-module)", 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("displayWidth"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("displayHeight"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("videocodecid"),
          &v.video_codec_id, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("audiocodecid"),
          &v.audio_codec_id, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          "onMetaData", 0 },

        { NGX_RTMP_AMF_OBJECT, 
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx->meta) {
        ngx_rtmp_free_shared_chain(cscf, ctx->meta);
        ctx->meta = NULL;
    }

    v.width = ctx->width;
    v.height = ctx->height;
    v.duration = ctx->duration;
    v.frame_rate = ctx->frame_rate;
    v.video_data_rate = ctx->video_data_rate;
    v.video_codec_id = ctx->video_codec_id;
    v.audio_data_rate = ctx->audio_data_rate;
    v.audio_codec_id = ctx->audio_codec_id;
    ngx_memcpy(v.profile, ctx->profile, sizeof(ctx->profile));
    ngx_memcpy(v.level, ctx->level, sizeof(ctx->level));

    rc = ngx_rtmp_append_amf(s, &ctx->meta, NULL, out_elts, 
                             sizeof(out_elts) / sizeof(out_elts[0]));
    if (rc != NGX_OK || ctx->meta == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_LIVE_CSID_META;
    h.msid = NGX_RTMP_LIVE_MSID;
    h.type = NGX_RTMP_MSG_AMF_META;
    ngx_rtmp_prepare_message(s, &h, NULL, ctx->meta);

    ctx->meta_version = ngx_rtmp_codec_get_next_version();

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_codec_meta_data(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_uint_t                      skip;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id_n;
        u_char                      video_codec_id_s[32];
        double                      audio_data_rate;
        double                      audio_codec_id_n;
        u_char                      audio_codec_id_s[32];
        u_char                      profile[32];
        u_char                      level[32];
    }                               v;

    static ngx_rtmp_amf_elt_t       in_video_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.video_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.video_codec_id_s, sizeof(v.video_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_audio_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.audio_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.audio_codec_id_s, sizeof(v.audio_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_inf[] = {

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT, 
          ngx_string("videocodecid"),
          in_video_codec_id, sizeof(in_video_codec_id) },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT, 
          ngx_string("audiocodecid"),
          in_audio_codec_id, sizeof(in_audio_codec_id) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT, 
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_codec_module);
    }

    ngx_memzero(&v, sizeof(v));

    /* use -1 as a sign of unchanged data;
     * 0 is a valid value for uncompressed audio */
    v.audio_codec_id_n = -1; 

    /* FFmpeg sends a string in front of actal metadata; ignore it */
    skip = !(in->buf->last > in->buf->pos
            && *in->buf->pos == NGX_RTMP_AMF_STRING);
    if (ngx_rtmp_receive_amf(s, in, in_elts + skip, 
                sizeof(in_elts) / sizeof(in_elts[0]) - skip)) 
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: error parsing data frame");
        return NGX_OK;
    }

    ctx->width = v.width;
    ctx->height = v.height;
    ctx->duration = v.duration;
    ctx->frame_rate = v.frame_rate;
    ctx->video_data_rate = v.video_data_rate;
    ctx->video_codec_id = v.video_codec_id_n;
    ctx->audio_data_rate = v.audio_data_rate;
    ctx->audio_codec_id = (v.audio_codec_id_n == -1
            ? 0 : v.audio_codec_id_n == 0
            ? NGX_RTMP_AUDIO_UNCOMPRESSED : v.audio_codec_id_n);
    ngx_memcpy(ctx->profile, v.profile, sizeof(v.profile));
    ngx_memcpy(ctx->level, v.level, sizeof(v.level));

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "codec: data frame: "
            "width=%ui height=%ui duration=%ui frame_rate=%ui "
            "video=%s (%ui) audio=%s (%ui)",
            ctx->width, ctx->height, ctx->duration, ctx->frame_rate,
            ngx_rtmp_get_video_codec_name(ctx->video_codec_id), 
            ctx->video_codec_id,
            ngx_rtmp_get_audio_codec_name(ctx->audio_codec_id), 
            ctx->audio_codec_id);

    ngx_rtmp_codec_update_meta(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_codec_disconnect;

    /* register metadata handler */
    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&ch->name, "@setDataFrame");
    ch->handler = ngx_rtmp_codec_meta_data;

    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&ch->name, "onMetaData");
    ch->handler = ngx_rtmp_codec_meta_data;


    return NGX_OK;
}
