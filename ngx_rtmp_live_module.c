/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_delete_stream_pt        next_delete_stream;


static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


#define NGX_RTMP_LIVE_TIME_ABSOLUTE     0x01
#define NGX_RTMP_LIVE_TIME_RELATIVE     0x02


static ngx_command_t  ngx_rtmp_live_commands[] = {

    { ngx_string("live"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, live),
      NULL },

    { ngx_string("stream_buckets"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, nbuckets),
      NULL },

    { ngx_string("buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, buflen),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_live_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_live_create_app_conf,          /* create app configuration */
    ngx_rtmp_live_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_live_module_ctx,              /* module context */
    ngx_rtmp_live_commands,                 /* module directives */
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


static void *
ngx_rtmp_live_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_live_app_conf_t      *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->live = NGX_CONF_UNSET;
    lacf->nbuckets = NGX_CONF_UNSET;
    lacf->buflen = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_live_app_conf_t *prev = parent;
    ngx_rtmp_live_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 0);

    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->streams = ngx_pcalloc(cf->pool, 
            sizeof(ngx_rtmp_live_stream_t *) * conf->nbuckets);

    return NGX_CONF_OK;
}


static ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_stream(ngx_rtmp_session_t *s, u_char *name, int create)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_stream_t    **stream;
    size_t                      len;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NULL;
    }

    len = ngx_strlen(name);
    stream = &lacf->streams[ngx_hash_key(name, len) % lacf->nbuckets];

    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strcmp(name, (*stream)->name) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: create stream '%s'", name);

    if (lacf->free_streams) {
        *stream = lacf->free_streams;
        lacf->free_streams = lacf->free_streams->next;
    } else {
        *stream = ngx_palloc(lacf->pool, sizeof(ngx_rtmp_live_stream_t));
    }
    ngx_memzero(*stream, sizeof(ngx_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name, 
            ngx_min(sizeof((*stream)->name) - 1, len));
    (*stream)->epoch = ngx_current_msec;

    return stream;
}


static void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name,
        ngx_uint_t flags)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ctx->session = s;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    if (ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 
                0, "live: already joined");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "live: join '%s'", name);

    stream = ngx_rtmp_live_get_stream(s, name, 1);
    if (stream == NULL) {
        return;
    }
    if (flags & NGX_RTMP_LIVE_PUBLISHING) {
        if ((*stream)->flags & NGX_RTMP_LIVE_PUBLISHING) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "live: already publishing");
            return;
        }
        (*stream)->flags |= NGX_RTMP_LIVE_PUBLISHING;
    }
    ctx->stream = *stream;
    ctx->flags = flags;
    ctx->next = (*stream)->ctx;
    (*stream)->ctx = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }
}


static ngx_int_t
ngx_rtmp_live_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx, **cctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: not joined ");
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: leave '%s'", ctx->stream->name);

    if (ctx->stream->flags & NGX_RTMP_LIVE_PUBLISHING
            && ctx->flags & NGX_RTMP_LIVE_PUBLISHING)
    {
        ctx->stream->flags &= ~NGX_RTMP_LIVE_PUBLISHING;
    }

    for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: delete empty stream '%s'", ctx->stream->name);

    stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);
    if (stream == NULL) {
        return NGX_ERROR;
    }
    *stream = (*stream)->next;

    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *out, *peer_out, *header_out, *pheader_out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch, lh;
    ngx_uint_t                      prio, peer_prio;
    ngx_uint_t                      peers, dropped_peers;
    size_t                          header_offset;
    ngx_uint_t                      header_version;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                "live: NULL application");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (!lacf->live 
            || in == NULL  || in->buf == NULL
            || ctx == NULL || ctx->stream == NULL
            || (h->type != NGX_RTMP_MSG_VIDEO
                && h->type != NGX_RTMP_MSG_AUDIO))
    {
        return NGX_OK;
    }

    if ((ctx->flags & NGX_RTMP_LIVE_PUBLISHING) == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "live: received audio/video from non-publisher");
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: av: %s timestamp=%uD",
            h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
            h->timestamp);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* prepare output header */
    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&lh, sizeof(lh));
    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_LIVE_MSID;
    ch.type = h->type;
    lh.msid = ch.msid;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        prio = ngx_rtmp_get_video_frame_type(in);
        ch.csid = NGX_RTMP_LIVE_CSID_VIDEO;
        lh.timestamp = ctx->last_video;
        ctx->last_video = ch.timestamp;
    } else {
        /* audio priority is the same as video key frame's */
        prio = NGX_RTMP_VIDEO_KEY_FRAME;
        ch.csid = NGX_RTMP_LIVE_CSID_AUDIO;
        lh.timestamp = ctx->last_audio;
        ctx->last_audio = ch.timestamp;
    }
    lh.csid = ch.csid;

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    ngx_rtmp_prepare_message(s, &ch, &lh, out);

    peers = 0;
    dropped_peers = 0;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    header_out = NULL;
    pheader_out = NULL;
    header_offset = 0;
    header_version = 0;
    if (codec_ctx) {
        if (h->type == NGX_RTMP_MSG_AUDIO) {
            if (codec_ctx->aac_pheader) {
                header_out = codec_ctx->aac_header;
                pheader_out = codec_ctx->aac_pheader;
                header_offset = offsetof(ngx_rtmp_live_ctx_t, aac_version);
                header_version = codec_ctx->aac_version;
            }
        } else {
            if (codec_ctx->avc_pheader) {
                header_out = codec_ctx->avc_header;
                pheader_out = codec_ctx->avc_pheader;
                header_offset = offsetof(ngx_rtmp_live_ctx_t, avc_version);
                header_version = codec_ctx->avc_version;
            }
        }
    }

    /* broadcast to all subscribers */
    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx) {
            continue;
        }
        ++peers;
        ss = pctx->session;

        /* send absolute frame */
        if ((pctx->msg_mask & (1 << h->type)) == 0) {
            ch.timestamp = ngx_current_msec - ss->epoch;
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                    "live: av: abs %s timestamp=%uD",
                    h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
                    ch.timestamp);
            /* send codec header as abs frame if any */
            peer_out = ngx_rtmp_append_shared_bufs(cscf, NULL, 
                    header_out ? header_out : in);
            ngx_rtmp_prepare_message(s, &ch, NULL, peer_out);
            pctx->msg_mask |= (1 << h->type);
            if (ngx_rtmp_send_message(ss, peer_out, prio) == NGX_OK
                    && header_out)
            {
                *(ngx_uint_t *)((u_char *)pctx + header_offset) 
                    = header_version;
            }
            ngx_rtmp_free_shared_chain(cscf, peer_out);
            continue;
        }

        /* send AVC/H264 header if newer header has arrived  */
        if (pheader_out && *(ngx_uint_t *)((u_char *)pctx + header_offset) 
                != header_version) 
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                    "live: sending codec header");
            if (ngx_rtmp_send_message(ss, pheader_out, prio) == NGX_OK) {
                *(ngx_uint_t *)((u_char *)pctx + header_offset) 
                    = header_version;
            }
        }

        /* push buffered data */
        peer_prio = prio;
        if (ngx_rtmp_send_message(ss, out, peer_prio) != NGX_OK) {
            ++pctx->dropped;
            ++dropped_peers;
        }
    }
    ngx_rtmp_free_shared_chain(cscf, out);

    ngx_rtmp_update_bandwidth(&ctx->stream->bw_in, h->mlen);
    ngx_rtmp_update_bandwidth(&ctx->stream->bw_out, 
            h->mlen * (peers - dropped_peers));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: publish: name='%s' type='%s'",
            v->name, v->type);

    /* join stream as publisher */
    ngx_rtmp_live_join(s, v->name, NGX_RTMP_LIVE_PUBLISHING);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: play: name='%s' start=%uD duration=%uD reset=%d",
            v->name, (uint32_t)v->start, 
            (uint32_t)v->duration, (uint32_t)v->reset);

    /* join stream as player */
    ngx_rtmp_live_join(s, v->name, 0);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_live_av;

    /* chain handlers */
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_live_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_live_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_live_delete_stream;

    return NGX_OK;
}
