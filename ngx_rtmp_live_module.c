/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_play_pt             next_play;
static ngx_rtmp_delete_stream_pt    next_delete_stream;


/* Chunk stream ids for output */
#define NGX_RTMP_LIVE_CSID_AUDIO   6
#define NGX_RTMP_LIVE_CSID_VIDEO   7

#define NGX_RTMP_LIVE_MSID          1


static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


typedef struct ngx_rtmp_live_ctx_s ngx_rtmp_live_ctx_t;


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_rtmp_live_ctx_t               **contexts;
    ngx_flag_t                          live;
    ngx_flag_t                          wait_key_frame;
    ngx_flag_t                          abstime;
} ngx_rtmp_live_app_conf_t;


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

    { ngx_string("wait_key_frame"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_key_frame),
      NULL },

    { ngx_string("abstime"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, abstime),
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


/* session flags */
#define NGX_RTMP_LIVE_PUBLISHING       0x01
#define NGX_RTMP_LIVE_PLAYING          0x02
#define NGX_RTMP_LIVE_KEYFRAME         0x04
#define NGX_RTMP_LIVE_AUDIO_STARTED    0x08
#define NGX_RTMP_LIVE_VIDEO_STARTED    0x10


struct ngx_rtmp_live_ctx_s {
    ngx_str_t                           stream;
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_live_ctx_t                *next;
    ngx_uint_t                          flags;
    uint32_t                            csid;
    ngx_chain_t                        *data_frame;
    ngx_rtmp_header_t                   last_audio;
    ngx_rtmp_header_t                   last_video;
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
    lacf->wait_key_frame = NGX_CONF_UNSET;
    lacf->abstime = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_live_app_conf_t *prev = parent;
    ngx_rtmp_live_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_value(conf->wait_key_frame, prev->wait_key_frame, 1);
    ngx_conf_merge_value(conf->abstime, prev->abstime, 0);

    conf->contexts = ngx_pcalloc(cf->pool, 
            sizeof(ngx_rtmp_live_ctx_t *) * conf->nbuckets);

    return NGX_CONF_OK;
}


static ngx_rtmp_live_ctx_t **
ngx_rtmp_live_get_head(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_app_conf_t  *lacf;
    ngx_rtmp_live_ctx_t       *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    return &lacf->contexts[
        ngx_hash_key(ctx->stream.data, ctx->stream.len) 
        % lacf->nbuckets];
}


static void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name,
        ngx_uint_t flags)
{
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_live_ctx_t));
        ctx->session = s;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    if (ctx->stream.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "live: already joined");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "live: join '%s'", name);

    ctx->stream.len = ngx_strlen(name);
    ctx->stream.data = ngx_palloc(s->connection->pool,
            ctx->stream.len);
    ngx_memcpy(ctx->stream.data, name, ctx->stream.len);

    hctx = ngx_rtmp_live_get_head(s);
    if (hctx == NULL) {
        return;
    }
    ctx->next = *hctx;
    ctx->flags = flags;
    *hctx = ctx;
}


static ngx_int_t
ngx_rtmp_live_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "live: leave '%V'", &ctx->stream);

    hctx = ngx_rtmp_live_get_head(s);
    if (hctx == NULL) {
        return NGX_ERROR;
    }
    ngx_str_null(&ctx->stream);

    for(; *hctx; hctx = &(*hctx)->next) {
        if (*hctx == ctx) {
            *hctx = (*hctx)->next;
            break;
        }
    }

next:
    return next_delete_stream(s, v);
}


#define NGX_RTMP_AUDIO_FRAME                NGX_RTMP_VIDEO_KEY_FRAME


static ngx_int_t
ngx_rtmp_live_send_abs_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;
    ngx_chain_t                    *out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_int_t                       rc;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: sending abs message");

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    sh = *h;
    sh.timestamp = ngx_rtmp_get_timestamp() - s->epoch;

    /* send empty message only for timestamp */

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_prepare_message(s, &sh, NULL, out);

    rc = ngx_rtmp_send_message(s, out, 0);

    ngx_rtmp_free_shared_chain(cscf, out);

    return rc;
}


static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx, *pctx, *cnext;
    ngx_chain_t                    *out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               sh, *lh;
    ngx_uint_t                      priority;
    int                             keyframe;

    c = s->connection;
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "live: NULL application");
        return NGX_ERROR;
    }

    if (!lacf->live) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    memset(&sh, 0, sizeof(sh));
    sh.timestamp = h->timestamp;
    if (lacf->abstime) {
        sh.timestamp += s->epoch;
    }
    sh.msid = NGX_RTMP_LIVE_MSID;
    sh.type = h->type;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "live: av: peer_epoch=%uD; my_epoch=%uD timestamp=%uD; r=%uD",
            s->peer_epoch, s->epoch, h->timestamp, sh.timestamp);

    keyframe = 0;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        lh = &ctx->last_video;
        sh.csid = NGX_RTMP_LIVE_CSID_VIDEO;
        priority = ngx_rtmp_get_video_frame_type(in);
        if (priority == NGX_RTMP_VIDEO_KEY_FRAME) {
            keyframe = 1;
        }

    } else if (h->type == NGX_RTMP_MSG_AUDIO) {
        lh = &ctx->last_audio;
        sh.csid = NGX_RTMP_LIVE_CSID_AUDIO;
        priority = NGX_RTMP_AUDIO_FRAME;
        
    } else {
        return NGX_OK;
    }

    /* we don't want absolute (fmt=0) frames in output;
     * force type 1 message */
    if (lh && lh->csid == 0) {
        *lh = sh;
        lh->mlen = 0;
    }

    if (ctx == NULL 
            || !(ctx->flags & NGX_RTMP_LIVE_PUBLISHING)) 
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "live: received audio/video from non-publisher");
        return NGX_OK;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &sh, lacf->abstime ? NULL : lh, out);

    /* live to all subscribers */
    for (pctx = *ngx_rtmp_live_get_head(s); pctx; pctx = cnext) {
        /* session can die further in loop
         * so save next ptr while it's not too late */
        cnext = pctx->next;

        if (pctx == ctx
                || !(pctx->flags & NGX_RTMP_LIVE_PLAYING)
                || pctx->stream.len != ctx->stream.len
                || ngx_strncmp(pctx->stream.data, ctx->stream.data, 
                    ctx->stream.len))
        {
            continue;
        }

        ss = pctx->session;

        /* waiting for a keyframe? */
        if (lacf->wait_key_frame
            && sh.type == NGX_RTMP_MSG_VIDEO 
            && !(pctx->flags & NGX_RTMP_LIVE_KEYFRAME)
            && !keyframe)
        {
            continue;
        }

        /* send initial frame with abs time */
        if (lacf->abstime == 0
            && ((h->type == NGX_RTMP_MSG_AUDIO
                && (pctx->flags & NGX_RTMP_LIVE_AUDIO_STARTED) == 0)
            || (h->type == NGX_RTMP_MSG_VIDEO
                && (pctx->flags & NGX_RTMP_LIVE_VIDEO_STARTED) == 0)))
        {
            if (ngx_rtmp_live_send_abs_message(ss, &sh, in) != NGX_OK) {
                continue;
            }
            if (h->type == NGX_RTMP_MSG_AUDIO) {
                pctx->flags |= NGX_RTMP_LIVE_AUDIO_STARTED;
            } else {
                pctx->flags |= NGX_RTMP_LIVE_VIDEO_STARTED;
            }

            continue;
        }


        if (ngx_rtmp_send_message(ss, out, priority) == NGX_OK
            && keyframe 
            && !(pctx->flags & NGX_RTMP_LIVE_KEYFRAME)) 
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "live: keyframe sent");
            pctx->flags |= NGX_RTMP_LIVE_KEYFRAME;
        }
    }

    ngx_rtmp_free_shared_chain(cscf, out);

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
    ngx_rtmp_live_join(s, v->name, NGX_RTMP_LIVE_PLAYING);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    /* register raw event handlers */
    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

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
