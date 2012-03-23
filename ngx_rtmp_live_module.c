/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


/* Standard stream ids for liveing */
#define NGX_RTMP_LIVE_CSID_AMF0    5
#define NGX_RTMP_LIVE_CSID_AUDIO   6
#define NGX_RTMP_LIVE_CSID_VIDEO   7


static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


static ngx_int_t ngx_rtmp_live_publish(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_live_play(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_live_set_data_frame(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_live_stream_length(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_rtmp_amf0_handler_t ngx_rtmp_live_map[] = {
    { ngx_string("publish"),            ngx_rtmp_live_publish          },
    { ngx_string("play"),               ngx_rtmp_live_play             },
    { ngx_string("-@setDataFrame"),     ngx_rtmp_live_set_data_frame   },
    { ngx_string("getStreamLength"),    ngx_rtmp_live_stream_length    },
    { ngx_string("releaseStream"),      ngx_rtmp_amf0_default          },
    { ngx_string("FCPublish"),          ngx_rtmp_amf0_default          },
    { ngx_string("FCSubscribe"),        ngx_rtmp_amf0_default          },
};


typedef struct ngx_rtmp_live_ctx_s ngx_rtmp_live_ctx_t;


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_rtmp_live_ctx_t               **contexts;
    ngx_flag_t                          live;
    ngx_flag_t                          wait_key_frame;
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
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_key_frame),
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
#define NGX_RTMP_LIVE_DATA_FRAME       0x08


struct ngx_rtmp_live_ctx_s {
    ngx_str_t                           stream;
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_live_ctx_t                *next;
    ngx_uint_t                          flags;
    uint32_t                            csid;
    ngx_chain_t                        *data_frame;
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
ngx_rtmp_live_join(ngx_rtmp_session_t *s, ngx_str_t *stream, 
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
                   "live: join '%V'", stream);

    ctx->stream = *stream;
    hctx = ngx_rtmp_live_get_head(s);
    if (hctx == NULL) {
        return;
    }
    ctx->next = *hctx;
    ctx->flags = flags;
    *hctx = ctx;
}


static ngx_int_t
ngx_rtmp_live_leave(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NGX_OK;
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

    return NGX_OK;
}


#define NGX_RTMP_VIDEO_KEY_FRAME            1
#define NGX_RTMP_VIDEO_INTER_FRAME          2
#define NGX_RTMP_VIDEO_DISPOSABLE_FRAME     3
#define NGX_RTMP_AUDIO_FRAME                NGX_RTMP_VIDEO_KEY_FRAME


static ngx_int_t
ngx_rtmp_get_video_frame_type(ngx_chain_t *in)
{
    return (in->buf->pos[0] & 0xf0) >> 4;
}


static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx, *cctx, *cnext;
    ngx_chain_t                    *out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               sh;
    ngx_uint_t                      priority;
    ngx_int_t                       rc;
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

    memset(&sh, 0, sizeof(sh));
    sh.timestamp = (h->timestamp + s->epoch);
    sh.msid = 1;
    sh.type = h->type;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "live: av: peer_epoch=%uD; my_epoch=%uD timestamp=%uD; r=%uD",
            s->peer_epoch, s->epoch, h->timestamp, sh.timestamp);

    keyframe = 0;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        sh.csid = NGX_RTMP_LIVE_CSID_VIDEO;
        priority = ngx_rtmp_get_video_frame_type(in);
        if (priority == NGX_RTMP_VIDEO_KEY_FRAME) {
            keyframe = 1;
        }

    } else if (h->type == NGX_RTMP_MSG_AUDIO) {
        sh.csid = NGX_RTMP_LIVE_CSID_AUDIO;
        priority = NGX_RTMP_AUDIO_FRAME;
        
    } else {
        return NGX_OK;
    }

    if (ctx == NULL 
            || !(ctx->flags & NGX_RTMP_LIVE_PUBLISHING)) 
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "live: received audio/video from non-publisher");
        return NGX_ERROR;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &sh, NULL, out);

    /* live to all subscribers */
    for (cctx = *ngx_rtmp_live_get_head(s); cctx; cctx = cnext) {
        /* session can die further in loop
         * so save next ptr while it's not too late */
        cnext = cctx->next;

        if (cctx == ctx
                || !(cctx->flags & NGX_RTMP_LIVE_PLAYING)
                || cctx->stream.len != ctx->stream.len
                || ngx_strncmp(cctx->stream.data, ctx->stream.data, 
                    ctx->stream.len))
        {
            continue;
        }

        ss = cctx->session;

        /* if we have metadata check if the subscriber
         * has already received one */
        if (ctx->data_frame
            && !(cctx->flags & NGX_RTMP_LIVE_DATA_FRAME))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "live: sending data_frame");

            rc = ngx_rtmp_send_message(ss, ctx->data_frame, 0);
            if (rc == NGX_ERROR) {
                continue;
            }

            if (rc == NGX_OK) {
                cctx->flags |= NGX_RTMP_LIVE_DATA_FRAME;
            }
        }

        /* waiting for a keyframe? */
        if (lacf->wait_key_frame
            && sh.type == NGX_RTMP_MSG_VIDEO 
            && !(cctx->flags & NGX_RTMP_LIVE_KEYFRAME)
            && !keyframe)
        {
            continue;
        }

        if (ngx_rtmp_send_message(ss, out, priority) == NGX_OK
            && keyframe 
            && !(cctx->flags & NGX_RTMP_LIVE_KEYFRAME)) 
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "live: keyframe sent");
            cctx->flags |= NGX_RTMP_LIVE_KEYFRAME;
        }
    }

    ngx_rtmp_free_shared_bufs(cscf, out);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               sh;
    ngx_str_t                       stream;

    static double                   trans;

    static struct {
        u_char                      name[1024];
        u_char                      type[1024];
    } v;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,       0                       },
        { NGX_RTMP_AMF0_NULL,   0,      NULL,         0                       },
        { NGX_RTMP_AMF0_STRING, 0,      &v.name,      sizeof(v.name)          },
        { NGX_RTMP_AMF0_STRING, 0,      &v.type,      sizeof(v.type)          },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",    "NetStream.Publish.Start",       0 },
        { NGX_RTMP_AMF0_STRING, "level",                    "status",       0 },
        { NGX_RTMP_AMF0_STRING, "description",  "Publish succeeded.",       0 },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus",                         0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)           },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: publish: name='%s' type=%s",
            v.name, v.type);

    /* join stream as publisher */
    stream.len = ngx_strlen(v.name);
    stream.data = ngx_palloc(s->connection->pool, stream.len);
    ngx_memcpy(stream.data, v.name, stream.len);
    ngx_rtmp_live_join(s, &stream, NGX_RTMP_LIVE_PUBLISHING);

    /* TODO: we can probably make any use of v.type: live/record/append */

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_LIVE_CSID_AMF0;
    sh.msid = h->msid;

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_play(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               sh;
    ngx_str_t                       stream;

    static double                   trans;
    static int                      bfalse;

    static struct {
        u_char                      name[1024];
        double                      start;
        double                      duration;
        int                         flush;
    } v;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,       0                       },
        { NGX_RTMP_AMF0_NULL,   0,      NULL,         0                       },
        { NGX_RTMP_AMF0_STRING, 0,      &v.name,      sizeof(v.name)          },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_NUMBER, 0,      &v.start,     0                       },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_NUMBER, 0,      &v.duration,  0                       },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_BOOLEAN,0,      &v.flush,     0                       }
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         "NetStream.Play.Reset",     0 },
        { NGX_RTMP_AMF0_STRING, "level",        "status",                   0 },
        { NGX_RTMP_AMF0_STRING, "description",  "Playing and resetting.",   0 },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus",                         0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)           },
    };

    static ngx_rtmp_amf0_elt_t      out2_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         "NetStream.Play.Start",     0 },
        { NGX_RTMP_AMF0_STRING, "level",        "status",                   0 },
        { NGX_RTMP_AMF0_STRING, "description",  "Started playing.",         0 },
    };

    static ngx_rtmp_amf0_elt_t      out2_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus",                         0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out2_inf,    sizeof(out2_inf)         },
    };

    static ngx_rtmp_amf0_elt_t      out3_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "|RtmpSampleAccess",                0 },
        { NGX_RTMP_AMF0_BOOLEAN,NULL,   &bfalse,                            0 },
        { NGX_RTMP_AMF0_BOOLEAN,NULL,   &bfalse,                            0 },
    };

    static ngx_rtmp_amf0_elt_t      out4_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code", "NetStream.Data.Start",             0 },
    };

    static ngx_rtmp_amf0_elt_t      out4_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus",                         0 },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out4_inf,    sizeof(out4_inf)         },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: play: name='%s' start=%uD duration=%uD flush=%d",
            v.name, (uint32_t)v.start, (uint32_t)v.duration, v.flush);

    /* join stream as player */
    stream.len = ngx_strlen(v.name);
    stream.data = ngx_palloc(s->connection->pool, stream.len);
    ngx_memcpy(stream.data, v.name, stream.len);
    ngx_rtmp_live_join(s, &stream, NGX_RTMP_LIVE_PLAYING);

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_LIVE_CSID_AMF0;
    sh.msid = h->msid;

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send sample access meta message FIXME */
    if (ngx_rtmp_send_amf0(s, &sh, out2_elts,
                sizeof(out2_elts) / sizeof(out2_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send data start meta message */
    sh.type = NGX_RTMP_MSG_AMF0_META;
    if (ngx_rtmp_send_amf0(s, &sh, out3_elts,
                sizeof(out3_elts) / sizeof(out3_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_rtmp_send_amf0(s, &sh, out4_elts,
                sizeof(out4_elts) / sizeof(out4_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_rtmp_live_set_data_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_amf0_ctx_t             act;
    ngx_rtmp_header_t               sh;
    ngx_rtmp_core_srv_conf_t       *cscf;

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING,   NULL,   "@setDataFrame",                  0 },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "live: data_frame");

    /* TODO: allow sending more meta packages to change live content */

    if (ctx->data_frame) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, 
                "duplicate data_frame");
        return NGX_OK;
    }

    /* create full metadata chain for output */
    memset(&act, 0, sizeof(act));
    act.cscf = cscf;
    act.alloc = ngx_rtmp_alloc_shared_buf;
    act.log = c->log;

    if (ngx_rtmp_amf0_write(&act, out_elts, 
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK) 
    {
        if (act.first) {
            ngx_rtmp_free_shared_bufs(cscf, act.first);
        }
        return NGX_ERROR;
    }

    if (act.first == NULL) {
        return NGX_OK;
    }

    ctx->data_frame = act.first;

    if (ngx_rtmp_append_shared_bufs(cscf, ctx->data_frame, in) == NULL) {
        if (ctx->data_frame) {
            ngx_rtmp_free_shared_bufs(cscf, ctx->data_frame);
        }
        return NGX_ERROR;
    }

    memset(&sh, 0, sizeof(sh));
    sh.csid = NGX_RTMP_LIVE_CSID_AMF0;
    sh.msid = 1;
    sh.type = NGX_RTMP_MSG_AMF0_META;

    ngx_rtmp_prepare_message(s, &sh, NULL, ctx->data_frame);

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_live_stream_length(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               sh;

    static double                   trans;
    static double                   length;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",                          0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &length,                            0 },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    memset(&sh, 0, sizeof(sh));
    sh.csid = h->csid;
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.msid = 0;

    /* send simple _result */
    return ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK
        ? NGX_DONE
        : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf0_handler_t            *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register event handlers */
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_live_leave;

    /* register AMF0 callbacks */
    ncalls = sizeof(ngx_rtmp_live_map) 
                / sizeof(ngx_rtmp_live_map[0]);
    ch = ngx_array_push_n(&cmcf->amf0, ncalls);
    if (h == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_live_map;
    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    return NGX_OK;
}
