/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


/* Standard stream ids for broadcasting */
#define NGX_RTMP_BROADCAST_MSID         1
#define NGX_RTMP_BROADCAST_CSID_AMF0    5
#define NGX_RTMP_BROADCAST_CSID_AUDIO   6
#define NGX_RTMP_BROADCAST_CSID_VIDEO   7


static ngx_int_t ngx_rtmp_broadcast_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_broadcast_create_srv_conf(ngx_conf_t *cf);
static char * ngx_rtmp_broadcast_merge_srv_conf(ngx_conf_t *cf, 
        void *parent, void *child);


static ngx_int_t ngx_rtmp_broadcast_connect(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_broadcast_create_stream(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_broadcast_publish(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_broadcast_play(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_broadcast_set_data_frame(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_broadcast_ok(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_rtmp_amf0_handler_t ngx_rtmp_broadcast_map[] = {
    { ngx_string("connect"),            ngx_rtmp_broadcast_connect          },
    { ngx_string("createStream"),       ngx_rtmp_broadcast_create_stream    },
    { ngx_string("publish"),            ngx_rtmp_broadcast_publish          },
    { ngx_string("play"),               ngx_rtmp_broadcast_play             },
    { ngx_string("-@setDataFrame"),     ngx_rtmp_broadcast_set_data_frame   },
    { ngx_string("releaseStream"),      ngx_rtmp_broadcast_ok               },
    { ngx_string("FCPublish"),          ngx_rtmp_broadcast_ok               },
    { ngx_string("FCSubscribe"),        ngx_rtmp_broadcast_ok               },
};


typedef struct {
    /* use hash-map
     * stream -> broadcast contexts */
    ngx_int_t                           buckets;
    struct ngx_rtmp_broadcast_ctx_s   **contexts;
} ngx_rtmp_broadcast_srv_conf_t;


static ngx_command_t  ngx_rtmp_broadcast_commands[] = {

    { ngx_string("broadcast_buckets"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_broadcast_srv_conf_t, buckets),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_broadcast_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_broadcast_postconfiguration,   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_broadcast_create_srv_conf,     /* create server configuration */
    ngx_rtmp_broadcast_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_rtmp_broadcast_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_broadcast_module_ctx,         /* module context */
    ngx_rtmp_broadcast_commands,            /* module directives */
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
#define NGX_RTMP_BROADCAST_PUBLISHER        0x01
#define NGX_RTMP_BROADCAST_SUBSCRIBER       0x02
#define NGX_RTMP_BROADCAST_KEYFRAME         0x04
#define NGX_RTMP_BROADCAST_DATA_FRAME       0x08


typedef struct ngx_rtmp_broadcast_ctx_s {
    ngx_str_t                           stream;
    ngx_rtmp_session_t                 *session;
    struct ngx_rtmp_broadcast_ctx_s    *next;
    ngx_uint_t                          flags;
    uint32_t                            csid;
    ngx_chain_t                        *data_frame;
} ngx_rtmp_broadcast_ctx_t;


static void *
ngx_rtmp_broadcast_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_broadcast_srv_conf_t      *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_broadcast_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    cscf->buckets = NGX_CONF_UNSET;

    return cscf;
}


static char *
ngx_rtmp_broadcast_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_broadcast_srv_conf_t *prev = parent;
    ngx_rtmp_broadcast_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->buckets, prev->buckets, 1024);

    conf->contexts = ngx_pcalloc(cf->pool, 
            sizeof(ngx_rtmp_broadcast_ctx_t *) * conf->buckets);

    return NGX_CONF_OK;
}


static ngx_rtmp_broadcast_ctx_t **
ngx_rtmp_broadcast_get_head(ngx_rtmp_session_t *s)
{
    ngx_rtmp_broadcast_srv_conf_t  *bscf;
    ngx_rtmp_broadcast_ctx_t       *ctx;

    bscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_broadcast_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);

    return &bscf->contexts[
        ngx_hash_key(ctx->stream.data, ctx->stream.len) 
        % bscf->buckets];
}


static void
ngx_rtmp_broadcast_set_flags(ngx_rtmp_session_t *s, ngx_uint_t flags)
{
    ngx_rtmp_broadcast_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);
    if (ctx == NULL) {
        return;
    }

    ctx->flags |= flags;
}


static void
ngx_rtmp_broadcast_join(ngx_rtmp_session_t *s, ngx_str_t *stream, 
        ngx_uint_t flags)
{
    ngx_connection_t               *c;
    ngx_rtmp_broadcast_ctx_t       *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_broadcast_ctx_t));
        ctx->session = s;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_broadcast_module);
    }

    if (ctx->stream.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "already joined");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "join broadcast stream '%V'", stream);

    ctx->stream = *stream;
    hctx = ngx_rtmp_broadcast_get_head(s);
    ctx->next = *hctx;
    ctx->flags = flags;
    *hctx = ctx;
}


static ngx_int_t
ngx_rtmp_broadcast_leave(ngx_rtmp_session_t *s)
{
    ngx_connection_t               *c;
    ngx_rtmp_broadcast_ctx_t       *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "leave broadcast stream '%V'", &ctx->stream);

    hctx = ngx_rtmp_broadcast_get_head(s);
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
ngx_rtmp_broadcast_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_broadcast_ctx_t       *ctx, *cctx, *cnext;
    ngx_chain_t                    *out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               sh;
    ngx_uint_t                      priority;
    ngx_int_t                       rc;
    int                             keyframe;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);

    memset(&sh, 0, sizeof(sh));
    sh.timestamp = h->timestamp + s->epoch;
    sh.msid = NGX_RTMP_BROADCAST_MSID;
    sh.type = h->type;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "av packet; peer_epoch=%uD; my_epoch=%uD timestamp=%uD; r=%uD",
            s->peer_epoch, s->epoch, h->timestamp, sh.timestamp);

    keyframe = 0;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        sh.csid = NGX_RTMP_BROADCAST_CSID_VIDEO;
        priority = ngx_rtmp_get_video_frame_type(in);
        if (priority == NGX_RTMP_VIDEO_KEY_FRAME) {
            keyframe = 1;
        }

    } else if (h->type == NGX_RTMP_MSG_AUDIO) {
        sh.csid = NGX_RTMP_BROADCAST_CSID_AUDIO;
        priority = NGX_RTMP_AUDIO_FRAME;
        
    } else {
        return NGX_OK;
    }

    if (ctx == NULL 
            || !(ctx->flags & NGX_RTMP_BROADCAST_PUBLISHER)) 
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "received audio/video from non-publisher");
        return NGX_ERROR;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &sh, NULL, out);

    /* broadcast to all subscribers */
    for (cctx = *ngx_rtmp_broadcast_get_head(s); cctx; cctx = cnext) {
        /* session can die further in loop
         * so save next ptr while it's not too late */
        cnext = cctx->next;

        if (cctx == ctx
                || !(cctx->flags & NGX_RTMP_BROADCAST_SUBSCRIBER)
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
            && !(cctx->flags & NGX_RTMP_BROADCAST_DATA_FRAME))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "sending data_frame");

            rc = ngx_rtmp_send_message(ss, ctx->data_frame, 0);
            if (rc == NGX_ERROR) {
                continue;
            }

            if (rc == NGX_OK) {
                cctx->flags |= NGX_RTMP_BROADCAST_DATA_FRAME;
            }
        }

        /* waiting for a keyframe? */
        if (cscf->wait_key_frame
            && sh.type == NGX_RTMP_MSG_VIDEO 
            && !(cctx->flags & NGX_RTMP_BROADCAST_KEYFRAME)
            && !keyframe)
        {
            continue;
        }

        if (ngx_rtmp_send_message(ss, out, priority) == NGX_OK
            && keyframe 
            && !(cctx->flags & NGX_RTMP_BROADCAST_KEYFRAME)) 
        {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "keyframe sent");
            cctx->flags |= NGX_RTMP_BROADCAST_KEYFRAME;
        }
    }

    ngx_rtmp_free_shared_bufs(cscf, out);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    return ngx_rtmp_broadcast_leave(s);
}


static ngx_int_t
ngx_rtmp_broadcast_connect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_connection_t           *c;
    ngx_rtmp_core_srv_conf_t   *cscf;

    static double               trans;
    static u_char               app[1024];
    static ngx_str_t            stream;
    static double               capabilities = 31;

    static ngx_rtmp_amf0_elt_t  in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",      app,        sizeof(app)           },
    };

    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,          &trans,     0                     },
        { NGX_RTMP_AMF0_OBJECT, NULL,       in_cmd,     sizeof(in_cmd)        },
    };

    static ngx_rtmp_amf0_elt_t  out_obj[] = {
        { NGX_RTMP_AMF0_STRING, "fmsVer",           "FMS/3,0,1,123",        0 },
        { NGX_RTMP_AMF0_NUMBER, "capabilities",     &capabilities,          0 },
    };

    static ngx_rtmp_amf0_elt_t  out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "level", "status",                          0 },
        { NGX_RTMP_AMF0_STRING, "code",  "NetConnection.Connect.Success",   0 },
        { NGX_RTMP_AMF0_STRING, "description",   "Connection succeeded.",   0 },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     0                         },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_obj,    sizeof(out_obj)           },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)           },
    };

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* parse input */
    app[0] = 0;
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "connect() called; app='%s'", app);

    /* join stream */
    stream.len = ngx_strlen(app);
    stream.data = ngx_palloc(c->pool, stream.len);
    ngx_memcpy(stream.data, app, stream.len);
    ngx_rtmp_broadcast_join(s, &stream, 0);

    /* send all replies */
    return ngx_rtmp_send_ack_size(s, cscf->ack_window)
        || ngx_rtmp_send_bandwidth(s, cscf->ack_window, NGX_RTMP_LIMIT_DYNAMIC)
        || ngx_rtmp_send_user_stream_begin(s, 0)
        || ngx_rtmp_send_chunk_size(s, cscf->chunk_size)
        || ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_ERROR
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static double               trans;
    static double               stream;

    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     0                         },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &stream,    sizeof(stream)            },
    };

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "createStream() called");

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    /* send result with standard stream */
    stream = NGX_RTMP_BROADCAST_MSID;
    return ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_broadcast_publish(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;

    static double                   trans;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,                             0 },
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

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "publish() called");

    /* mark current session as publisher */
    ngx_rtmp_broadcast_set_flags(s, NGX_RTMP_BROADCAST_PUBLISHER);

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 
                NGX_RTMP_BROADCAST_MSID) != NGX_OK) 
    {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_BROADCAST_CSID_AMF0;
    sh.msid = h->msid;

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_play(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;

    static double                   trans;
    static uint8_t                  bfalse;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,                             0 },
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

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "play() called");

    /* mark session as subscriber */
    ngx_rtmp_broadcast_set_flags(s, NGX_RTMP_BROADCAST_SUBSCRIBER);

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 
                NGX_RTMP_BROADCAST_MSID) != NGX_OK) 
    {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_BROADCAST_CSID_AMF0;
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

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_set_data_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_broadcast_ctx_t       *ctx;
    ngx_rtmp_amf0_ctx_t             act;
    ngx_rtmp_header_t               sh;
    ngx_rtmp_core_srv_conf_t       *cscf;

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING,   NULL,   "@setDataFrame",                  0 },
    };

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "data_frame arrived");

    /* TODO: allow sending more meta packages to change broadcast content */

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
    sh.csid = NGX_RTMP_BROADCAST_CSID_AMF0;
    sh.msid = NGX_RTMP_BROADCAST_MSID;
    sh.type = NGX_RTMP_MSG_AMF0_META;

    ngx_rtmp_prepare_message(s, &sh, NULL, ctx->data_frame);

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_broadcast_ok(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;

    static double                   trans;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",                          0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
    };

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
                sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_broadcast_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf0_handler_t            *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register event handlers */
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_broadcast_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_broadcast_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_broadcast_done;

    /* register AMF0 callbacks */
    ncalls = sizeof(ngx_rtmp_broadcast_map) 
                / sizeof(ngx_rtmp_broadcast_map[0]);
    ch = ngx_array_push_n(&cmcf->amf0, ncalls);
    if (h == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_broadcast_map;
    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    return NGX_OK;
}
