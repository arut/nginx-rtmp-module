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


/* Frame cutoff */
#define NGX_RTMP_CUTOFF_ALL             0
#define NGX_RTMP_CUTOFF_KEY             1
#define NGX_RTMP_CUTOFF_INTER           2
#define NGX_RTMP_CUTOFF_DISPOSABLE      3


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


typedef struct {
    ngx_str_t                           name;
    ngx_rtmp_event_handler_pt           handler;
} ngx_rtmp_broadcast_map_t;


static ngx_rtmp_broadcast_map_t ngx_rtmp_broadcast_map[] = {
    { ngx_string("connect"),            ngx_rtmp_broadcast_connect          },
    { ngx_string("createStream"),       ngx_rtmp_broadcast_create_stream    },
    { ngx_string("publish"),            ngx_rtmp_broadcast_publish          },
    { ngx_string("play"),               ngx_rtmp_broadcast_play             },
    { ngx_string("@setDataFrame"),      ngx_rtmp_broadcast_set_data_frame   },
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
    if (ctx == NULL || !ctx->stream.len) {
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
    ngx_rtmp_broadcast_ctx_t       *ctx, *cctx;
    ngx_chain_t                    *out;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_header_t               sh;
    ngx_rtmp_session_t             *ss;
    ngx_uint_t                      priority;
    int                             keyframe;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);

    sh = *h;
    keyframe = 0;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        sh.csid = NGX_RTMP_BROADCAST_CSID_VIDEO;
        priority = ngx_rtmp_get_video_frame_type(in);
        if (priority == NGX_RTMP_VIDEO_KEY_FRAME) {
            keyframe = 1;
        }

    } else {
        sh.csid = NGX_RTMP_BROADCAST_CSID_AUDIO;
        priority = NGX_RTMP_AUDIO_FRAME;
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
    for (cctx = *ngx_rtmp_broadcast_get_head(s); 
            cctx; cctx = cctx->next) 
    {
        if (cctx != ctx
                && cctx->flags & NGX_RTMP_BROADCAST_SUBSCRIBER
                && cctx->stream.len == ctx->stream.len
                && !ngx_strncmp(cctx->stream.data, ctx->stream.data, 
                    ctx->stream.len))
        {
            ss = cctx->session;

            /* if we have metadata check if the subscriber
             * has already received one */
            if (ctx->data_frame
                && !(cctx->flags & NGX_RTMP_BROADCAST_DATA_FRAME))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                        "sending data_frame");

                switch (ngx_rtmp_send_message(ss, ctx->data_frame, 0)) {
                    case NGX_OK:
                        cctx->flags |= NGX_RTMP_BROADCAST_DATA_FRAME;
                        break;
                    case NGX_AGAIN:
                        break;
                    default:
                        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0, 
                            "error sending message");
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

            if (ngx_rtmp_send_message(ss, out, priority) == NGX_OK) {
                if (keyframe) {
                    cctx->flags |= NGX_RTMP_BROADCAST_KEYFRAME;
                }
            } else {
                ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0, 
                        "error sending message");
            }
        }
    }

    ngx_rtmp_free_shared_bufs(cscf, out);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_connect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t   *cscf;

    static double               trans;
    static u_char               app[1024];
    static u_char               url[1024];
    static u_char               acodecs[1024];
    static ngx_str_t            app_str;
    static double               capabilities = 31;
    static double               object_enc;

    static ngx_rtmp_amf0_elt_t      in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",          app,        sizeof(app)     },
        { NGX_RTMP_AMF0_STRING, "tcUrl"  ,      url,        sizeof(url)     },
        { NGX_RTMP_AMF0_STRING, "audiocodecs"  ,      acodecs,        sizeof(acodecs)     },
    };

    static ngx_rtmp_amf0_elt_t      out_obj[] = {
        { NGX_RTMP_AMF0_STRING, "fmsVer",        "FMS/3,0,1,123" ,       sizeof("FMS/3,0,1,123")-1               },
        { NGX_RTMP_AMF0_NUMBER, "capabilities",   &capabilities,       sizeof(capabilities)               },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "level",        NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,       0               },
        { NGX_RTMP_AMF0_NUMBER, "objectEncoding", &object_enc ,       sizeof(object_enc)               },
    };

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_OBJECT, NULL,   in_cmd,     sizeof(in_cmd)          },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  sizeof("_result") - 1   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_obj,    sizeof(out_obj)         },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)         },
    };

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_str_set(&out_inf[0], "status");
    ngx_str_set(&out_inf[1], "NetConnection.Connect.Success");
    ngx_str_set(&out_inf[2], "Connection succeeded.");

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect() called; app='%s' url='%s'",
            app, url);

    /*FIXME: app_str allocation!!!!!!! */
    /*FIXME: add memsetting input data */
    /* join stream */
    ngx_str_set(&app_str, "preved");
    /*
    app_str.data = app;
    app_str.len = ngx_strlen(app);
    */
    ngx_rtmp_broadcast_join(s, &app_str, 0);

    return ngx_rtmp_send_ack_size(s, cscf->ack_window)
        || ngx_rtmp_send_bandwidth(s, cscf->ack_window, NGX_RTMP_LIMIT_DYNAMIC)
        || ngx_rtmp_send_user_stream_begin(s, 0)
        || ngx_rtmp_send_chunk_size(s, cscf->chunk_size)
        || ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_OK
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static double       trans;
    static double       stream;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)           },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  sizeof("_result") - 1   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                       },    
        { NGX_RTMP_AMF0_NUMBER, NULL,   &stream,    sizeof(stream)          },
    };

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "createStream() called");

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    stream = NGX_RTMP_BROADCAST_MSID;

    return ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_broadcast_publish(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t   sh;

    static double       trans;
    static u_char       pub_name[1024];
    static u_char       pub_type[1024];

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL,   NULL,   NULL,       0                       },
        { NGX_RTMP_AMF0_STRING, NULL,   pub_name,   sizeof(pub_name)        },
        { NGX_RTMP_AMF0_STRING, NULL,   pub_type,   sizeof(pub_type)        },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus", sizeof("onStatus") - 1 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                       },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)         },
    };

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "publish() called; pubName='%s' pubType='%s'",
            pub_name, pub_type);

    if (ngx_rtmp_send_user_stream_begin(s, 
                NGX_RTMP_BROADCAST_MSID) != NGX_OK) 
    {
        return NGX_ERROR;
    }

    ngx_rtmp_broadcast_set_flags(s, NGX_RTMP_BROADCAST_PUBLISHER);

    ngx_str_set(&out_inf[0], "NetStream.Publish.Start");
    ngx_str_set(&out_inf[1], "status");
    ngx_str_set(&out_inf[2], "Publish succeeded.");

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
    ngx_rtmp_header_t   sh;

    static double       trans;
    static u_char       play_name[1024];
    static int          bfalse;

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      out2_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL,   NULL,   NULL,       0                       },
        { NGX_RTMP_AMF0_STRING, NULL,   play_name,   sizeof(play_name)        },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus", sizeof("onStatus") - 1 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                       },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)         },
    };

    static ngx_rtmp_amf0_elt_t      out2_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus", sizeof("onStatus") - 1 },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out2_inf,    sizeof(out2_inf)         },
    };
    
    static ngx_rtmp_amf0_elt_t      out3_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "|RtmpSampleAccess", sizeof("|RtmpSampleAccess") - 1 },
        { NGX_RTMP_AMF0_BOOLEAN, NULL,   &bfalse,    sizeof(bfalse)         },
    };


    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    play_name[0] = 0;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "play() called; playame='%s'",
            play_name);

    if (ngx_rtmp_send_user_stream_begin(s, 
                NGX_RTMP_BROADCAST_MSID) != NGX_OK) 
    {
        return NGX_ERROR;
    }

    ngx_rtmp_broadcast_set_flags(s, NGX_RTMP_BROADCAST_SUBSCRIBER);

    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_BROADCAST_CSID_AMF0;
    sh.msid = h->msid;

    ngx_str_set(&out_inf[0], "NetStream.Play.Reset");
    ngx_str_set(&out_inf[1], "status");
    ngx_str_set(&out_inf[2], "Playing and resetting.");

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_str_set(&out_inf[0], "NetStream.Play.Start");
    ngx_str_set(&out_inf[1], "status");
    ngx_str_set(&out_inf[2], "Started playing.");

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_str_set(&out2_inf[0], "NetStream.Data.Start");
    sh.type = NGX_RTMP_MSG_AMF0_META;

    if (ngx_rtmp_send_amf0(s, &sh, out3_elts,
                sizeof(out3_elts) / sizeof(out3_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_rtmp_send_amf0(s, &sh, out2_elts,
                sizeof(out2_elts) / sizeof(out2_elts[0])) != NGX_OK)
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
        {   NGX_RTMP_AMF0_STRING,   NULL,   
            "@setDataFrame",        sizeof("@setDataFrame") - 1 },
    };

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "data_frame arrived");

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
    sh.msid = h->msid;
    sh.type = h->type;

    ngx_rtmp_prepare_message(s, h, NULL, ctx->data_frame);

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_broadcast_ok(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static double       trans;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)           },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "onStatus",  sizeof("onStatus") - 1 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                       },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)         },
    };

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_broadcast_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_hash_key_t                     *h;
    ngx_rtmp_disconnect_handler_pt     *dh;
    ngx_rtmp_event_handler_pt          *avh;
    ngx_rtmp_broadcast_map_t           *bm;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register audio/video broadcast handler */
    avh = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *avh = ngx_rtmp_broadcast_av;

    avh = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *avh = ngx_rtmp_broadcast_av;

    /* register disconnect handler */
    dh = ngx_array_push(&cmcf->disconnect);

    if (dh == NULL) {
        return NGX_ERROR;
    }

    *dh = ngx_rtmp_broadcast_leave;
    
    /* register AMF0 call handlers */
    ncalls = sizeof(ngx_rtmp_broadcast_map) 
                / sizeof(ngx_rtmp_broadcast_map[0]);
    h = ngx_array_push_n(&cmcf->amf0, ncalls);
    if (h == NULL) {
        return NGX_ERROR;
    }

    bm = ngx_rtmp_broadcast_map;
    for(n = 0; n < ncalls; ++n, ++h, ++bm) {
        h->key = bm->name;
        h->value = bm->handler;
    }

    return NGX_OK;
}
