/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


static ngx_int_t ngx_rtmp_broadcast_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_broadcast_create_srv_conf(ngx_conf_t *cf);
static char * ngx_rtmp_broadcast_merge_srv_conf(ngx_conf_t *cf, 
        void *parent, void *child);


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


#define NGX_RTMP_PUBLISHER              0x01
#define NGX_RTMP_SUBSCRIBER             0x02

#define NGX_RTMP_SESSION_HASH_SIZE      16384


typedef struct ngx_rtmp_broadcast_ctx_s {
    ngx_str_t                           stream;
    ngx_rtmp_session_t                 *session;
    struct ngx_rtmp_broadcast_ctx_s    *next;
    ngx_uint_t                          flags; /* publisher/subscriber */
    uint32_t                            csid;
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
ngx_rtmp_broadcast_get_head(ngx_rtmp_broadcast_ctx_t *ctx)
{
    ngx_rtmp_broadcast_srv_conf_t  *bscf;

    bscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_broadcast_module);

    return &bscf->contexts[
        ngx_hash_key(ctx->stream.data, ctx->stream.len) 
        % bscf->buckets];
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
                   "join broadcast stream '%V'", &stream);

    s->stream = *stream;
    hctx = ngx_rtmp_broadcast_get_head(ctx);
    ctx->next = *hctx;
    ctx->flags = flags;
    *hctx = ctx;
}


static void
ngx_rtmp_broadcast_leave(ngx_rtmp_session_t *s)
{
    ngx_connection_t               *c;
    ngx_rtmp_broadcast_ctx_t       *ctx, **hctx;

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_broadcast_module);
    if (ctx == NULL || !ctx->stream.len) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "leave broadcast stream '%V'", &s->stream);

    hctx = ngx_rtmp_broadcast_get_head(ctx);
    ngx_str_null(&ctx->stream);

    for(; *hctx; hctx = &(*hctx)->next) {
        if (*hctx == ctx) {
            *hctx = (*hctx)->next;
            return;
        }
    }
}


static ngx_rtmp_broadcast_connect(ngx_rtmp_session_t *s, double in_trans,
        ngx_chain_t *in)
{
    static double       trans;
    static u_char       app[1024];
    static u_char       url[1024];

    static ngx_rtmp_amf0_elt_t      in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",          app,        sizeof(app)     },
        { NGX_RTMP_AMF0_STRING, "pageUrl",      url,        sizeof(utl)     },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,       0               },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_OBJECT, NULL,   in_cmd,     sizeof(in_cmd)          },
        { NGX_RTMP_AMF0_NULL,   NULL,   NULL,       0                       },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  sizeof("_result") - 1   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                       },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)         },
    };

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    trans = in_trans;
    ngx_str_set(&inf[0], "NetConnection.Connect.Success");
    ngx_str_set(&inf[1], "status");
    ngx_str_set(&inf[2], "Connection succeeded.");

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "connect() called; app='%s' url='%s'",
            app, url);

    /*ngx_rtmp_broadcast_join(s, app);*/

    return ngx_rtmp_send_ack_size(s, 65536)
        || ngx_rtmp_send_bandwidth(s, 65536, NGX_RTMP_LIMIT_SOFT)
        || ngx_rtmp_send_user_stream_begin(s, 1)
        || ngx_rtmp_send_amf0(s, 3, 1, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_ERROR
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_broadcast_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_hash_key_t                     *h;
    ngx_rtmp_disconnect_handler_pt     *dh;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_rtmp_module);

    /* add connect() handler */
    h = ngx_array_push(&cmcf->calls);

    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&h->key, "connect");
    h->value = ngx_rtmp_broadcast_connect;

    /* add disconnect handler */
    dh = ngx_array_push(&cmcf->disconnect);

    if (dh == NULL) {
        return NGX_ERROR;
    }

    *dh = ngx_rtmp_broadcast_leave;

    return NGX_OK;
}
