/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_play_pt             next_play;


static ngx_int_t ngx_rtmp_relay_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_relay_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);
static char * ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf);
static ngx_int_t ngx_rtmp_relay_publish(ngx_rtmp_session_t *s, 
        ngx_rtmp_publish_t *v);


/*                _____
 * =push=        |     |---publish--->
 * ---publish--->|     |---publish--->
 *     (src)     |     |---publish--->
 *                -----  (next,relay)
 *                      need reconnect
 * =pull=         _____
 * -----play---->|     |
 * -----play---->|     |----play----->
 * -----play---->|     | (src,relay)
 *     (next)     -----
 */


typedef struct {
    ngx_url_t                       url;
    ngx_str_t                       app;
    ngx_str_t                       name;
    unsigned                        push:1;
} ngx_rtmp_relay_target_t;


typedef struct ngx_rtmp_relay_ctx_s ngx_rtmp_relay_ctx_t;

struct ngx_rtmp_relay_ctx_s {
    ngx_str_t                       name;
    ngx_rtmp_session_t             *session;
    ngx_rtmp_relay_target_t        *target;
    ngx_rtmp_relay_ctx_t           *src;
    ngx_rtmp_relay_ctx_t           *dst;
    ngx_rtmp_relay_ctx_t           *next;
    ngx_event_t                     recon;
};


typedef struct {
    ngx_array_t                     targets;
    ngx_log_t                      *log;
    ngx_uint_t                      nbuckets;
    ngx_rtmp_relay_ctx_t          **ctx;
} ngx_rtmp_relay_app_conf_t;


#define NGX_RTMP_RELAY_CONNECT_TRANS            1
#define NGX_RTMP_RELAY_CREATE_STREAM_TRANS      2


#define NGX_RTMP_RELAY_CSID_AMF_INI             3
#define NGX_RTMP_RELAY_CSID_AMF                 5
#define NGX_RTMP_RELAY_MSID                     1


/*
push remoteapp mystream 192.168.0.10
push mystream 192.168.0.10
push 192.168.0.10
*/

static ngx_command_t  ngx_rtmp_relay_commands[] = {

    { ngx_string("push"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pull"),
      NGX_RTMP_APP_CONF| NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_relay_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_relay_postconfiguration,       /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_relay_create_app_conf,         /* create app configuration */
    ngx_rtmp_relay_merge_app_conf           /* merge app configuration */
};


ngx_module_t  ngx_rtmp_relay_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_relay_module_ctx,             /* module context */
    ngx_rtmp_relay_commands,                /* module directives */
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
ngx_rtmp_relay_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_relay_app_conf_t     *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_app_conf_t));
    if (racf == NULL) {
        return NULL;
    }

    ngx_array_init(&racf->targets, cf->pool, 1, sizeof(ngx_rtmp_relay_target_t));
    racf->nbuckets = 1024;
    racf->log = &cf->cycle->new_log;

    return racf;
}


static char *
ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_relay_app_conf_t *conf = child;

    conf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_ctx_t *) 
            * conf->nbuckets);

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_rtmp_relay_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void 
ngx_rtmp_relay_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}


static void
ngx_rtmp_relay_create(ngx_rtmp_session_t *s,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_peer_connection_t          *pc;
    ngx_rtmp_session_t             *rs;
    ngx_connection_t               *c;
    ngx_pool_t                     *pool;
    ngx_int_t                       rc;
    ngx_rtmp_relay_ctx_t           *rctx, **cctx;
    ngx_uint_t                      hash;
    ngx_rtmp_addr_conf_t            addr_conf;
    ngx_rtmp_conf_ctx_t             addr_ctx;
    ngx_rtmp_relay_ctx_t           *ctx;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return;
    }

    pool = NULL;
    pool = ngx_create_pool(4096, racf->log);
    if (pool == NULL) {
        return;
    }

    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_relay_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    rctx->target = target;
    rctx->name.len = ctx->name.len;
    rctx->name.data = ngx_palloc(pool, ctx->name.len);
    ngx_memcpy(rctx->name.data, ctx->name.data, ctx->name.len);

    hash = ngx_hash_key(rctx->name.data, rctx->name.len);
    cctx = &racf->ctx[hash % racf->nbuckets];

    if (target->push) {
        ctx->next = *cctx;
        *cctx = ctx;
        ctx->src = ctx;
        ctx->dst = rctx;
        rctx->src = ctx;
    } else {
        rctx->next = *cctx;
        *cctx = rctx;
        rctx->src = rctx;
        rctx->dst = ctx;
        ctx->src = rctx;
    }

    /* connect */
    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto clear;
    }

    pc->log      = racf->log;
    pc->get      = ngx_rtmp_relay_get_peer;
    pc->free     = ngx_rtmp_relay_free_peer;
    pc->name     = &target->url.host;
    pc->socklen  = target->url.socklen;
    pc->sockaddr = (struct sockaddr *)&target->url.sockaddr;

    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, racf->log, 0, 
                "relay: connection failed");
        goto clear;
    }

    c = pc->connection;
    c->pool = pool;

    ngx_memzero(&addr_conf, sizeof(addr_conf));
    addr_conf.ctx = &addr_ctx;
    addr_ctx.main_conf = s->main_conf;
    addr_ctx.srv_conf  = s->srv_conf;
    ngx_str_set(&addr_conf.addr_text, "ngx-relay");

    rs = ngx_rtmp_init_session(c, &addr_conf);
    if (rs == NULL) {
        /* no need to destroy pool */
        return;
    }

    rs->app_conf = s->app_conf;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_relay_module);

    ngx_str_set(&rs->flashver, "ngx-local-relay");

    ngx_rtmp_client_handshake(rs);

    return;

clear:
    if (pool) {
        ngx_destroy_pool(pool);
    }
}


static ngx_int_t
ngx_rtmp_relay_init(ngx_rtmp_session_t *s, u_char *name)
{
    size_t                          n, len;
    ngx_rtmp_relay_target_t        *target;
    ngx_uint_t                      hash;
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_ctx_t           *sctx, *ctx, **cctx;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL) {
        return NGX_ERROR;
    }

    len = ngx_strlen(name);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_relay_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_relay_module);
    }
    ctx->session = s;
    ctx->name.len = len;
    ctx->name.data = ngx_palloc(s->connection->pool, len);
    ngx_memcpy(ctx->name.data, name, len);

    /* find relay stream */
    hash = ngx_hash_key(name, len);
    cctx = &racf->ctx[hash % racf->nbuckets];
    for (sctx = *cctx; sctx; sctx = sctx->next) {
        if (sctx->name.len == len
            && !ngx_memcmp(name, sctx->name.data, len))
        {
            break;
        }
    }

    if (sctx) {
        /* add player to pull stream */
        if (sctx->target) {
            ctx->src = sctx->src;
            ctx->next = sctx->dst;
            sctx->dst = ctx;
        }
        return NGX_OK;
    }

    /* create relays */
    target = racf->targets.elts;
    for (n = 0; n < racf->targets.nelts; ++n, ++target) {
        if (target->name.len == 0 ||
            (len == target->name.len
             && !ngx_memcmp(name, target->name.data, len)))
        {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "relay: create: name='%s' url='%V'",
                name, &target->url);

            ngx_rtmp_relay_create(s, target);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->targets.nelts == 0) {
        goto next;
    }

    ngx_rtmp_relay_init(s, v->name);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_relay_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->targets.nelts == 0) {
        goto next;
    }

    ngx_rtmp_relay_init(s, v->name);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_relay_play_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_t             v;
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));
    *(ngx_cpymem(v.name, ctx->name.data, 
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;

    return ngx_rtmp_play(s, &v);
}


static ngx_int_t
ngx_rtmp_relay_publish_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_publish_t          v;
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_publish_t));
    *(ngx_cpymem(v.name, ctx->name.data, 
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;

    return ngx_rtmp_publish(s, &v);
}


static ngx_int_t
ngx_rtmp_relay_send_connect(ngx_rtmp_session_t *s)
{
    static double               trans = NGX_RTMP_RELAY_CONNECT_TRANS;

    static ngx_rtmp_amf_elt_t   out_cmd[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("app"),
          NULL, 0 },    /* <-- to fill */

        { NGX_RTMP_AMF_STRING, 
          ngx_string("flashVer"),
          "ngx-remote-relay", 0 }
    };

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "connect", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_cmd, sizeof(out_cmd) }
    };

    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_header_t           h;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    out_cmd[0].data = ctx->target->app.data;
    out_cmd[0].len  = ctx->target->app.len;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_send_create_stream(ngx_rtmp_session_t *s)
{
    static double               trans = NGX_RTMP_RELAY_CREATE_STREAM_TRANS;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "createStream", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 }
    };

    ngx_rtmp_header_t           h;


    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_send_publish(ngx_rtmp_session_t *s)
{
    static double               trans;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "publish", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- to fill */

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "live", 0 }
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_relay_ctx_t       *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    out_elts[3].data = ctx->name.data;
    out_elts[3].len  = ctx->name.len;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_send_play(ngx_rtmp_session_t *s)
{
    static double               trans;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "play", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- to fill */
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_relay_ctx_t       *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    out_elts[3].data = ctx->name.data;
    out_elts[3].len  = ctx->name.len;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_on_result(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static double               trans;
    ngx_rtmp_relay_ctx_t       *ctx;

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || ctx->target == NULL) {
        return NGX_OK;
    }

    /* TODO: add analyzing <code> for errors */
    trans = 0;
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    switch ((ngx_int_t)trans) {
        case NGX_RTMP_RELAY_CONNECT_TRANS:
            return ngx_rtmp_relay_send_create_stream(s);

        case NGX_RTMP_RELAY_CREATE_STREAM_TRANS:
            if (ctx->target->push) {
                if (ngx_rtmp_relay_send_publish(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_relay_play_local(s);

            } else {
                if (ngx_rtmp_relay_send_play(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_relay_publish_local(s);
            }

        default:
            return NGX_OK;
    }
}


static ngx_int_t
ngx_rtmp_relay_handshake_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t               *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || ctx->src == NULL) {
        return NGX_OK;
    }

    return ngx_rtmp_relay_send_connect(s);
}


static ngx_int_t
ngx_rtmp_relay_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_app_conf_t          *racf;
    ngx_rtmp_relay_ctx_t               *ctx, **cctx;
    ngx_uint_t                          hash;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || ctx->src == NULL) {
        return NGX_OK;
    }

    /* destination end disconnecting */
    if (ctx->src != ctx) {
        for (cctx = &ctx->src->dst; *cctx; cctx = &(*cctx)->next) {
            if (*cctx == ctx) {
                *cctx = ctx->next;
                break;
            }
        }

        /*TODO: add push reconnect */
        /* if (ctx->target) {...} */

        if (ctx->src->dst == NULL) {
            ngx_rtmp_finalize_session(ctx->src->session);
        }

        return NGX_OK;
    }

    /* source end disconnecting */
    for (cctx = &ctx->src->dst; *cctx; cctx = &(*cctx)->next) {
        (*cctx)->src = NULL;
        ngx_rtmp_finalize_session((*cctx)->session);
    }
    ctx->src = NULL;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    hash = ngx_hash_key(ctx->name.data, ctx->name.len);
    cctx = &racf->ctx[hash % racf->nbuckets];
    for (; *cctx && *cctx != ctx; cctx = &(*cctx)->next);
    if (*cctx) {
        *cctx = ctx->next;
    }
    ngx_rtmp_finalize_session(ctx->session);

    return NGX_OK;
}


static char *
ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value;
    ngx_rtmp_core_app_conf_t           *cacf;
    ngx_rtmp_relay_app_conf_t          *racf;
    ngx_rtmp_relay_target_t            *target;
    ngx_url_t                          *u;

    value = cf->args->elts;

    cacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);
    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_relay_module);

    target = ngx_array_push(&racf->targets);
    ngx_memzero(target, sizeof(ngx_rtmp_relay_target_t));
    if (value[0].data[3] == 'h') { /* push */
        target->push = 1;
    }

    u = &target->url;
    u->default_port = 1935;
    u->uri_part = 1;

    switch (cf->args->nelts) {
        case 4:
            target->app = value[1];
            target->name = value[2];
            u->url = value[3];
            break;

        case 3:
            target->app = cacf->name;
            target->name = value[1];
            u->url = value[2];
            break;

        case 2:
            target->app = cacf->name;
            u->url = value[1];
            break;
    }
    
    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_relay_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);


    h = ngx_array_push(&cmcf->events[NGX_RTMP_HANDSHAKE_DONE]);
    *h = ngx_rtmp_relay_handshake_done;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_relay_disconnect;


    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_relay_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_relay_play;


    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_result");
    ch->handler = ngx_rtmp_relay_on_result;

    return NGX_OK;
}
