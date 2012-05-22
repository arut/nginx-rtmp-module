/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_relay_module.h"
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
    ngx_str_t                       app;
    ngx_str_t                       url;
    ngx_rtmp_session_t             *session;
    ngx_rtmp_relay_ctx_t           *publish;
    ngx_rtmp_relay_ctx_t           *play;
    ngx_rtmp_relay_ctx_t           *next;
    unsigned                        relay:1;
};


typedef struct {
    ngx_array_t                     targets;
    ngx_log_t                      *log;
    ngx_uint_t                      nbuckets;
    ngx_msec_t                      buflen;
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
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("relay_buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_relay_app_conf_t, buflen),
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
    racf->buflen = NGX_CONF_UNSET;

    return racf;
}


static char *
ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_relay_app_conf_t *prev = parent;
    ngx_rtmp_relay_app_conf_t *conf = child;

    conf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_ctx_t *) 
            * conf->nbuckets);

    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 5000);

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


typedef ngx_rtmp_relay_ctx_t * (* ngx_rtmp_relay_create_ctx_pt)
    (ngx_rtmp_session_t *s, ngx_str_t *app, ngx_str_t *name, ngx_url_t *url);


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_remote_ctx(ngx_rtmp_session_t *s, ngx_str_t *app,
        ngx_str_t *name, ngx_url_t *url)
{
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_rtmp_addr_conf_t           *addr_conf;
    ngx_rtmp_conf_ctx_t            *addr_ctx;
    ngx_rtmp_session_t             *rs;
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_peer_connection_t          *pc;
    ngx_connection_t               *c;
    ngx_pool_t                     *pool;
    ngx_int_t                       rc;


    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);

    pool = NULL;
    pool = ngx_create_pool(4096, racf->log);
    if (pool == NULL) {
        return NULL;
    }

    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_relay_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    rctx->name.len = name->len;
    rctx->name.data = ngx_palloc(pool, name->len);
    if (rctx->name.data == NULL) {
        goto clear;
    }
    ngx_memcpy(rctx->name.data, name->data, rctx->name.len);

    rctx->app.len = app->len;
    rctx->app.data = ngx_palloc(pool, app->len);
    if (rctx->app.data == NULL) {
        goto clear;
    }
    ngx_memcpy(rctx->app.data, app->data, app->len);

    rctx->url.len = url->url.len;
    rctx->url.data = ngx_palloc(pool, rctx->url.len);
    if (rctx->url.data == NULL) {
        goto clear;
    }
    ngx_memcpy(rctx->url.data, url->url.data, url->url.len);

    rctx->relay = 1;

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto clear;
    }
    pc->log = racf->log;
    pc->get = ngx_rtmp_relay_get_peer;
    pc->free = ngx_rtmp_relay_free_peer;
    pc->name = &url->host;
    pc->socklen = url->socklen;
    pc->sockaddr = (struct sockaddr *)ngx_palloc(pool, pc->socklen);
    if (pc->sockaddr == NULL) {
        goto clear;
    }
    ngx_memcpy(pc->sockaddr, &url->sockaddr, pc->socklen);

    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, racf->log, 0, 
                "relay: connection failed");
        goto clear;
    }
    c = pc->connection;
    c->pool = pool;

    addr_conf = ngx_pcalloc(pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto clear;
    }
    addr_ctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_ctx == NULL) {
        goto clear;
    }
    addr_conf->ctx = addr_ctx;
    addr_ctx->main_conf = s->main_conf;
    addr_ctx->srv_conf  = s->srv_conf;
    ngx_str_set(&addr_conf->addr_text, "ngx-relay");

    rs = ngx_rtmp_init_session(c, addr_conf);
    if (rs == NULL) {
        /* no need to destroy pool */
        return NULL;
    }
    rs->app_conf = s->app_conf;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_relay_module);
    ngx_str_set(&rs->flashver, "ngx-local-relay");
    
    ngx_rtmp_client_handshake(rs, 1);
    return rctx;

clear:
    if (pool) {
        ngx_destroy_pool(pool);
    }
    return NULL;
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_local_ctx(ngx_rtmp_session_t *s, ngx_str_t *app,
        ngx_str_t *name, ngx_url_t *url)
{
    ngx_rtmp_relay_ctx_t           *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_relay_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_relay_module);
    }
    ctx->session = s;
    
    ctx->name.len = name->len;
    ctx->name.data = ngx_palloc(s->connection->pool, name->len);
    if (ctx->name.data == NULL) {
        return NULL;
    }
    ngx_memcpy(ctx->name.data, name->data, ctx->name.len);

    ctx->app.len = app->len;
    ctx->app.data = ngx_palloc(s->connection->pool, app->len);
    if (ctx->app.data == NULL) {
        return NULL;
    }
    ngx_memcpy(ctx->app.data, app->data, app->len);

    return ctx;
}


static ngx_int_t
ngx_rtmp_relay_create(ngx_rtmp_session_t *s, ngx_str_t *app,
        ngx_str_t *name, ngx_url_t *url,
        ngx_rtmp_relay_create_ctx_pt create_publish_ctx,
        ngx_rtmp_relay_create_ctx_pt create_play_ctx)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_ctx_t           *publish_ctx, *play_ctx, **cctx;
    ngx_uint_t                      hash;


    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL) {
        return NGX_ERROR;
    }

    play_ctx = create_play_ctx(s, app, name, url);
    if (play_ctx == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_hash_key(name->data, name->len);
    cctx = &racf->ctx[hash % racf->nbuckets];
    for (; *cctx; cctx = &(*cctx)->next) {
        if ((*cctx)->name.len == name->len
            && !ngx_memcmp(name->data, (*cctx)->name.data, 
                name->len))
        {
            break;
        }
    }

    if (*cctx) {
        play_ctx->publish = (*cctx)->publish;
        play_ctx->next = (*cctx)->play;
        (*cctx)->play = play_ctx;
        return NGX_OK;
    }

    publish_ctx = create_publish_ctx(s, app, name, url);
    if (publish_ctx == NULL) {
        ngx_rtmp_finalize_session(play_ctx->session);
        return NGX_ERROR;
    }

    publish_ctx->publish = publish_ctx;
    publish_ctx->play = play_ctx;
    play_ctx->publish = publish_ctx;
    *cctx = publish_ctx;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *app, ngx_str_t *name,
        ngx_url_t *url)
{
    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "relay: create pull app='%V' name='%V' url='%V'",
            app, name, url);

    return ngx_rtmp_relay_create(s, app, name, url,
            ngx_rtmp_relay_create_remote_ctx,
            ngx_rtmp_relay_create_local_ctx);
}


ngx_int_t
ngx_rtmp_relay_push(ngx_rtmp_session_t *s, ngx_str_t *app, ngx_str_t *name,
        ngx_url_t *url)
{
    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "relay: create push app='%V' name='%V' url='%V'",
            app, name, url);

    return ngx_rtmp_relay_create(s, app, name, url,
            ngx_rtmp_relay_create_local_ctx,
            ngx_rtmp_relay_create_remote_ctx);
}


static ngx_int_t
ngx_rtmp_relay_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx && ctx->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->targets.nelts == 0) {
        goto next;
    }

    name.len = ngx_strlen(v->name);
    name.data = v->name;

    target = racf->targets.elts;
    for (n = 0; n < racf->targets.nelts; ++n, ++target) {
        if (target->push
            && (target->name.len == 0
                || (name.len == target->name.len
                    && !ngx_memcmp(name.data, target->name.data, name.len))))
        {
            if (ngx_rtmp_relay_push(s, &target->app, &name, &target->url) 
                    != NGX_OK) 
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "relay: push failed app='%V' name='%V' url='%V'",
                        &target->app, &target->name, &target->url.url);
            }
        }
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_relay_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx && ctx->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->targets.nelts == 0) {
        goto next;
    }

    name.len = ngx_strlen(v->name);
    name.data = v->name;

    target = racf->targets.elts;
    for (n = 0; n < racf->targets.nelts; ++n, ++target) {
        if (!target->push
            && (target->name.len == 0
                || (name.len == target->name.len
                    && !ngx_memcmp(name.data, target->name.data, name.len))))
        {
            if (ngx_rtmp_relay_pull(s, &target->app, &name, &target->url) 
                    != NGX_OK) 
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "relay: pull failed app='%V' name='%V' url='%V'",
                        &target->app, &target->name, &target->url.url);
            }
            break;
        }
    }

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
    static double               acodecs = 3575;
    static double               vcodecs = 252;

    static ngx_rtmp_amf_elt_t   out_cmd[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("app"),
          NULL, 0 },    /* <-- fill */

        { NGX_RTMP_AMF_STRING, 
          ngx_string("tcUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING, 
          ngx_string("flashVer"),
          "LNX.11,1,102,55", 0 },
          /*"ngx-remote-relay", 0 },*/ /*TODO*/

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          &acodecs, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          &vcodecs, 0 }
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

    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_header_t           h;
    size_t                      len;
    u_char                     *p;


    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    out_cmd[0].data = ctx->app.data;
    out_cmd[0].len  = ctx->app.len;

    /* create good tcUrl; FMS needs it */
    len = sizeof("rtmp://") - 1 + ctx->url.len + 
        sizeof("/") - 1 + ctx->app.len;
    p = ngx_palloc(s->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    out_cmd[1].data = p;
    p = ngx_cpymem(p, "rtmp://", sizeof("rtmp://") - 1);
    p = ngx_cpymem(p, ctx->url.data, ctx->url.len);
    *p++ = '/';
    p = ngx_cpymem(p, ctx->app.data, ctx->app.len);
    out_cmd[1].len = p - (u_char *)out_cmd[1].data;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
        || ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK
        ? NGX_ERROR
        : NGX_OK; 
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
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 }
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
    h.msid = NGX_RTMP_RELAY_MSID;
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
    ngx_rtmp_relay_app_conf_t  *racf;


    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (racf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    out_elts[3].data = ctx->name.data;
    out_elts[3].len  = ctx->name.len;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.msid = NGX_RTMP_RELAY_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
           || ngx_rtmp_send_user_set_buflen(s, NGX_RTMP_RELAY_MSID, 
                   racf->buflen) != NGX_OK
           ? NGX_ERROR
           : NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_on_result(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !ctx->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "relay: _result: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    switch ((ngx_int_t)v.trans) {
        case NGX_RTMP_RELAY_CONNECT_TRANS:
            return ngx_rtmp_relay_send_create_stream(s);

        case NGX_RTMP_RELAY_CREATE_STREAM_TRANS:
            if (ctx->publish != ctx) {
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
ngx_rtmp_relay_on_error(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !ctx->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "relay: _error: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_on_status(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    static ngx_rtmp_amf_elt_t   in_elts_meta[] = {

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !ctx->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (h->type == NGX_RTMP_MSG_AMF_META) {
        ngx_rtmp_receive_amf(s, in, in_elts_meta, 
                sizeof(in_elts_meta) / sizeof(in_elts_meta[0]));
    } else {
        ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]));
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "relay: onStatus: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_handshake_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t               *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || ctx->publish == NULL) {
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
    if (ctx == NULL || ctx->publish == NULL) {
        return NGX_OK;
    }

    /* play end disconnect? */
    if (ctx->publish != ctx) {
        for (cctx = &ctx->publish->play; *cctx; cctx = &(*cctx)->next) {
            if (*cctx == ctx) {
                *cctx = ctx->next;
                break;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0, 
                "relay: play disconnect app='%V' name='%V'",
                &ctx->app, &ctx->name);

        /*TODO: add push reconnect */
        /*
        if (ctx->relay) {
            ngx_rtmp_relay_push(ctx-publish->session,
                    &ctx->publish->name, &target);
        }*/

        if (ctx->publish->play == NULL) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, 
                 ctx->publish->session->connection->log, 0, 
                "relay: publish disconnect empty app='%V' name='%V'",
                &ctx->app, &ctx->name);
            ngx_rtmp_finalize_session(ctx->publish->session);
        }

        return NGX_OK;
    }

    /* publish end disconnect */
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0, 
            "relay: publish disconnect app='%V' name='%V'",
            &ctx->app, &ctx->name);

    for (cctx = &ctx->play; *cctx; cctx = &(*cctx)->next) {
        (*cctx)->publish = NULL;
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, (*cctx)->session->connection->log, 
            0, "relay: play disconnect orphan app='%V' name='%V'",
            &(*cctx)->app, &(*cctx)->name);
        ngx_rtmp_finalize_session((*cctx)->session);
    }
    ctx->publish = NULL;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    hash = ngx_hash_key(ctx->name.data, ctx->name.len);
    cctx = &racf->ctx[hash % racf->nbuckets];
    for (; *cctx && *cctx != ctx; cctx = &(*cctx)->next);
    if (*cctx) {
        *cctx = ctx->next;
    }

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

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_error");
    ch->handler = ngx_rtmp_relay_on_error;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "onStatus");
    ch->handler = ngx_rtmp_relay_on_status;

    return NGX_OK;
}
