
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_play_pt             next_play;
static ngx_rtmp_delete_stream_pt    next_delete_stream;
static ngx_rtmp_close_stream_pt     next_close_stream;


static ngx_int_t ngx_rtmp_relay_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_rtmp_relay_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_relay_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char * ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_relay_publish(ngx_rtmp_session_t *s,
       ngx_rtmp_publish_t *v);
static ngx_rtmp_relay_ctx_t * ngx_rtmp_relay_create_connection(
       ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
       ngx_rtmp_relay_target_t *target);


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
    ngx_array_t                 pulls;         /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 pushes;        /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 static_pulls;  /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 static_events; /* ngx_event_t * */
    ngx_log_t                  *log;
    ngx_uint_t                  nbuckets;
    ngx_msec_t                  buflen;
    ngx_flag_t                  session_relay;
    ngx_msec_t                  push_reconnect;
    ngx_msec_t                  pull_reconnect;
    ngx_rtmp_relay_ctx_t        **ctx;
} ngx_rtmp_relay_app_conf_t;


typedef struct {
    ngx_rtmp_conf_ctx_t         cctx;
    ngx_rtmp_relay_target_t    *target;
} ngx_rtmp_relay_static_t;


#define NGX_RTMP_RELAY_CONNECT_TRANS            1
#define NGX_RTMP_RELAY_CREATE_STREAM_TRANS      2


#define NGX_RTMP_RELAY_CSID_AMF_INI             3
#define NGX_RTMP_RELAY_CSID_AMF                 5
#define NGX_RTMP_RELAY_MSID                     1


/* default flashVer */
#define NGX_RTMP_RELAY_FLASHVER                 "LNX.11,1,102,55"


static ngx_command_t  ngx_rtmp_relay_commands[] = {

    { ngx_string("push"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pull"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
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

    { ngx_string("push_reconnect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_relay_app_conf_t, push_reconnect),
      NULL },

    { ngx_string("pull_reconnect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_relay_app_conf_t, pull_reconnect),
      NULL },

    { ngx_string("session_relay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_relay_app_conf_t, session_relay),
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
    ngx_rtmp_relay_init_process,            /* init process */
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

    if (ngx_array_init(&racf->pushes, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    if (ngx_array_init(&racf->pulls, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    if (ngx_array_init(&racf->static_pulls, cf->pool, 1, sizeof(void *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&racf->static_events, cf->pool, 1, sizeof(void *))
        != NGX_OK)
    {
        return NULL;
    }

    racf->nbuckets = 1024;
    racf->log = &cf->cycle->new_log;
    racf->buflen = NGX_CONF_UNSET_MSEC;
    racf->session_relay = NGX_CONF_UNSET;
    racf->push_reconnect = NGX_CONF_UNSET_MSEC;
    racf->pull_reconnect = NGX_CONF_UNSET_MSEC;

    return racf;
}


static char *
ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_relay_app_conf_t  *prev = parent;
    ngx_rtmp_relay_app_conf_t  *conf = child;

    conf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_ctx_t *)
            * conf->nbuckets);

    ngx_conf_merge_value(conf->session_relay, prev->session_relay, 0);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 5000);
    ngx_conf_merge_msec_value(conf->push_reconnect, prev->push_reconnect,
            3000);
    ngx_conf_merge_msec_value(conf->pull_reconnect, prev->pull_reconnect,
            3000);

    return NGX_CONF_OK;
}


static void
ngx_rtmp_relay_static_pull_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_relay_static_t    *rs = ev->data;

    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_relay_app_conf_t  *racf;

    racf = ngx_rtmp_get_module_app_conf(&rs->cctx, ngx_rtmp_relay_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                   "relay: reconnecting static pull");

    ctx = ngx_rtmp_relay_create_connection(&rs->cctx, &rs->target->name,
                                           rs->target);
    if (ctx) {
        ctx->session->static_relay = 1;
        ctx->static_evt = ev;
        return;
    }

    ngx_add_timer(ev, racf->pull_reconnect);
}


static void
ngx_rtmp_relay_push_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_session_t             *s = ev->data;

    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_ctx_t           *ctx, *pctx;
    ngx_uint_t                      n;
    ngx_rtmp_relay_target_t        *target, **t;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "relay: push reconnect");

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return;
    }

    t = racf->pushes.elts;
    for (n = 0; n < racf->pushes.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (ctx->name.len != target->name.len ||
            ngx_memcmp(ctx->name.data, target->name.data, ctx->name.len)))
        {
            continue;
        }

        for (pctx = ctx->play; pctx; pctx = pctx->next) {
            if (pctx->tag == &ngx_rtmp_relay_module &&
                pctx->data == target)
            {
                break;
            }
        }

        if (pctx) {
            continue;
        }

        if (ngx_rtmp_relay_push(s, &ctx->name, target) == NGX_OK) {
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "relay: push reconnect failed name='%V' app='%V' "
                "playpath='%V' url='%V'",
                &ctx->name, &target->app, &target->play_path,
                &target->url.url);

        if (!ctx->push_evt.timer_set) {
            ngx_add_timer(&ctx->push_evt, racf->push_reconnect);
        }
    }
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
    (ngx_rtmp_session_t *s, ngx_str_t *name, ngx_rtmp_relay_target_t *target);


static ngx_int_t
ngx_rtmp_relay_copy_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    if (src->len == 0) {
        return NGX_OK;
    }
    dst->len = src->len;
    dst->data = ngx_palloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    return NGX_OK;
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_connection(ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_rtmp_addr_conf_t           *addr_conf;
    ngx_rtmp_conf_ctx_t            *addr_ctx;
    ngx_rtmp_session_t             *rs;
    ngx_peer_connection_t          *pc;
    ngx_connection_t               *c;
    ngx_addr_t                     *addr;
    ngx_pool_t                     *pool;
    ngx_int_t                       rc;
    ngx_str_t                       v, *uri;
    u_char                         *first, *last, *p;

    racf = ngx_rtmp_get_module_app_conf(cctx, ngx_rtmp_relay_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                   "relay: create remote context");

    pool = NULL;
    pool = ngx_create_pool(4096, racf->log);
    if (pool == NULL) {
        return NULL;
    }

    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_relay_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    if (name && ngx_rtmp_relay_copy_str(pool, &rctx->name, name) != NGX_OK) {
        goto clear;
    }

    if (ngx_rtmp_relay_copy_str(pool, &rctx->url, &target->url.url) != NGX_OK) {
        goto clear;
    }

    rctx->tag = target->tag;
    rctx->data = target->data;

#define NGX_RTMP_RELAY_STR_COPY(to, from)                                     \
    if (ngx_rtmp_relay_copy_str(pool, &rctx->to, &target->from) != NGX_OK) {  \
        goto clear;                                                           \
    }

    NGX_RTMP_RELAY_STR_COPY(app,        app);
    NGX_RTMP_RELAY_STR_COPY(tc_url,     tc_url);
    NGX_RTMP_RELAY_STR_COPY(page_url,   page_url);
    NGX_RTMP_RELAY_STR_COPY(swf_url,    swf_url);
    NGX_RTMP_RELAY_STR_COPY(flash_ver,  flash_ver);
    NGX_RTMP_RELAY_STR_COPY(play_path,  play_path);

    rctx->live  = target->live;
    rctx->start = target->start;
    rctx->stop  = target->stop;

#undef NGX_RTMP_RELAY_STR_COPY

    if (rctx->app.len == 0 || rctx->play_path.len == 0) {
        /* parse uri */
        uri = &target->url.uri;
        first = uri->data;
        last  = uri->data + uri->len;
        if (first != last && *first == '/') {
            ++first;
        }

        if (first != last) {

            /* deduce app */
            p = ngx_strlchr(first, last, '/');
            if (p == NULL) {
                p = last;
            }

            if (rctx->app.len == 0 && first != p) {
                v.data = first;
                v.len = p - first;
                if (ngx_rtmp_relay_copy_str(pool, &rctx->app, &v) != NGX_OK) {
                    goto clear;
                }
            }

            /* deduce play_path */
            if (p != last) {
                ++p;
            }

            if (rctx->play_path.len == 0 && p != last) {
                v.data = p;
                v.len = last - p;
                if (ngx_rtmp_relay_copy_str(pool, &rctx->play_path, &v)
                        != NGX_OK)
                {
                    goto clear;
                }
            }
        }
    }

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto clear;
    }

    if (target->url.naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, racf->log, 0,
                      "relay: no address");
        goto clear;
    }

    /* get address */
    addr = &target->url.addrs[target->counter % target->url.naddrs];
    target->counter++;

    /* copy log to keep shared log unchanged */
    rctx->log = *racf->log;
    pc->log = &rctx->log;
    pc->get = ngx_rtmp_relay_get_peer;
    pc->free = ngx_rtmp_relay_free_peer;
    pc->name = &addr->name;
    pc->socklen = addr->socklen;
    pc->sockaddr = (struct sockaddr *)ngx_palloc(pool, pc->socklen);
    if (pc->sockaddr == NULL) {
        goto clear;
    }
    ngx_memcpy(pc->sockaddr, addr->sockaddr, pc->socklen);

    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                "relay: connection failed");
        goto clear;
    }
    c = pc->connection;
    c->pool = pool;
    c->addr_text = rctx->url;

    addr_conf = ngx_pcalloc(pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto clear;
    }
    addr_ctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_ctx == NULL) {
        goto clear;
    }
    addr_conf->ctx = addr_ctx;
    addr_ctx->main_conf = cctx->main_conf;
    addr_ctx->srv_conf  = cctx->srv_conf;
    ngx_str_set(&addr_conf->addr_text, "ngx-relay");

    rs = ngx_rtmp_init_session(c, addr_conf);
    if (rs == NULL) {
        /* no need to destroy pool */
        return NULL;
    }
    rs->app_conf = cctx->app_conf;
    rs->relay = 1;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_relay_module);
    ngx_str_set(&rs->flashver, "ngx-local-relay");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    ngx_rtmp_client_handshake(rs, 1);
    return rctx;

clear:
    if (pool) {
        ngx_destroy_pool(pool);
    }
    return NULL;
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_remote_ctx(ngx_rtmp_session_t *s, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_conf_ctx_t         cctx;

    cctx.app_conf = s->app_conf;
    cctx.srv_conf = s->srv_conf;
    cctx.main_conf = s->main_conf;

    return ngx_rtmp_relay_create_connection(&cctx, name, target);
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_local_ctx(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_relay_ctx_t           *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "relay: create local context");

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_relay_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_relay_module);
    }
    ctx->session = s;

    ctx->push_evt.data = s;
    ctx->push_evt.log = s->connection->log;
    ctx->push_evt.handler = ngx_rtmp_relay_push_reconnect;

    if (ctx->publish) {
        return NULL;
    }

    if (ngx_rtmp_relay_copy_str(s->connection->pool, &ctx->name, name)
            != NGX_OK)
    {
        return NULL;
    }

    return ctx;
}


static ngx_int_t
ngx_rtmp_relay_create(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target,
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

    play_ctx = create_play_ctx(s, name, target);
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

    publish_ctx = create_publish_ctx(s, name, target);
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
ngx_rtmp_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "relay: create pull name='%V' app='%V' playpath='%V' url='%V'",
            name, &target->app, &target->play_path, &target->url.url);

    return ngx_rtmp_relay_create(s, name, target,
            ngx_rtmp_relay_create_remote_ctx,
            ngx_rtmp_relay_create_local_ctx);
}


ngx_int_t
ngx_rtmp_relay_push(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "relay: create push name='%V' app='%V' playpath='%V' url='%V'",
            name, &target->app, &target->play_path, &target->url.url);

    return ngx_rtmp_relay_create(s, name, target,
            ngx_rtmp_relay_create_local_ctx,
            ngx_rtmp_relay_create_remote_ctx);
}


static ngx_int_t
ngx_rtmp_relay_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target, **t;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    if (s->auto_pushed) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx && s->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->pushes.nelts == 0) {
        goto next;
    }

    name.len = ngx_strlen(v->name);
    name.data = v->name;

    t = racf->pushes.elts;
    for (n = 0; n < racf->pushes.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (name.len != target->name.len ||
            ngx_memcmp(name.data, target->name.data, name.len)))
        {
            continue;
        }

        if (ngx_rtmp_relay_push(s, &name, target) == NGX_OK) {
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "relay: push failed name='%V' app='%V' "
                "playpath='%V' url='%V'",
                &name, &target->app, &target->play_path,
                &target->url.url);

        if (!ctx->push_evt.timer_set) {
            ngx_add_timer(&ctx->push_evt, racf->push_reconnect);
        }
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_relay_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target, **t;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx && s->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->pulls.nelts == 0) {
        goto next;
    }

    name.len = ngx_strlen(v->name);
    name.data = v->name;

    t = racf->pulls.elts;
    for (n = 0; n < racf->pulls.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (name.len != target->name.len ||
            ngx_memcmp(name.data, target->name.data, name.len)))
        {
            continue;
        }

        if (ngx_rtmp_relay_pull(s, &name, target) == NGX_OK) {
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "relay: pull failed name='%V' app='%V' "
                "playpath='%V' url='%V'",
                &name, &target->app, &target->play_path,
                &target->url.url);
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
    v.silent = 1;
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
    v.silent = 1;
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
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("flashVer"),
          NULL, 0 }, /* <-- fill */

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

    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_header_t           h;
    size_t                      len, url_len;
    u_char                     *p, *url_end;


    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (cacf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    /* app */
    if (ctx->app.len) {
        out_cmd[0].data = ctx->app.data;
        out_cmd[0].len  = ctx->app.len;
    } else {
        out_cmd[0].data = cacf->name.data;
        out_cmd[0].len  = cacf->name.len;
    }

    /* tcUrl */
    if (ctx->tc_url.len) {
        out_cmd[1].data = ctx->tc_url.data;
        out_cmd[1].len  = ctx->tc_url.len;
    } else {
        len = sizeof("rtmp://") - 1 + ctx->url.len +
            sizeof("/") - 1 + ctx->app.len;
        p = ngx_palloc(s->connection->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        out_cmd[1].data = p;
        p = ngx_cpymem(p, "rtmp://", sizeof("rtmp://") - 1);

        url_len = ctx->url.len;
        url_end = ngx_strlchr(ctx->url.data, ctx->url.data + ctx->url.len, '/');
        if (url_end) {
            url_len = (size_t) (url_end - ctx->url.data);
        }

        p = ngx_cpymem(p, ctx->url.data, url_len);
        *p++ = '/';
        p = ngx_cpymem(p, ctx->app.data, ctx->app.len);
        out_cmd[1].len = p - (u_char *)out_cmd[1].data;
    }

    /* pageUrl */
    out_cmd[2].data = ctx->page_url.data;
    out_cmd[2].len  = ctx->page_url.len;

    /* swfUrl */
    out_cmd[3].data = ctx->swf_url.data;
    out_cmd[3].len  = ctx->swf_url.len;

    /* flashVer */
    if (ctx->flash_ver.len) {
        out_cmd[4].data = ctx->flash_ver.data;
        out_cmd[4].len  = ctx->flash_ver.len;
    } else {
        out_cmd[4].data = NGX_RTMP_RELAY_FLASHVER;
        out_cmd[4].len  = sizeof(NGX_RTMP_RELAY_FLASHVER) - 1;
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK
        || ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK
        || ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
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

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        out_elts[3].data = ctx->name.data;
        out_elts[3].len  = ctx->name.len;
    }

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
    static double               start, duration;

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
          NULL, 0 }, /* <- fill */

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &start, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &duration, 0 },
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_relay_app_conf_t  *racf;


    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (racf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        out_elts[3].data = ctx->name.data;
        out_elts[3].len  = ctx->name.len;
    }

    if (ctx->live) {
        start = -1000;
        duration = -1000;
    } else {
        start    = (ctx->start ? ctx->start : -2000);
        duration = (ctx->stop  ? ctx->stop - ctx->start : -1000);
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.msid = NGX_RTMP_RELAY_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
           || ngx_rtmp_send_set_buflen(s, NGX_RTMP_RELAY_MSID,
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
    if (ctx == NULL || !s->relay) {
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
            if (ctx->publish != ctx && !s->static_relay) {
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
    if (ctx == NULL || !s->relay) {
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
    if (ctx == NULL || !s->relay) {
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
    ngx_rtmp_relay_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    return ngx_rtmp_relay_send_connect(s);
}


static void
ngx_rtmp_relay_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_relay_app_conf_t          *racf;
    ngx_rtmp_relay_ctx_t               *ctx, **cctx;
    ngx_uint_t                          hash;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return;
    }

    if (s->static_relay) {
        ngx_add_timer(ctx->static_evt, racf->pull_reconnect);
    }

    if (ctx->publish == NULL) {
        return;
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

        /* push reconnect */
        if (s->relay && ctx->tag == &ngx_rtmp_relay_module &&
            !ctx->publish->push_evt.timer_set)
        {
            ngx_add_timer(&ctx->publish->push_evt, racf->push_reconnect);
        }

#ifdef NGX_DEBUG
        {
            ngx_uint_t  n = 0;
            for (cctx = &ctx->publish->play; *cctx; cctx = &(*cctx)->next, ++n);
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
                "relay: play left after disconnect app='%V' name='%V': %ui",
                &ctx->app, &ctx->name, n);
        }
#endif

        if (ctx->publish->play == NULL && ctx->publish->session->relay) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP,
                 ctx->publish->session->connection->log, 0,
                "relay: publish disconnect empty app='%V' name='%V'",
                &ctx->app, &ctx->name);
            ngx_rtmp_finalize_session(ctx->publish->session);
        }

        ctx->publish = NULL;

        return;
    }

    /* publish end disconnect */
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
            "relay: publish disconnect app='%V' name='%V'",
            &ctx->app, &ctx->name);

    if (ctx->push_evt.timer_set) {
        ngx_del_timer(&ctx->push_evt);
    }

    for (cctx = &ctx->play; *cctx; cctx = &(*cctx)->next) {
        (*cctx)->publish = NULL;
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, (*cctx)->session->connection->log,
            0, "relay: play disconnect orphan app='%V' name='%V'",
            &(*cctx)->app, &(*cctx)->name);
        ngx_rtmp_finalize_session((*cctx)->session);
    }
    ctx->publish = NULL;

    hash = ngx_hash_key(ctx->name.data, ctx->name.len);
    cctx = &racf->ctx[hash % racf->nbuckets];
    for (; *cctx && *cctx != ctx; cctx = &(*cctx)->next);
    if (*cctx) {
        *cctx = ctx->next;
    }
}


static ngx_int_t
ngx_rtmp_relay_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_relay_app_conf_t  *racf;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf && !racf->session_relay) {
        ngx_rtmp_relay_close(s);
    }

    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_relay_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_relay_close(s);

    return next_delete_stream(s, v);
}


static char *
ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value, v, n;
    ngx_rtmp_relay_app_conf_t          *racf;
    ngx_rtmp_relay_target_t            *target, **t;
    ngx_url_t                          *u;
    ngx_uint_t                          i;
    ngx_int_t                           is_pull, is_static;
    ngx_event_t                       **ee, *e;
    ngx_rtmp_relay_static_t            *rs;
    u_char                             *p;

    value = cf->args->elts;

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_relay_module);

    is_pull = (value[0].data[3] == 'l');
    is_static = 0;

    target = ngx_pcalloc(cf->pool, sizeof(*target));
    if (target == NULL) {
        return NGX_CONF_ERROR;
    }

    target->tag = &ngx_rtmp_relay_module;
    target->data = target;

    u = &target->url;
    u->default_port = 1935;
    u->uri_part = 1;
    u->url = value[1];

    if (ngx_strncasecmp(u->url.data, (u_char *) "rtmp://", 7) == 0) {
        u->url.data += 7;
        u->url.len  -= 7;
    }

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }

    value += 2;
    for (i = 2; i < cf->args->nelts; ++i, ++value) {
        p = ngx_strlchr(value->data, value->data + value->len, '=');

        if (p == NULL) {
            n = *value;
            ngx_str_set(&v, "1");

        } else {
            n.data = value->data;
            n.len  = p - value->data;

            v.data = p + 1;
            v.len  = value->data + value->len - p - 1;
        }

#define NGX_RTMP_RELAY_STR_PAR(name, var)                                     \
        if (n.len == sizeof(name) - 1                                         \
            && ngx_strncasecmp(n.data, (u_char *) name, n.len) == 0)          \
        {                                                                     \
            target->var = v;                                                  \
            continue;                                                         \
        }

#define NGX_RTMP_RELAY_NUM_PAR(name, var)                                     \
        if (n.len == sizeof(name) - 1                                         \
            && ngx_strncasecmp(n.data, (u_char *) name, n.len) == 0)          \
        {                                                                     \
            target->var = ngx_atoi(v.data, v.len);                            \
            continue;                                                         \
        }

        NGX_RTMP_RELAY_STR_PAR("app",         app);
        NGX_RTMP_RELAY_STR_PAR("name",        name);
        NGX_RTMP_RELAY_STR_PAR("tcUrl",       tc_url);
        NGX_RTMP_RELAY_STR_PAR("pageUrl",     page_url);
        NGX_RTMP_RELAY_STR_PAR("swfUrl",      swf_url);
        NGX_RTMP_RELAY_STR_PAR("flashVer",    flash_ver);
        NGX_RTMP_RELAY_STR_PAR("playPath",    play_path);
        NGX_RTMP_RELAY_NUM_PAR("live",        live);
        NGX_RTMP_RELAY_NUM_PAR("start",       start);
        NGX_RTMP_RELAY_NUM_PAR("stop",        stop);

#undef NGX_RTMP_RELAY_STR_PAR
#undef NGX_RTMP_RELAY_NUM_PAR

        if (n.len == sizeof("static") - 1 &&
            ngx_strncasecmp(n.data, (u_char *) "static", n.len) == 0 &&
            ngx_atoi(v.data, v.len))
        {
            is_static = 1;
            continue;
        }

        return "unsuppored parameter";
    }

    if (is_static) {

        if (!is_pull) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "static push is not allowed");
            return NGX_CONF_ERROR;
        }

        if (target->name.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "stream name missing in static pull "
                               "declaration");
            return NGX_CONF_ERROR;
        }

        ee = ngx_array_push(&racf->static_events);
        if (ee == NULL) {
            return NGX_CONF_ERROR;
        }

        e = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
        if (e == NULL) {
            return NGX_CONF_ERROR;
        }

        *ee = e;

        rs = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_static_t));
        if (rs == NULL) {
            return NGX_CONF_ERROR;
        }

        rs->target = target;

        e->data = rs;
        e->log = &cf->cycle->new_log;
        e->handler = ngx_rtmp_relay_static_pull_reconnect;

        t = ngx_array_push(&racf->static_pulls);

    } else if (is_pull) {
        t = ngx_array_push(&racf->pulls);

    } else {
        t = ngx_array_push(&racf->pushes);
    }

    if (t == NULL) {
        return NGX_CONF_ERROR;
    }

    *t = target;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_relay_init_process(ngx_cycle_t *cycle)
{
#if !(NGX_WIN32)
    ngx_rtmp_core_main_conf_t  *cmcf = ngx_rtmp_core_main_conf;
    ngx_rtmp_core_srv_conf_t  **pcscf, *cscf;
    ngx_rtmp_core_app_conf_t  **pcacf, *cacf;
    ngx_rtmp_relay_app_conf_t  *racf;
    ngx_uint_t                  n, m, k;
    ngx_rtmp_relay_static_t    *rs;
    ngx_rtmp_listen_t          *lst;
    ngx_event_t               **pevent, *event;

    if (cmcf == NULL || cmcf->listen.nelts == 0) {
        return NGX_OK;
    }

    /* only first worker does static pulling */

    if (ngx_process_slot) {
        return NGX_OK;
    }

    lst = cmcf->listen.elts;

    pcscf = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; ++n, ++pcscf) {

        cscf = *pcscf;
        pcacf = cscf->applications.elts;

        for (m = 0; m < cscf->applications.nelts; ++m, ++pcacf) {

            cacf = *pcacf;
            racf = cacf->app_conf[ngx_rtmp_relay_module.ctx_index];
            pevent = racf->static_events.elts;

            for (k = 0; k < racf->static_events.nelts; ++k, ++pevent) {
                event = *pevent;

                rs = event->data;
                rs->cctx = *lst->ctx;
                rs->cctx.app_conf = cacf->app_conf;

                ngx_post_event(event, &ngx_rtmp_init_queue);
            }
        }
    }
#endif
    return NGX_OK;
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


    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_relay_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_relay_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_relay_delete_stream;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_relay_close_stream;


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
