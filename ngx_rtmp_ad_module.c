/*
 * Copyright (c) 2013 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_relay_module.h"


/*static ngx_rtmp_disconnect_pt    next_disconnect;*/
static ngx_rtmp_publish_pt       next_publish;
static ngx_rtmp_close_stream_pt  next_close_stream;
static ngx_rtmp_stream_eof_pt    next_stream_eof;


static char *ngx_rtmp_ad_on_ad(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_rtmp_ad_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_ad_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_ad_merge_app_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    ngx_url_t                                  *url;
    ngx_msec_t                                  ad_timeout;
} ngx_rtmp_ad_app_conf_t;


typedef struct {
    unsigned                                    ad:1;
    ngx_rtmp_session_t                         *cosession;
    u_char                                      name[NGX_RTMP_MAX_NAME];
    u_char                                      args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                                 ad_evt;
    time_t                                      start;
} ngx_rtmp_ad_ctx_t;


static ngx_command_t  ngx_rtmp_ad_commands[] = {

    { ngx_string("on_ad"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_ad_on_ad,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ad_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_ad_app_conf_t, ad_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_ad_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_ad_postconfiguration,          /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_ad_create_app_conf,            /* create app configuration */
    ngx_rtmp_ad_merge_app_conf              /* merge app configuration */
};


ngx_module_t  ngx_rtmp_ad_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_ad_module_ctx,                /* module context */
    ngx_rtmp_ad_commands,                   /* module directives */
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
ngx_rtmp_ad_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_ad_app_conf_t  *aacf;

    aacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_ad_app_conf_t));
    if (aacf == NULL) {
        return NULL;
    }

    aacf->url = NGX_CONF_UNSET_PTR;
    aacf->ad_timeout = NGX_CONF_UNSET_MSEC;

    return aacf;
}


static char *
ngx_rtmp_ad_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_ad_app_conf_t *prev = parent;
    ngx_rtmp_ad_app_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);
    ngx_conf_merge_msec_value(conf->ad_timeout, prev->ad_timeout, 600);

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_ad_create(ngx_rtmp_session_t *s, void *arg, ngx_pool_t *pool)
{
    size_t                   name_len, args_len;
    ngx_buf_t               *b;
    ngx_chain_t             *pl, *al;
    ngx_rtmp_ad_ctx_t       *ctx;
    ngx_rtmp_ad_app_conf_t  *aacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    name_len = ctx ? ngx_strlen(ctx->name) : 0;
    args_len = ctx ? ngx_strlen(ctx->args) : 0;

    b = ngx_create_temp_buf(pool, sizeof("&call=ad") +
                                  sizeof("&time=") + NGX_TIME_T_LEN +
                                  sizeof("&name=") + name_len * 3 +
                                  1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=ad", sizeof("&call=ad") - 1);
    b->last = ngx_cpymem(b->last, (u_char *) "&time=", sizeof("&time=") - 1);
    b->last = ngx_sprintf(b->last, "%T", ngx_cached_time->sec - ctx->start);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
        b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                           NGX_ESCAPE_ARGS);
    }

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, ctx->args, args_len);
    }

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_ad_module);

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    al->next = pl;

#if 0
    bl = NULL;
    if (nacf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        cl = al;
        al = bl;
        bl = cl;
    }
#endif

    return ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET,
                                                &aacf->url->host,
                                                &aacf->url->uri, al, NULL, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_int_t 
ngx_rtmp_ad_handle(ngx_rtmp_session_t *s, void *arg, ngx_chain_t *in)
{
    u_char                    url[NGX_RTMP_MAX_NAME];
    ngx_url_t                *u;
    ngx_int_t                 rc;
    ngx_str_t                 local_name;
    ngx_rtmp_ad_ctx_t        *ctx, *adctx;
    ngx_rtmp_session_t       *adsession;
    ngx_rtmp_conf_ctx_t       cctx;
    ngx_rtmp_relay_ctx_t     *rctx;
    ngx_rtmp_ad_app_conf_t   *aacf;
    ngx_rtmp_relay_target_t   target;

    static ngx_str_t          location = ngx_string("location");

    rc = ngx_rtmp_notify_parse_http_retcode(s, in);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);
    
    if (rc != NGX_AGAIN) {
        goto next;
    }

    /* HTTP 3xx */

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "ad: update redirect received");

    rc = ngx_rtmp_notify_parse_http_header(s, in, &location, url,
                                           sizeof(url) - 1);
    if (rc <= 0) {
        goto next;
    }

    if (ngx_strncasecmp(url, (u_char *) "rtmp://", 7)) {
        goto next;
    }

    /* static pull */

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "ad: url='%*s'", rc, url);

    local_name.data = ctx->name;
    local_name.len = ngx_strlen(ctx->name);

    ngx_memzero(&target, sizeof(target));

    u = &target.url;
    u->url.data = url + 7;
    u->url.len = rc - 7;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 1; /* want ip here */

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "ad: bad url failed '%V'", &local_name);
        return NGX_ERROR;
    }

    cctx.app_conf = s->app_conf;
    cctx.srv_conf = s->srv_conf;
    cctx.main_conf = s->main_conf;

    rctx = ngx_rtmp_relay_create_connection(&cctx, &local_name, &target);
    if (rctx == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "ad: failed to create relay");
        goto next;
    }

    adsession = rctx->session;
    adsession->static_relay = 1;

    adctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_ad_ctx_t));
    if (adctx == NULL) {
        goto next;
    }

    adctx->ad = 1;

    ngx_rtmp_set_ctx(adsession, adctx, ngx_rtmp_ad_module);

    ctx->cosession = adsession;
    adctx->cosession = s;

    return NGX_OK;

next:
    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_ad_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "ad: schedule update %Mms", aacf->ad_timeout);

    ngx_add_timer(&ctx->ad_evt, aacf->ad_timeout);

    return NGX_OK;
}


static void 
ngx_rtmp_ad_update(ngx_event_t *e)
{
    ngx_connection_t         *c;
    ngx_rtmp_ad_ctx_t        *ctx;
    ngx_rtmp_session_t       *s;
    ngx_rtmp_ad_app_conf_t   *aacf;
    ngx_rtmp_netcall_init_t   ci;

    c = e->data;
    s = c->data;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);
    if (ctx && (ctx->cosession || ctx->ad)) {
        goto next;
    }

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_ad_module);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "ad: update '%V'", &aacf->url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = aacf->url;
    ci.create = ngx_rtmp_ad_create;
    ci.handle = ngx_rtmp_ad_handle;

    if (ngx_rtmp_netcall_create(s, &ci) == NGX_OK) {
        return;
    }

next:
    /* schedule next ad */

    ngx_rtmp_ad_handle(s, NULL, NULL);
}

/*
static ngx_int_t
ngx_rtmp_ad_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_ad_ctx_t  *ctx, *sctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);
    if (ctx == NULL || ctx->cosession == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "ad: disconnect");

    sctx = ngx_rtmp_get_module_ctx(ctx->cosession, ngx_rtmp_ad_module);

    sctx->cosession = NULL;
    ctx->cosession = NULL;

next:
    return next_disconnect(s);
}

*/
static ngx_int_t
ngx_rtmp_ad_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_event_t              *e;
    ngx_rtmp_ad_ctx_t        *ctx;
    ngx_rtmp_ad_app_conf_t   *aacf;
    ngx_rtmp_close_stream_t   csv;

    if (s->auto_pushed) {
        goto next;
    }

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_ad_module);
    if (aacf == NULL || aacf->url == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "ad: publish");

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);
    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_ad_ctx_t));
        if (ctx == NULL) {
            goto next;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_ad_module);
    }

    if (ctx->cosession) {

        if (ctx->ad) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "ad: suspend session");

            ngx_memzero(&csv, sizeof(csv));
            next_close_stream(ctx->cosession, &csv);
            goto next;
        }

        /* source stream tries to publish something while in ad mode */

        ngx_rtmp_finalize_session(s);

        return NGX_OK;
    }

    ngx_memcpy(ctx->name, v->name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, v->args, NGX_RTMP_MAX_ARGS);

    if (ctx->ad_evt.timer_set) {
        goto next;
    }

    ctx->start = ngx_cached_time->sec;

    e = &ctx->ad_evt;
    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_ad_update;

    ngx_add_timer(e, aacf->ad_timeout);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "ad: schedule initial update %Mms",
                   aacf->ad_timeout);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_ad_close_stream(ngx_rtmp_session_t *s,
                             ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_ad_ctx_t   *ctx, *sctx;
    ngx_rtmp_publish_t   pv;
    ngx_rtmp_session_t  *cosession;

    cosession = NULL;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);

    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "ad: close_stream");

    if (ctx->ad) {
        cosession = ctx->cosession;
    }

    if (ctx->ad_evt.timer_set) {
        ngx_del_timer(&ctx->ad_evt);
    }

next:
    next_close_stream(s, v);

    if (cosession == NULL) {
        return NGX_OK;
    }

    sctx = ngx_rtmp_get_module_ctx(ctx->cosession, ngx_rtmp_ad_module);
    if (sctx == NULL) {
        return NGX_OK;
    }

    ctx->cosession = NULL;
    sctx->cosession = NULL;
    ngx_rtmp_finalize_session(s);

    sctx->start = ngx_cached_time->sec;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "ad: resume session");

    ngx_memzero(&pv, sizeof(pv));
    ngx_memcpy(pv.name, sctx->name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(pv.args, sctx->args, NGX_RTMP_MAX_ARGS);
    pv.silent = 1;

    next_publish(cosession, &pv);

    /* schedule next ad */

    ngx_rtmp_ad_handle(cosession, NULL, NULL);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_ad_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_ad_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_ad_module);
    if (ctx == NULL || !ctx->ad) {
        goto next;
    }

    /* finalize ad session on stream eof */

    ngx_rtmp_finalize_session(s);

next:
    return next_stream_eof(s, v);
}



static char *
ngx_rtmp_ad_on_ad(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_ad_app_conf_t  *aacf = conf;
    ngx_str_t               *value;

    value = cf->args->elts;

    aacf->url = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (aacf->url == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_ad_postconfiguration(ngx_conf_t *cf)
{/*
    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_ad_disconnect;
*/
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_ad_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_ad_close_stream;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_ad_stream_eof;

    return NGX_OK;
}
