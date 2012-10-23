/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_record_module.h"


static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_delete_stream_pt                next_delete_stream;
static ngx_rtmp_record_done_pt                  next_record_done;


static char *ngx_rtmp_notify_on_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);
static ngx_int_t ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname, 
       ngx_url_t *url);


ngx_str_t   ngx_rtmp_notify_urlencoded = 
            ngx_string("application/x-www-form-urlencoded");


#define NGX_RTMP_NOTIFY_PUBLISHING              0x01
#define NGX_RTMP_NOTIFY_PLAYING                 0x02


enum {
    NGX_RTMP_NOTIFY_PLAY,
    NGX_RTMP_NOTIFY_PUBLISH,
    NGX_RTMP_NOTIFY_PLAY_DONE,
    NGX_RTMP_NOTIFY_PUBLISH_DONE,
    NGX_RTMP_NOTIFY_DONE,
    NGX_RTMP_NOTIFY_RECORD_DONE,
    NGX_RTMP_NOTIFY_MAX
};


typedef struct {
    ngx_url_t                                  *url[NGX_RTMP_NOTIFY_MAX];
    ngx_flag_t                                  active;
} ngx_rtmp_notify_app_conf_t;


typedef struct {
    ngx_uint_t                                  flags;
    u_char                                      name[NGX_RTMP_MAX_NAME];
    u_char                                      args[NGX_RTMP_MAX_ARGS];
} ngx_rtmp_notify_ctx_t;


typedef struct {
    u_char                                     *cbname;
    ngx_url_t                                  *url;
} ngx_rtmp_notify_done_t;


static ngx_command_t  ngx_rtmp_notify_commands[] = {

    { ngx_string("on_publish"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_record_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_RTMP_REC_CONF|
                         NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_notify_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_notify_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_notify_create_app_conf,        /* create app configuration */
    ngx_rtmp_notify_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_notify_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_notify_module_ctx,            /* module context */
    ngx_rtmp_notify_commands,               /* module directives */
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
ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_uint_t                      n;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_app_conf_t));
    if (nacf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_MAX; ++n) {
        nacf->url[n] = NGX_CONF_UNSET_PTR;
    }

    return nacf;
}


static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_app_conf_t *prev = parent;
    ngx_rtmp_notify_app_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
        if (conf->url[n]) {
            conf->active = 1;
        }
    }

    if (conf->active) {
        prev->active = 1;
    }

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_notify_publish_create(ngx_rtmp_session_t *s, void *arg, 
        ngx_pool_t *pool)
{
    ngx_rtmp_publish_t             *v = arg;

    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    ngx_url_t                      *url;
    size_t                          name_len, type_len, args_len;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    /* common variables */
    cl = ngx_rtmp_netcall_http_format_session(s, pool);

    if (cl == NULL) {
        return NULL;
    }

    /* publish variables */
    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    name_len = ngx_strlen(v->name);
    type_len = ngx_strlen(v->type);
    args_len = ngx_strlen(v->args);
    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("&call=publish") +
            sizeof("&addr=") + addr_text->len *3 +
            sizeof("&name=") + name_len * 3 +
            sizeof("&type=") + type_len * 3 +
            1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=publish", 
            sizeof("&call=publish") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&addr=", sizeof("&addr=") -1);
    b->last = (u_char*)ngx_escape_uri(b->last, addr_text->data, 
            addr_text->len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->name, name_len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&type=", sizeof("&type=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->type, type_len, 0);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *)ngx_cpymem(b->last, v->args, args_len);
    }

    /* HTTP header */
    url = nacf->url[NGX_RTMP_NOTIFY_PUBLISH];
    hl = ngx_rtmp_netcall_http_format_header(NGX_RTMP_NETCALL_HTTP_POST,
            &url->uri, &url->host,
            pool, cl->buf->last - cl->buf->pos + (pl->buf->last - pl->buf->pos),
            &ngx_rtmp_notify_urlencoded);

    if (hl == NULL) {
        return NULL;
    }

    hl->next = cl;
    cl->next = pl;
    pl->next = NULL;

    return hl;
}


static ngx_chain_t *
ngx_rtmp_notify_play_create(ngx_rtmp_session_t *s, void *arg, 
        ngx_pool_t *pool)
{
    ngx_rtmp_play_t                *v = arg;

    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    ngx_url_t                      *url;
    size_t                          name_len, args_len;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    /* common variables */
    cl = ngx_rtmp_netcall_http_format_session(s, pool);

    if (cl == NULL) {
        return NULL;
    }

    /* play variables */
    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    name_len = ngx_strlen(v->name);
    args_len = ngx_strlen(v->args);
    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("&call=play") + 
            sizeof("&addr=") + addr_text->len * 3 + 
            sizeof("&name=") + name_len * 3 +
            sizeof("&start=&duration=&reset=") + NGX_OFF_T_LEN * 3
            + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=play", 
            sizeof("&call=play") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&addr=", sizeof("&addr=") -1);
    b->last = (u_char*)ngx_escape_uri(b->last, addr_text->data, 
            addr_text->len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->name, name_len, 0);

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "&start=%uD&duration=%uD&reset=%d",
            (uint32_t)v->start, (uint32_t)v->duration, v->reset & 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *)ngx_cpymem(b->last, v->args, args_len);
    }

    /* HTTP header */
    url = nacf->url[NGX_RTMP_NOTIFY_PLAY];
    hl = ngx_rtmp_netcall_http_format_header(NGX_RTMP_NETCALL_HTTP_POST,
            &url->uri, &url->host,
            pool, cl->buf->last - cl->buf->pos + (pl->buf->last - pl->buf->pos),
            &ngx_rtmp_notify_urlencoded);

    if (hl == NULL) {
        return NULL;
    }

    hl->next = cl;
    cl->next = pl;
    pl->next = NULL;

    return hl;
}


static ngx_chain_t *
ngx_rtmp_notify_done_create(ngx_rtmp_session_t *s, void *arg, 
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_done_t         *ds = arg;

    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    size_t                          cbname_len, name_len, args_len;
    ngx_str_t                      *addr_text;
    ngx_rtmp_notify_ctx_t          *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    /* common variables */
    cl = ngx_rtmp_netcall_http_format_session(s, pool);

    if (cl == NULL) {
        return NULL;
    }

    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    cbname_len = ngx_strlen(ds->cbname);
    name_len = ctx ? ngx_strlen(ctx->name) : 0;
    args_len = ctx ? ngx_strlen(ctx->args) : 0;
    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("&call=") + cbname_len +
            sizeof("&addr=") + addr_text->len * 3 + 
            sizeof("&name=") + name_len * 3
            + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=", sizeof("&call=") - 1);
    b->last = ngx_cpymem(b->last, ds->cbname, cbname_len);

    b->last = ngx_cpymem(b->last, (u_char*)"&addr=", sizeof("&addr=") -1);
    b->last = (u_char*)ngx_escape_uri(b->last, addr_text->data, 
            addr_text->len, 0);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
        b->last = (u_char*)ngx_escape_uri(b->last, ctx->name, name_len, 0);
    }

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *)ngx_cpymem(b->last, ctx->args, args_len);
    }

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(NGX_RTMP_NETCALL_HTTP_POST,
            &ds->url->uri, &ds->url->host,
            pool, cl->buf->last - cl->buf->pos + (pl->buf->last - pl->buf->pos),
            &ngx_rtmp_notify_urlencoded);

    if (hl == NULL) {
        return NULL;
    }

    hl->next = cl;
    cl->next = pl;
    pl->next = NULL;

    return hl;
}


static ngx_chain_t *
ngx_rtmp_notify_record_done_create(ngx_rtmp_session_t *s, void *arg,
                                   ngx_pool_t *pool)
{
    ngx_rtmp_record_done_t         *v = arg;

    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    ngx_url_t                      *url;
    size_t                          name_len, args_len;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    /* common variables */
    cl = ngx_rtmp_netcall_http_format_session(s, pool);

    if (cl == NULL) {
        return NULL;
    }

    /* publish variables */
    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    name_len  = ngx_strlen(ctx->name);
    args_len  = ngx_strlen(ctx->args);
    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=record_done") +
                            sizeof("&recorder=") + v->recorder.len + 
                            sizeof("&addr=") + addr_text->len *3 +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&path=") + v->path.len * 3 +
                            + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=record_done", 
                         sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char *)"&recorder=", 
                         sizeof("&recorder=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->recorder.data,
                                      v->recorder.len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&addr=", sizeof("&addr=") -1);
    b->last = (u_char*)ngx_escape_uri(b->last, addr_text->data, 
                                      addr_text->len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, ctx->name, name_len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&path=", sizeof("&path=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->path.data, v->path.len, 0);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *)ngx_cpymem(b->last, ctx->args, args_len);
    }

    /* HTTP header */
    url = nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE];
    hl = ngx_rtmp_netcall_http_format_header(NGX_RTMP_NETCALL_HTTP_POST,
            &url->uri, &url->host,
            pool, cl->buf->last - cl->buf->pos + (pl->buf->last - pl->buf->pos),
            &ngx_rtmp_notify_urlencoded);

    if (hl == NULL) {
        return NULL;
    }

    hl->next = cl;
    cl->next = pl;
    pl->next = NULL;

    return hl;
}


static ngx_int_t 
ngx_rtmp_notify_parse_http_retcode(ngx_rtmp_session_t *s, 
        ngx_chain_t *in) 
{
    ngx_buf_t      *b;
    ngx_int_t       n;
    u_char          c;

    /* find 10th character */

    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "notify: HTTP retcode: %dxx", (int)(c - '0'));
                return c == (u_char)'2' ? NGX_OK : NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "notify: invalid HTTP retcode: %d..", (int)c);

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "notify: invalid HTTP response");

    return NGX_ERROR;
}


static ngx_int_t 
ngx_rtmp_notify_publish_handle(ngx_rtmp_session_t *s, 
        void *arg, ngx_chain_t *in)
{
    if (ngx_rtmp_notify_parse_http_retcode(s, in) != NGX_OK) {
        return NGX_ERROR;
    }

    return next_publish(s, (ngx_rtmp_publish_t *)arg);
}


static ngx_int_t 
ngx_rtmp_notify_play_handle(ngx_rtmp_session_t *s, 
        void *arg, ngx_chain_t *in)
{
    if (ngx_rtmp_notify_parse_http_retcode(s, in) != NGX_OK) {
        return NGX_ERROR;
    }

    return next_play(s, (ngx_rtmp_play_t *)arg);
}


static void
ngx_rtmp_notify_init(ngx_rtmp_session_t *s, 
        u_char name[NGX_RTMP_MAX_NAME], u_char args[NGX_RTMP_MAX_ARGS],
        ngx_uint_t flags)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_app_conf_t     *nacf;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    if (!nacf->active) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_notify_ctx_t));
        if (ctx == NULL) {
            return;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_notify_module);
    }

    ngx_memcpy(ctx->name, name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, args, NGX_RTMP_MAX_ARGS);

    ctx->flags |= flags;
}


static ngx_int_t
ngx_rtmp_notify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    if (nacf == NULL) {
        goto next;
    }

    ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PUBLISHING);

    if (nacf->url[NGX_RTMP_NOTIFY_PUBLISH] == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: publish '%V'", 
                  &nacf->url[NGX_RTMP_NOTIFY_PUBLISH]->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = nacf->url[NGX_RTMP_NOTIFY_PUBLISH];
    ci.create = ngx_rtmp_notify_publish_create;
    ci.handle = ngx_rtmp_notify_publish_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_notify_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    if (nacf == NULL) {
        goto next;
    }

    ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PLAYING);
    
    if (nacf->url[NGX_RTMP_NOTIFY_PLAY] == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: play '%V'",
                  &nacf->url[NGX_RTMP_NOTIFY_PLAY]->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = nacf->url[NGX_RTMP_NOTIFY_PLAY];
    ci.create = ngx_rtmp_notify_play_create;
    ci.handle = ngx_rtmp_notify_play_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_notify_delete_stream(ngx_rtmp_session_t *s,
                              ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_app_conf_t     *nacf;

    if (s->auto_pushed) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    if (ctx == NULL) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    if (nacf == NULL) {
        goto next;
    }

    if (nacf->url[NGX_RTMP_NOTIFY_PUBLISH_DONE] && 
        (ctx->flags & NGX_RTMP_NOTIFY_PUBLISHING)) 
    {
        ngx_rtmp_notify_done(s, "publish_done",
                             nacf->url[NGX_RTMP_NOTIFY_PUBLISH_DONE]);
    }

    if (nacf->url[NGX_RTMP_NOTIFY_PLAY_DONE] && 
        (ctx->flags & NGX_RTMP_NOTIFY_PLAYING))
    {
        ngx_rtmp_notify_done(s, "play_done",
                             nacf->url[NGX_RTMP_NOTIFY_PLAY_DONE]);
    }

    if (nacf->url[NGX_RTMP_NOTIFY_DONE] && ctx->flags) {
        ngx_rtmp_notify_done(s, "done", nacf->url[NGX_RTMP_NOTIFY_DONE]);
    }

    ctx->flags = 0;

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_notify_record_done(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    ngx_rtmp_netcall_init_t         ci;
    ngx_rtmp_notify_app_conf_t     *nacf;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL || nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE] == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: record_done recorder=%V path='%V' url='%V'",
                  &v->recorder, &v->path,
                  &nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE]->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url    = nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE];
    ci.create = ngx_rtmp_notify_record_done_create;
    ci.arg    = v;

    ngx_rtmp_netcall_create(s, &ci);

next:
    return next_record_done(s, v);
}


static ngx_int_t
ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname, ngx_url_t *url)
{
    ngx_rtmp_netcall_init_t         ci;
    ngx_rtmp_notify_done_t          ds;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: %s '%V'", cbname, &url->url);

    ds.cbname = (u_char *) cbname;
    ds.url = url;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.arg = &ds;
    ci.create = ngx_rtmp_notify_done_create;

    return ngx_rtmp_netcall_create(s, &ci);
}


static char *
ngx_rtmp_notify_on_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_str_t                      *url, *name;
    ngx_url_t                      *u;
    size_t                          add;
    ngx_str_t                      *value;
    ngx_uint_t                      n;

    value = cf->args->elts;
    name = &value[0];
    url = &value[1];

    add = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;
    u->uri_part = 1;
    
    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }

    nacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_notify_module);

    n = 0;

    switch (name->len) {
        case sizeof("on_done") - 1: /* and on_play */
            if (name->data[3] == 'd') {
                n = NGX_RTMP_NOTIFY_DONE;
            } else {
                n = NGX_RTMP_NOTIFY_PLAY;
            }
            break;

        case sizeof("on_publish") - 1:
            n = NGX_RTMP_NOTIFY_PUBLISH;
            break;

        case sizeof("on_play_done") - 1:
            n = NGX_RTMP_NOTIFY_PLAY_DONE;
            break;

        case sizeof("on_record_done") - 1:
            n = NGX_RTMP_NOTIFY_RECORD_DONE;
            break;

        case sizeof("on_publish_done") - 1:
            n = NGX_RTMP_NOTIFY_PUBLISH_DONE;
            break;
    }

    nacf->url[n] = u;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_notify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_notify_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_notify_delete_stream;

    next_record_done = ngx_rtmp_record_done;
    ngx_rtmp_record_done = ngx_rtmp_notify_record_done;

    return NGX_OK;
}
