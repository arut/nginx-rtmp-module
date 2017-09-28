
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_record_module.h"
#include "ngx_rtmp_relay_module.h"


static ngx_rtmp_connect_pt                      next_connect;
static ngx_rtmp_disconnect_pt                   next_disconnect;
static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_close_stream_pt                 next_close_stream;
static ngx_rtmp_record_done_pt                  next_record_done;


static char *ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static void *ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent,
       void *child);
static ngx_int_t ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname,
       ngx_uint_t url_idx);


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
    NGX_RTMP_NOTIFY_UPDATE,
    NGX_RTMP_NOTIFY_APP_MAX
};


enum {
    NGX_RTMP_NOTIFY_CONNECT,
    NGX_RTMP_NOTIFY_DISCONNECT,
    NGX_RTMP_NOTIFY_SRV_MAX
};


typedef struct {
    ngx_url_t                                  *url[NGX_RTMP_NOTIFY_APP_MAX];
    ngx_flag_t                                  active;
    ngx_uint_t                                  method;
    ngx_msec_t                                  update_timeout;
    ngx_flag_t                                  update_strict;
    ngx_flag_t                                  relay_redirect;
} ngx_rtmp_notify_app_conf_t;


typedef struct {
    ngx_url_t                                  *url[NGX_RTMP_NOTIFY_SRV_MAX];
    ngx_uint_t                                  method;
} ngx_rtmp_notify_srv_conf_t;


typedef struct {
    ngx_uint_t                                  flags;
    u_char                                      name[NGX_RTMP_MAX_NAME];
    u_char                                      args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                                 update_evt;
    time_t                                      start;
} ngx_rtmp_notify_ctx_t;


typedef struct {
    u_char                                     *cbname;
    ngx_uint_t                                  url_idx;
} ngx_rtmp_notify_done_t;


static ngx_command_t  ngx_rtmp_notify_commands[] = {

    { ngx_string("on_connect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_disconnect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_record_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_RTMP_REC_CONF|
                         NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_update"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_method"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_method,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_update_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, update_timeout),
      NULL },

    { ngx_string("notify_update_strict"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, update_strict),
      NULL },

    { ngx_string("notify_relay_redirect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, relay_redirect),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_notify_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_notify_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_notify_create_srv_conf,        /* create server configuration */
    ngx_rtmp_notify_merge_srv_conf,         /* merge server configuration */
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

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        nacf->url[n] = NGX_CONF_UNSET_PTR;
    }

    nacf->method = NGX_CONF_UNSET_UINT;
    nacf->update_timeout = NGX_CONF_UNSET_MSEC;
    nacf->update_strict = NGX_CONF_UNSET;
    nacf->relay_redirect = NGX_CONF_UNSET;

    return nacf;
}


static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_app_conf_t *prev = parent;
    ngx_rtmp_notify_app_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
        if (conf->url[n]) {
            conf->active = 1;
        }
    }

    if (conf->active) {
        prev->active = 1;
    }

    ngx_conf_merge_uint_value(conf->method, prev->method,
                              NGX_RTMP_NETCALL_HTTP_POST);
    ngx_conf_merge_msec_value(conf->update_timeout, prev->update_timeout,
                              30000);
    ngx_conf_merge_value(conf->update_strict, prev->update_strict, 0);
    ngx_conf_merge_value(conf->relay_redirect, prev->relay_redirect, 0);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_uint_t                      n;

    nscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_srv_conf_t));
    if (nscf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        nscf->url[n] = NGX_CONF_UNSET_PTR;
    }

    nscf->method = NGX_CONF_UNSET_UINT;

    return nscf;
}


static char *
ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_srv_conf_t *prev = parent;
    ngx_rtmp_notify_srv_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
    }

    ngx_conf_merge_uint_value(conf->method, prev->method,
                              NGX_RTMP_NETCALL_HTTP_POST);

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_notify_create_request(ngx_rtmp_session_t *s, ngx_pool_t *pool,
                                   ngx_uint_t url_idx, ngx_chain_t *args)
{
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_chain_t                *al, *bl, *cl;
    ngx_url_t                  *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nacf->url[url_idx];

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    al->next = args;

    bl = NULL;

    if (nacf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        cl = al;
        al = bl;
        bl = cl;
    }

    return ngx_rtmp_netcall_http_format_request(nacf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_connect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_connect_t             *v = arg;

    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    size_t                          app_len, args_len, flashver_len,
                                    swf_url_len, tc_url_len, page_url_len;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    /* these values are still missing in session
     * so we have to construct the request from
     * connection struct */

    app_len = ngx_strlen(v->app);
    args_len = ngx_strlen(v->args);
    flashver_len = ngx_strlen(v->flashver);
    swf_url_len = ngx_strlen(v->swf_url);
    tc_url_len = ngx_strlen(v->tc_url);
    page_url_len = ngx_strlen(v->page_url);

    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("call=connect") - 1 +
            sizeof("&app=") - 1 + app_len * 3 +
            sizeof("&flashver=") - 1 + flashver_len * 3 +
            sizeof("&swfurl=") - 1 + swf_url_len * 3 +
            sizeof("&tcurl=") - 1 + tc_url_len * 3 +
            sizeof("&pageurl=") - 1 + page_url_len * 3 +
            sizeof("&addr=") - 1 + addr_text->len * 3 +
            sizeof("&epoch=") - 1 + NGX_INT32_LEN +
            1 + args_len
        );

    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "app=", sizeof("app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->app, app_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&flashver=",
                         sizeof("&flashver=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->flashver, flashver_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&swfurl=",
                         sizeof("&swfurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->swf_url, swf_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&tcurl=",
                         sizeof("&tcurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->tc_url, tc_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&pageurl=",
                         sizeof("&pageurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->page_url, page_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&addr=", sizeof("&addr=") -1);
    b->last = (u_char*) ngx_escape_uri(b->last, addr_text->data,
                                       addr_text->len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&epoch=", sizeof("&epoch=") -1);
    b->last = ngx_sprintf(b->last, "%uD", (uint32_t) s->epoch);

    b->last = ngx_cpymem(b->last, (u_char*) "&call=connect",
                         sizeof("&call=connect") - 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, v->args, args_len);
    }

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nscf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_disconnect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl, *pl;
    ngx_buf_t                      *b;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=disconnect") +
                            sizeof("&app=") + s->app.len * 3 +
                            1 + s->args.len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=disconnect",
                         sizeof("&call=disconnect") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&app=", sizeof("&app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->app.data, s->app.len,
                                       NGX_ESCAPE_ARGS);

    if (s->args.len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, s->args.data, s->args.len);
    }

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    al->next = pl;

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nscf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_publish_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_publish_t             *v = arg;

    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len, type_len, args_len;

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    name_len = ngx_strlen(v->name);
    type_len = ngx_strlen(v->type);
    args_len = ngx_strlen(v->args);

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=publish") +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&type=") + type_len * 3 +
                            1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=publish",
                         sizeof("&call=publish") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->name, name_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&type=", sizeof("&type=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->type, type_len,
                                       NGX_ESCAPE_ARGS);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, v->args, args_len);
    }

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_PUBLISH, pl);
}


static ngx_chain_t *
ngx_rtmp_notify_play_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_play_t                *v = arg;

    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len, args_len;

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    name_len = ngx_strlen(v->name);
    args_len = ngx_strlen(v->args);

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=play") +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&start=&duration=&reset=") +
                            NGX_INT32_LEN * 3 + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=play",
                         sizeof("&call=play") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->name, name_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_snprintf(b->last, b->end - b->last,
                           "&start=%uD&duration=%uD&reset=%d",
                           (uint32_t) v->start, (uint32_t) v->duration,
                           v->reset & 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, v->args, args_len);
    }

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_PLAY, pl);
}


static ngx_chain_t *
ngx_rtmp_notify_done_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_done_t         *ds = arg;

    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          cbname_len, name_len, args_len;
    ngx_rtmp_notify_ctx_t          *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    cbname_len = ngx_strlen(ds->cbname);
    name_len = ctx ? ngx_strlen(ctx->name) : 0;
    args_len = ctx ? ngx_strlen(ctx->args) : 0;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=") + cbname_len +
                            sizeof("&name=") + name_len * 3 +
                            1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=", sizeof("&call=") - 1);
    b->last = ngx_cpymem(b->last, ds->cbname, cbname_len);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
        b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                           NGX_ESCAPE_ARGS);
    }

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, ctx->args, args_len);
    }

    return ngx_rtmp_notify_create_request(s, pool, ds->url_idx, pl);
}


static ngx_chain_t *
ngx_rtmp_notify_update_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len, args_len;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_str_t                       sfx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    if (ctx->flags & NGX_RTMP_NOTIFY_PUBLISHING) {
        ngx_str_set(&sfx, "_publish");
    } else if (ctx->flags & NGX_RTMP_NOTIFY_PLAYING) {
        ngx_str_set(&sfx, "_play");
    } else {
        ngx_str_null(&sfx);
    }

    name_len = ctx ? ngx_strlen(ctx->name) : 0;
    args_len = ctx ? ngx_strlen(ctx->args) : 0;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=update") + sfx.len +
                            sizeof("&time=") + NGX_TIME_T_LEN +
                            sizeof("&timestamp=") + NGX_INT32_LEN +
                            sizeof("&name=") + name_len * 3 +
                            1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=update",
                         sizeof("&call=update") - 1);
    b->last = ngx_cpymem(b->last, sfx.data, sfx.len);

    b->last = ngx_cpymem(b->last, (u_char *) "&time=",
                         sizeof("&time=") - 1);
    b->last = ngx_sprintf(b->last, "%T", ngx_cached_time->sec - ctx->start);

    b->last = ngx_cpymem(b->last, (u_char *) "&timestamp=",
                         sizeof("&timestamp=") - 1);
    b->last = ngx_sprintf(b->last, "%D", s->current_time);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
        b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                           NGX_ESCAPE_ARGS);
    }

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, ctx->args, args_len);
    }

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_UPDATE, pl);
}


static ngx_chain_t *
ngx_rtmp_notify_record_done_create(ngx_rtmp_session_t *s, void *arg,
                                   ngx_pool_t *pool)
{
    ngx_rtmp_record_done_t         *v = arg;

    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len, args_len;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    name_len  = ngx_strlen(ctx->name);
    args_len  = ngx_strlen(ctx->args);

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=record_done") +
                            sizeof("&recorder=") + v->recorder.len +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&path=") + v->path.len * 3 +
                            1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=record_done",
                         sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char *) "&recorder=",
                         sizeof("&recorder=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->recorder.data,
                                       v->recorder.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&path=", sizeof("&path=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->path.data, v->path.len,
                                       NGX_ESCAPE_ARGS);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, ctx->args, args_len);
    }

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_RECORD_DONE,
                                          pl);
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
                switch (c) {
                    case (u_char) '2':
                        return NGX_OK;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    default:
                        return NGX_ERROR;
                }
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "notify: invalid HTTP retcode: %d..", (int)c);

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "notify: empty or broken HTTP response");

    /*
     * not enough data;
     * it can happen in case of empty or broken reply
     */

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_notify_parse_http_header(ngx_rtmp_session_t *s,
        ngx_chain_t *in, ngx_str_t *name, u_char *data, size_t len)
{
    ngx_buf_t      *b;
    ngx_int_t       matched;
    u_char         *p, c;
    ngx_uint_t      n;

    enum {
        parse_name,
        parse_space,
        parse_value,
        parse_value_newline
    } state = parse_name;

    n = 0;
    matched = 0;

    while (in) {
        b = in->buf;

        for (p = b->pos; p != b->last; ++p) {
            c = *p;

            if (c == '\r') {
                continue;
            }

            switch (state) {
                case parse_value_newline:
                    if (c == ' ' || c == '\t') {
                        state = parse_space;
                        break;
                    }

                    if (matched) {
                        return n;
                    }

                    if (c == '\n') {
                        return NGX_OK;
                    }

                    n = 0;
                    state = parse_name;
                    /* fall through */

                case parse_name:
                    switch (c) {
                        case ':':
                            matched = (n == name->len);
                            n = 0;
                            state = parse_space;
                            break;
                        case '\n':
                            n = 0;
                            break;
                        default:
                            if (n < name->len &&
                                ngx_tolower(c) == ngx_tolower(name->data[n]))
                            {
                                ++n;
                                break;
                            }
                            n = name->len + 1;
                    }
                    break;

                case parse_space:
                    if (c == ' ' || c == '\t') {
                        break;
                    }
                    state = parse_value;
                    /* fall through */

                case parse_value:
                    if (c == '\n') {
                        state = parse_value_newline;
                        break;
                    }

                    if (matched && n + 1 < len) {
                        data[n++] = c;
                    }

                    break;
            }
        }

        in = in->next;
    }

    return NGX_OK;
}


static void
ngx_rtmp_notify_clear_flag(ngx_rtmp_session_t *s, ngx_uint_t flag)
{
    ngx_rtmp_notify_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    ctx->flags &= ~flag;
}


static ngx_int_t
ngx_rtmp_notify_connect_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_connect_t *v = arg;
    ngx_int_t           rc;
    u_char              app[NGX_RTMP_MAX_NAME];

    static ngx_str_t    location = ngx_string("location");

    rc = ngx_rtmp_notify_parse_http_retcode(s, in);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "notify: connect redirect received");

        rc = ngx_rtmp_notify_parse_http_header(s, in, &location, app,
                                               sizeof(app) - 1);
        if (rc > 0) {
            *ngx_cpymem(v->app, app, rc) = 0;
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "notify: connect redirect to '%s'", v->app);
        }
    }

    return next_connect(s, v);
}


static void
ngx_rtmp_notify_set_name(u_char *dst, size_t dst_len, u_char *src,
    size_t src_len)
{
    u_char     result[16], *p;
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, src, src_len);
    ngx_md5_final(result, &md5);

    p = ngx_hex_dump(dst, result, ngx_min((dst_len - 1) / 2, 16));
    *p = '\0';
}


static ngx_int_t
ngx_rtmp_notify_publish_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_publish_t         *v = arg;
    ngx_int_t                   rc;
    ngx_str_t                   local_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *u;
    ngx_rtmp_notify_app_conf_t *nacf;
    u_char                      name[NGX_RTMP_MAX_NAME];

    static ngx_str_t    location = ngx_string("location");

    rc = ngx_rtmp_notify_parse_http_retcode(s, in);
    if (rc == NGX_ERROR) {
        ngx_rtmp_notify_clear_flag(s, NGX_RTMP_NOTIFY_PUBLISHING);
        return NGX_ERROR;
    }

    if (rc != NGX_AGAIN) {
        goto next;
    }

    /* HTTP 3xx */

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: publish redirect received");

    rc = ngx_rtmp_notify_parse_http_header(s, in, &location, name,
                                           sizeof(name) - 1);
    if (rc <= 0) {
        goto next;
    }

    if (ngx_strncasecmp(name, (u_char *) "rtmp://", 7)) {
        *ngx_cpymem(v->name, name, rc) = 0;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: publish redirect to '%s'", v->name);
        goto next;
    }

    /* push */

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf->relay_redirect) {
        ngx_rtmp_notify_set_name(v->name, NGX_RTMP_MAX_NAME, name, (size_t) rc);
    }

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "notify: push '%s' to '%*s'", v->name, rc, name);

    local_name.data = v->name;
    local_name.len = ngx_strlen(v->name);

    ngx_memzero(&target, sizeof(target));

    u = &target.url;
    u->url = local_name;
    u->url.data = name + 7;
    u->url.len = rc - 7;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 1; /* want ip here */

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: push failed '%V'", &local_name);
        return NGX_ERROR;
    }

    ngx_rtmp_relay_push(s, &local_name, &target);

next:

    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_notify_play_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_play_t            *v = arg;
    ngx_int_t                   rc;
    ngx_str_t                   local_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *u;
    ngx_rtmp_notify_app_conf_t *nacf;
    u_char                      name[NGX_RTMP_MAX_NAME];

    static ngx_str_t            location = ngx_string("location");

    rc = ngx_rtmp_notify_parse_http_retcode(s, in);
    if (rc == NGX_ERROR) {
        ngx_rtmp_notify_clear_flag(s, NGX_RTMP_NOTIFY_PLAYING);
        return NGX_ERROR;
    }

    if (rc != NGX_AGAIN) {
        goto next;
    }

    /* HTTP 3xx */

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: play redirect received");

    rc = ngx_rtmp_notify_parse_http_header(s, in, &location, name,
                                           sizeof(name) - 1);
    if (rc <= 0) {
        goto next;
    }

    if (ngx_strncasecmp(name, (u_char *) "rtmp://", 7)) {
        *ngx_cpymem(v->name, name, rc) = 0;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: play redirect to '%s'", v->name);
        goto next;
    }

    /* pull */

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf->relay_redirect) {
        ngx_rtmp_notify_set_name(v->name, NGX_RTMP_MAX_NAME, name, (size_t) rc);
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: pull '%s' from '%*s'", v->name, rc, name);

    local_name.data = v->name;
    local_name.len = ngx_strlen(v->name);

    ngx_memzero(&target, sizeof(target));

    u = &target.url;
    u->url = local_name;
    u->url.data = name + 7;
    u->url.len = rc - 7;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 1; /* want ip here */

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: pull failed '%V'", &local_name);
        return NGX_ERROR;
    }

    ngx_rtmp_relay_pull(s, &local_name, &target);

next:

    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_notify_update_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_rtmp_notify_ctx_t      *ctx;
    ngx_int_t                   rc;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    rc = ngx_rtmp_notify_parse_http_retcode(s, in);

    if ((!nacf->update_strict && rc == NGX_ERROR) ||
         (nacf->update_strict && rc != NGX_OK))
    {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: update failed");

        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: schedule update %Mms",
                   nacf->update_timeout);

    ngx_add_timer(&ctx->update_evt, nacf->update_timeout);

    return NGX_OK;
}


static void
ngx_rtmp_notify_update(ngx_event_t *e)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_rtmp_netcall_init_t     ci;
    ngx_url_t                  *url;

    c = e->data;
    s = c->data;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nacf->url[NGX_RTMP_NOTIFY_UPDATE];

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: update '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_notify_update_create;
    ci.handle = ngx_rtmp_notify_update_handle;

    if (ngx_rtmp_netcall_create(s, &ci) == NGX_OK) {
        return;
    }

    /* schedule next update on connection error */

    ngx_rtmp_notify_update_handle(s, NULL, NULL);
}


static void
ngx_rtmp_notify_init(ngx_rtmp_session_t *s,
        u_char name[NGX_RTMP_MAX_NAME], u_char args[NGX_RTMP_MAX_ARGS],
        ngx_uint_t flags)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_event_t                    *e;

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

    if (nacf->url[NGX_RTMP_NOTIFY_UPDATE] == NULL ||
        nacf->update_timeout == 0)
    {
        return;
    }

    if (ctx->update_evt.timer_set) {
        return;
    }

    ctx->start = ngx_cached_time->sec;

    e = &ctx->update_evt;

    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_notify_update;

    ngx_add_timer(e, nacf->update_timeout);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: schedule initial update %Mms",
                   nacf->update_timeout);
}


static ngx_int_t
ngx_rtmp_notify_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: connect '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_notify_connect_create;
    ci.handle = ngx_rtmp_notify_connect_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_connect(s, v);
}


static ngx_int_t
ngx_rtmp_notify_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: disconnect '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_notify_disconnect_create;

    ngx_rtmp_netcall_create(s, &ci);

next:
    return next_disconnect(s);
}


static ngx_int_t
ngx_rtmp_notify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    url = nacf->url[NGX_RTMP_NOTIFY_PUBLISH];

    ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PUBLISHING);

    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: publish '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
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
    ngx_url_t                      *url;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    url = nacf->url[NGX_RTMP_NOTIFY_PLAY];

    ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PLAYING);

    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: play '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_notify_play_create;
    ci.handle = ngx_rtmp_notify_play_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_notify_close_stream(ngx_rtmp_session_t *s,
                             ngx_rtmp_close_stream_t *v)
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

    if (ctx->flags & NGX_RTMP_NOTIFY_PUBLISHING) {
        ngx_rtmp_notify_done(s, "publish_done", NGX_RTMP_NOTIFY_PUBLISH_DONE);
    }

    if (ctx->flags & NGX_RTMP_NOTIFY_PLAYING) {
        ngx_rtmp_notify_done(s, "play_done", NGX_RTMP_NOTIFY_PLAY_DONE);
    }

    if (ctx->flags) {
        ngx_rtmp_notify_done(s, "done", NGX_RTMP_NOTIFY_DONE);
    }

    if (ctx->update_evt.timer_set) {
        ngx_del_timer(&ctx->update_evt);
    }

    ctx->flags = 0;

next:
    return next_close_stream(s, v);
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
ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname, ngx_uint_t url_idx)
{
    ngx_rtmp_netcall_init_t         ci;
    ngx_rtmp_notify_done_t          ds;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_url_t                      *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nacf->url[url_idx];
    if (url == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: %s '%V'", cbname, &url->url);

    ds.cbname = (u_char *) cbname;
    ds.url_idx = url_idx;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.arg = &ds;
    ci.create = ngx_rtmp_notify_done_create;

    return ngx_rtmp_netcall_create(s, &ci);
}


static ngx_url_t *
ngx_rtmp_notify_parse_url(ngx_conf_t *cf, ngx_str_t *url)
{
    ngx_url_t  *u;
    size_t      add;

    add = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
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
        return NULL;
    }

    return u;
}


static char *
ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_connect") - 1:
            n = NGX_RTMP_NOTIFY_CONNECT;
            break;

        case sizeof("on_disconnect") - 1:
            n = NGX_RTMP_NOTIFY_DISCONNECT;
            break;
    }

    nscf->url[n] = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_done") - 1: /* and on_play */
            if (name->data[3] == 'd') {
                n = NGX_RTMP_NOTIFY_DONE;
            } else {
                n = NGX_RTMP_NOTIFY_PLAY;
            }
            break;

        case sizeof("on_update") - 1:
            n = NGX_RTMP_NOTIFY_UPDATE;
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


static char *
ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    if (value->len == sizeof("get") - 1 &&
        ngx_strncasecmp(value->data, (u_char *) "get", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_GET;

    } else if (value->len == sizeof("post") - 1 &&
               ngx_strncasecmp(value->data, (u_char *) "post", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_POST;

    } else {
        return "got unexpected method";
    }

    nscf = ngx_rtmp_conf_get_module_srv_conf(cf, ngx_rtmp_notify_module);
    nscf->method = nacf->method;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf)
{
    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_notify_connect;

    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_notify_disconnect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_notify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_notify_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_notify_close_stream;

    next_record_done = ngx_rtmp_record_done;
    ngx_rtmp_record_done = ngx_rtmp_notify_record_done;

    return NGX_OK;
}
