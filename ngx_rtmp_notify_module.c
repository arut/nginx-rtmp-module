/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"


static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;


static char *ngx_rtmp_notify_on_event(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


typedef struct {
    ngx_url_t                                  *publish_url;
    ngx_url_t                                  *play_url;
} ngx_rtmp_notify_app_conf_t;


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
    ngx_rtmp_notify_app_conf_t      *nacf;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_app_conf_t));
    if (nacf == NULL) {
        return NULL;
    }

    return nacf;
}


static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_app_conf_t *prev = parent;
    ngx_rtmp_notify_app_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->publish_url, prev->publish_url, 0);
    ngx_conf_merge_ptr_value(conf->play_url, prev->play_url, 0);

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
    size_t                          name_len, type_len;

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

    b = ngx_create_temp_buf(pool,
            sizeof("&call=publish") +
            sizeof("&name=") + name_len * 3 +
            sizeof("&type=") + type_len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=publish", 
            sizeof("&call=publish") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->name, name_len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&type=", sizeof("&type=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->type, type_len, 0);

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(nacf->publish_url, pool,
               cl->buf->last - cl->buf->pos
            + (pl->buf->last - pl->buf->pos));

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
    size_t                          name_len;

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

    b = ngx_create_temp_buf(pool,
            sizeof("&call=play") + 
            sizeof("&name=") + name_len * 3
            + 10 * 2 + 1);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=play", 
            sizeof("&call=play") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, v->name, name_len, 0);

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "&start=%uD&duration=%uD&reset=%d",
            (uint32_t)v->start, (uint32_t)v->duration, v->reset & 1);

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(nacf->play_url, pool,
               cl->buf->last - cl->buf->pos
            + (pl->buf->last - pl->buf->pos));

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


static ngx_int_t
ngx_rtmp_notify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL || nacf->publish_url == NULL) {
        return next_publish(s, v);
    }

    ci.url = nacf->publish_url;
    ci.create = ngx_rtmp_notify_publish_create;
    ci.handle = ngx_rtmp_notify_publish_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);
}


static ngx_int_t
ngx_rtmp_notify_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL || nacf->play_url == NULL) {
        return next_play(s, v);
    }

    ci.url = nacf->play_url;
    ci.create = ngx_rtmp_notify_play_create;
    ci.handle = ngx_rtmp_notify_play_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

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

    if (name->len == sizeof("on_play") - 1) {
        nacf->play_url = u;
    } else { /* on_publish */
        nacf->publish_url = u;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_notify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_notify_play;

    return NGX_OK;
}

