
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_record_module.h"


static char *ngx_rtmp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_rtmp_control_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_control_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


typedef const char * (*ngx_rtmp_control_handler_t)(ngx_http_request_t *r,
    ngx_rtmp_session_t *);


#define NGX_RTMP_CONTROL_ALL        0xff
#define NGX_RTMP_CONTROL_RECORD     0x01
#define NGX_RTMP_CONTROL_DROP       0x02
#define NGX_RTMP_CONTROL_REDIRECT   0x04


enum {
    NGX_RTMP_CONTROL_FILTER_CLIENT = 0,
    NGX_RTMP_CONTROL_FILTER_PUBLISHER,
    NGX_RTMP_CONTROL_FILTER_SUBSCRIBER
};


typedef struct {
    ngx_uint_t                      count;
    ngx_str_t                       path;
    ngx_uint_t                      filter;
    ngx_str_t                       method;
    ngx_array_t                     sessions; /* ngx_rtmp_session_t * */
} ngx_rtmp_control_ctx_t;


typedef struct {
    ngx_uint_t                      control;
} ngx_rtmp_control_loc_conf_t;


static ngx_conf_bitmask_t           ngx_rtmp_control_masks[] = {
    { ngx_string("all"),            NGX_RTMP_CONTROL_ALL       },
    { ngx_string("record"),         NGX_RTMP_CONTROL_RECORD    },
    { ngx_string("drop"),           NGX_RTMP_CONTROL_DROP      },
    { ngx_string("redirect"),       NGX_RTMP_CONTROL_REDIRECT  },
    { ngx_null_string,              0                          }
};


static ngx_command_t  ngx_rtmp_control_commands[] = {

    { ngx_string("rtmp_control"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_rtmp_control,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_control_loc_conf_t, control),
      ngx_rtmp_control_masks },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_control_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_control_create_loc_conf,   /* create location configuration */
    ngx_rtmp_control_merge_loc_conf,    /* merge location configuration */
};


ngx_module_t  ngx_rtmp_control_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_control_module_ctx,       /* module context */
    ngx_rtmp_control_commands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static const char *
ngx_rtmp_control_record_handler(ngx_http_request_t *r, ngx_rtmp_session_t *s)
{
    ngx_int_t                    rc;
    ngx_str_t                    rec;
    ngx_uint_t                   rn;
    ngx_rtmp_control_ctx_t      *ctx;
    ngx_rtmp_core_app_conf_t    *cacf;
    ngx_rtmp_record_app_conf_t  *racf;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    racf = cacf->app_conf[ngx_rtmp_record_module.ctx_index];

    if (ngx_http_arg(r, (u_char *) "rec", sizeof("rec") - 1, &rec) != NGX_OK) {
        rec.len = 0;
    }

    rn = ngx_rtmp_record_find(racf, &rec);
    if (rn == NGX_CONF_UNSET_UINT) {
        return "Recorder not found";
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    if (ctx->method.len == sizeof("start") - 1 &&
        ngx_strncmp(ctx->method.data, "start", ctx->method.len) == 0)
    {
        rc = ngx_rtmp_record_open(s, rn, &ctx->path);

    } else if (ctx->method.len == sizeof("stop") - 1 &&
               ngx_strncmp(ctx->method.data, "stop", ctx->method.len) == 0)
    {
        rc = ngx_rtmp_record_close(s, rn, &ctx->path);

    } else {
        return "Undefined method";
    }

    if (rc == NGX_ERROR) {
        return "Recorder error";
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_drop_handler(ngx_http_request_t *r, ngx_rtmp_session_t *s)
{
    ngx_rtmp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    ngx_rtmp_finalize_session(s);

    ++ctx->count;

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_redirect_handler(ngx_http_request_t *r, ngx_rtmp_session_t *s)
{
    ngx_str_t                 name;
    ngx_rtmp_play_t           vplay;
    ngx_rtmp_publish_t        vpublish;
    ngx_rtmp_live_ctx_t      *lctx;
    ngx_rtmp_control_ctx_t   *ctx;
    ngx_rtmp_close_stream_t   vc;

    if (ngx_http_arg(r, (u_char *) "newname", sizeof("newname") - 1, &name)
        != NGX_OK)
    {
        return "newname not specified";
    }

    if (name.len >= NGX_RTMP_MAX_NAME) {
        name.len = NGX_RTMP_MAX_NAME - 1;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);
    ctx->count++;

    ngx_memzero(&vc, sizeof(ngx_rtmp_close_stream_t));

    /* close_stream should be synchronous */
    ngx_rtmp_close_stream(s, &vc);

    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (lctx && lctx->publishing) {
        /* publish */

        ngx_memzero(&vpublish, sizeof(ngx_rtmp_publish_t));

        ngx_memcpy(vpublish.name, name.data, name.len);

        ngx_rtmp_cmd_fill_args(vpublish.name, vpublish.args);

        if (ngx_rtmp_publish(s, &vpublish) != NGX_OK) {
            return "publish failed";
        }

    } else {
        /* play */

        ngx_memzero(&vplay, sizeof(ngx_rtmp_play_t));

        ngx_memcpy(vplay.name, name.data, name.len);

        ngx_rtmp_cmd_fill_args(vplay.name, vplay.args);

        if (ngx_rtmp_play(s, &vplay) != NGX_OK) {
            return "play failed";
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_walk_session(ngx_http_request_t *r,
    ngx_rtmp_live_ctx_t *lctx)
{
    ngx_str_t                addr, *paddr, clientid;
    ngx_rtmp_session_t      *s, **ss;
    ngx_rtmp_control_ctx_t  *ctx;

    s = lctx->session;

    if (s == NULL || s->connection == NULL) {
        return NGX_CONF_OK;
    }

    if (ngx_http_arg(r, (u_char *) "addr", sizeof("addr") - 1, &addr)
        == NGX_OK)
    {
        paddr = &s->connection->addr_text;
        if (paddr->len != addr.len ||
            ngx_strncmp(paddr->data, addr.data, addr.len))
        {
            return NGX_CONF_OK;
        }
    }

    if (ngx_http_arg(r, (u_char *) "clientid", sizeof("clientid") - 1,
                     &clientid)
        == NGX_OK)
    {
        if (s->connection->number !=
            (ngx_uint_t) ngx_atoi(clientid.data, clientid.len))
        {
            return NGX_CONF_OK;
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    switch (ctx->filter) {
        case NGX_RTMP_CONTROL_FILTER_PUBLISHER:
            if (!lctx->publishing) {
                return NGX_CONF_OK;
            }
            break;

        case NGX_RTMP_CONTROL_FILTER_SUBSCRIBER:
            if (lctx->publishing) {
                return NGX_CONF_OK;
            }
            break;

        case NGX_RTMP_CONTROL_FILTER_CLIENT:
            break;
    }

    ss = ngx_array_push(&ctx->sessions);
    if (ss == NULL) {
        return "allocation error";
    }

    *ss = s;

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_walk_stream(ngx_http_request_t *r,
    ngx_rtmp_live_stream_t *ls)
{
    const char           *s;
    ngx_rtmp_live_ctx_t  *lctx;

    for (lctx = ls->ctx; lctx; lctx = lctx->next) {
        s = ngx_rtmp_control_walk_session(r, lctx);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_walk_app(ngx_http_request_t *r,
    ngx_rtmp_core_app_conf_t *cacf)
{
    size_t                     len;
    ngx_str_t                  name;
    const char                *s;
    ngx_uint_t                 n;
    ngx_rtmp_live_stream_t    *ls;
    ngx_rtmp_live_app_conf_t  *lacf;

    lacf = cacf->app_conf[ngx_rtmp_live_module.ctx_index];

    if (ngx_http_arg(r, (u_char *) "name", sizeof("name") - 1, &name) != NGX_OK)
    {
        for (n = 0; n < (ngx_uint_t) lacf->nbuckets; ++n) {
            for (ls = lacf->streams[n]; ls; ls = ls->next) {
                s = ngx_rtmp_control_walk_stream(r, ls);
                if (s != NGX_CONF_OK) {
                    return s;
                }
            }
        }

        return NGX_CONF_OK;
    }

    for (ls = lacf->streams[ngx_hash_key(name.data, name.len) % lacf->nbuckets];
         ls; ls = ls->next) 
    {
        len = ngx_strlen(ls->name);
        if (name.len != len || ngx_strncmp(name.data, ls->name, name.len)) {
            continue;
        }

        s = ngx_rtmp_control_walk_stream(r, ls);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_walk_server(ngx_http_request_t *r,
    ngx_rtmp_core_srv_conf_t *cscf)
{
    ngx_str_t                   app;
    ngx_uint_t                  n;
    const char                 *s;
    ngx_rtmp_core_app_conf_t  **pcacf;

    if (ngx_http_arg(r, (u_char *) "app", sizeof("app") - 1, &app) != NGX_OK) {
        app.len = 0;
    }

    pcacf = cscf->applications.elts;

    for (n = 0; n < cscf->applications.nelts; ++n, ++pcacf) {
        if (app.len && ((*pcacf)->name.len != app.len ||
                        ngx_strncmp((*pcacf)->name.data, app.data, app.len)))
        {
            continue;
        }

        s = ngx_rtmp_control_walk_app(r, *pcacf);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_walk(ngx_http_request_t *r, ngx_rtmp_control_handler_t h)
{
    ngx_rtmp_core_main_conf_t  *cmcf = ngx_rtmp_core_main_conf;

    ngx_str_t                   srv;
    ngx_uint_t                  sn, n;
    const char                 *msg;
    ngx_rtmp_session_t        **s;
    ngx_rtmp_control_ctx_t     *ctx;
    ngx_rtmp_core_srv_conf_t  **pcscf;

    sn = 0;
    if (ngx_http_arg(r, (u_char *) "srv", sizeof("srv") - 1, &srv) == NGX_OK) {
        sn = ngx_atoi(srv.data, srv.len);
    }

    if (sn >= cmcf->servers.nelts) {
        return "Server index out of range";
    }

    pcscf  = cmcf->servers.elts;
    pcscf += sn;

    msg = ngx_rtmp_control_walk_server(r, *pcscf);
    if (msg != NGX_CONF_OK) {
        return msg;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    s = ctx->sessions.elts;
    for (n = 0; n < ctx->sessions.nelts; n++) {
        msg = h(r, s[n]);
        if (msg != NGX_CONF_OK) {
            return msg;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_control_record(ngx_http_request_t *r, ngx_str_t *method)
{
    ngx_buf_t               *b;
    const char              *msg;
    ngx_chain_t              cl;
    ngx_rtmp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);
    ctx->filter = NGX_RTMP_CONTROL_FILTER_PUBLISHER;

    msg = ngx_rtmp_control_walk(r, ngx_rtmp_control_record_handler);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    if (ctx->path.len == 0) {
        return NGX_HTTP_NO_CONTENT;
    }

    /* output record path */

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ctx->path.len;

    b = ngx_create_temp_buf(r->pool, ctx->path.len);
    if (b == NULL) {
        goto error;
    }

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    b->last = ngx_cpymem(b->pos, ctx->path.data, ctx->path.len);
    b->last_buf = 1;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_rtmp_control_drop(ngx_http_request_t *r, ngx_str_t *method)
{
    size_t                   len;
    u_char                  *p;
    ngx_buf_t               *b;
    ngx_chain_t              cl;
    const char              *msg;
    ngx_rtmp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    if (ctx->method.len == sizeof("publisher") - 1 &&
        ngx_memcmp(ctx->method.data, "publisher", ctx->method.len) == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_PUBLISHER;

    } else if (ctx->method.len == sizeof("subscriber") - 1 &&
               ngx_memcmp(ctx->method.data, "subscriber", ctx->method.len)
               == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_SUBSCRIBER;

    } else if (method->len == sizeof("client") - 1 &&
               ngx_memcmp(ctx->method.data, "client", ctx->method.len) == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_CLIENT;

    } else {
        msg = "Undefined filter";
        goto error;
    }

    msg = ngx_rtmp_control_walk(r, ngx_rtmp_control_drop_handler);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    /* output count */

    len = NGX_INT_T_LEN;

    p = ngx_palloc(r->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = (size_t) (ngx_snprintf(p, len, "%ui", ctx->count) - p);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        goto error;
    }

    b->start = b->pos = p;
    b->end = b->last = p + len;
    b->temporary = 1;
    b->last_buf = 1;

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_rtmp_control_redirect(ngx_http_request_t *r, ngx_str_t *method)
{
    size_t                   len;
    u_char                  *p;
    ngx_buf_t               *b;
    ngx_chain_t              cl;
    const char              *msg;
    ngx_rtmp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_control_module);

    if (ctx->method.len == sizeof("publisher") - 1 &&
        ngx_memcmp(ctx->method.data, "publisher", ctx->method.len) == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_PUBLISHER;

    } else if (ctx->method.len == sizeof("subscriber") - 1 &&
               ngx_memcmp(ctx->method.data, "subscriber", ctx->method.len)
               == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_SUBSCRIBER;

    } else if (ctx->method.len == sizeof("client") - 1 &&
               ngx_memcmp(ctx->method.data, "client", ctx->method.len) == 0)
    {
        ctx->filter = NGX_RTMP_CONTROL_FILTER_CLIENT;

    } else {
        msg = "Undefined filter";
        goto error;
    }

    msg = ngx_rtmp_control_walk(r, ngx_rtmp_control_redirect_handler);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    /* output count */

    len = NGX_INT_T_LEN;

    p = ngx_palloc(r->connection->pool, len);
    if (p == NULL) {
        goto error;
    }

    len = (size_t) (ngx_snprintf(p, len, "%ui", ctx->count) - p);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        goto error;
    }

    b->start = b->pos = p;
    b->end = b->last = p + len;
    b->temporary = 1;
    b->last_buf = 1;

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_rtmp_control_handler(ngx_http_request_t *r)
{
    u_char                       *p;
    ngx_str_t                     section, method;
    ngx_uint_t                    n;
    ngx_rtmp_control_ctx_t       *ctx;
    ngx_rtmp_control_loc_conf_t  *llcf;

    llcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_control_module);
    if (llcf->control == 0) {
        return NGX_DECLINED;
    }

    /* uri format: .../section/method?args */

    ngx_str_null(&section);
    ngx_str_null(&method);

    for (n = r->uri.len; n; --n) {
        p = &r->uri.data[n - 1];

        if (*p != '/') {
            continue;
        }

        if (method.data) {
            section.data = p + 1;
            section.len  = method.data - section.data - 1;
            break;
        }

        method.data = p + 1;
        method.len  = r->uri.data + r->uri.len - method.data;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
                   "rtmp_control: section='%V' method='%V'",
                   &section, &method);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_control_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_rtmp_control_module);

    if (ngx_array_init(&ctx->sessions, r->pool, 1, sizeof(void *)) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->method = method;

#define NGX_RTMP_CONTROL_SECTION(flag, secname)                             \
    if (llcf->control & NGX_RTMP_CONTROL_##flag &&                          \
        section.len == sizeof(#secname) - 1 &&                              \
        ngx_strncmp(section.data, #secname, sizeof(#secname) - 1) == 0)     \
    {                                                                       \
        return ngx_rtmp_control_##secname(r, &method);                      \
    }

    NGX_RTMP_CONTROL_SECTION(RECORD, record);
    NGX_RTMP_CONTROL_SECTION(DROP, drop);
    NGX_RTMP_CONTROL_SECTION(REDIRECT, redirect);

#undef NGX_RTMP_CONTROL_SECTION

    return NGX_DECLINED;
}


static void *
ngx_rtmp_control_create_loc_conf(ngx_conf_t *cf)
{
    ngx_rtmp_control_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_control_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->control = 0;

    return conf;
}


static char *
ngx_rtmp_control_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_control_loc_conf_t  *prev = parent;
    ngx_rtmp_control_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->control, prev->control, 0);

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rtmp_control_handler;

    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}
