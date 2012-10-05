/*
 * Copyright (c) 2012 Neutron Soutmun
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include "ngx_rtmp.h"

#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_authen_module.h"


static ngx_rtmp_connect_pt  next_connect;


static char *ngx_rtmp_authen_on_connect(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static ngx_int_t ngx_rtmp_authen_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_authen_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_authen_merge_app_conf(ngx_conf_t *cf,
        void *parent, void *child);


typedef struct {
    ngx_url_t    *connect_url;
} ngx_rtmp_authen_app_conf_t;


static ngx_command_t  ngx_rtmp_authen_commands[] = {
    { ngx_string("on_connect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_authen_on_connect,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_authen_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_authen_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_authen_create_app_conf,        /* create app configuration */
    ngx_rtmp_authen_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_authen_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_authen_module_ctx,            /* module context */
    ngx_rtmp_authen_commands,               /* module directives */
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
ngx_rtmp_authen_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_authen_app_conf_t    *aacf;

    aacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_authen_app_conf_t));
    if (aacf == NULL) {
        return NULL;
    }

    return aacf;
}


static char *
ngx_rtmp_authen_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_authen_app_conf_t    *prev = parent;
    ngx_rtmp_authen_app_conf_t    *conf = child;

    ngx_conf_merge_ptr_value(conf->connect_url, prev->connect_url, 0);

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_authen_connect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_authen_app_conf_t    *aacf;
    ngx_chain_t                   *hl, *cl, *pl;
    ngx_buf_t                     *b;
    ngx_str_t                     *addr_text;

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_authen_module);

    /* common variables */
    cl = ngx_rtmp_netcall_http_format_session(s, pool);

    if (cl == NULL) {
        return NULL;
    }

    /* connect variables */
    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("&call=connect") +
            sizeof("&addr=") + addr_text->len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char *)"&call=connect",
            sizeof("&call=connect") - 1);

    b->last = ngx_cpymem(b->last, (u_char *)"&addr=", sizeof("&addr=") - 1);
    b->last = (u_char *)ngx_escape_uri(b->last, addr_text->data,
            addr_text->len, 0);

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(aacf->connect_url, pool,
            cl->buf->last - cl->buf->pos + (pl->buf->last - pl->buf->pos),
            &ngx_rtmp_netcall_content_type_urlencoded);

    if (hl == NULL) {
        return NULL;
    }

    hl->next = cl;
    cl->next = pl;
    pl->next = NULL;

    return hl;
}


static ngx_int_t
ngx_rtmp_authen_http_response_decode(ngx_rtmp_session_t *s,
        ngx_rtmp_authen_ctx_t *ctx)
{
    ngx_http_request_t    r;
    ngx_str_t             val;
    u_char                val_buf[NGX_RTMP_AUTHEN_MAX_RESPONSE];
    u_char                status;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect (authen): response: %s", ctx->resp.data);

    val.len  = 0;
    val.data = val_buf;

    r.args.len  = ctx->resp.len;
    r.args.data = ctx->resp.data;

    ctx->conn_desc.len = 0;

    if (ngx_http_arg(&r, (u_char *)"desc", sizeof("desc") - 1, &val) == NGX_OK
            && val.len > 0) {

        ctx->conn_desc.len  = ngx_base64_decoded_length(val.len);
        ctx->conn_desc.data = ngx_pcalloc(s->connection->pool,
                ctx->conn_desc.len + 1);

        if (ctx->conn_desc.data != NULL &&
                ngx_decode_base64(&ctx->conn_desc, &val) == NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "connect (authen): description: %s", ctx->conn_desc.data);
        } else {
          ctx->conn_desc.len = 0;
        }
    }

    val.len = 0;
    if (ngx_http_arg(&r, (u_char *)"status", sizeof ("status") - 1,
            &val) != NGX_OK || val.len == 0) {
        return NGX_ERROR;
    } else {
        status = val.data[0];

        ctx->user.len = 0;
        val.len       = 0;

        if (ngx_http_arg(&r, (u_char *)"user", sizeof("user") - 1,
                &val) == NGX_OK && val.len > 0) {
            ctx->user.data = ngx_pcalloc(s->connection->pool, val.len + 1);

            if (ctx->user.data != NULL) {
                u_char *dst = ctx->user.data;

                ngx_unescape_uri(&dst, &val.data, val.len, 0);
                *dst = '\0';

                ctx->user.len = ngx_strlen(ctx->user.data);
            }
        }

        ctx->authmod.len = 0;
        val.len       = 0;

        if (ngx_http_arg(&r, (u_char *)"authmod", sizeof("authmod") - 1,
                &val) == NGX_OK && val.len > 0) {
            ctx->authmod.data = ngx_pcalloc(s->connection->pool, val.len + 1);

            if (ctx->authmod.data != NULL) {
                u_char *dst = ctx->authmod.data;

                ngx_unescape_uri(&dst, &val.data, val.len, 0);
                *dst = '\0';

                ctx->authmod.len = ngx_strlen(ctx->authmod.data);
            }
        }
    }

    switch (status) {
    /* Allow */
    case (u_char)'a':
    case (u_char)'A':
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Allow, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Allow");
        }

        ctx->conn_status = NGX_RTMP_CONN_ALLOW;
        return NGX_OK;

    /* Reject */
    case (u_char)'r':
    case (u_char)'R':
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Reject, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Reject");
        }

        if (ctx->conn_desc.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Reject, reason: %s",
                    ctx->conn_desc.data);
        }

        ctx->conn_status = NGX_RTMP_CONN_REJECT;
        return NGX_OK;

    /* Deny */
    case (u_char)'d':
    case (u_char)'D':
    default:
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Deny, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): Deny");
        }

        ctx->conn_status = NGX_RTMP_CONN_DENY;
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_rtmp_authen_parse_http_response(ngx_rtmp_session_t *s, ngx_chain_t *in,
        ngx_rtmp_authen_ctx_t *ctx)
{
    ngx_buf_t    *b;
    size_t        chunk;
    size_t        len;

    ctx->conn_status  = NGX_RTMP_CONN_DENY;

    enum {
        sw_header = 0,
        sw_cr,
        sw_crlf,
        sw_crlfcr,
        sw_lf,
        sw_response
    } state;

    state = 0;

    while (in) {
        u_char    *p = NULL;

        b = in->buf;
        for (p = b->pos; p < b->last; p++) {
            u_char ch = *p;

            switch (state) {
            case sw_header:
                switch (ch) {
                    case CR:
                      state = sw_cr;
                      break;
                    case LF:
                      state = sw_lf;
                      break;
                }
                break;

            case sw_cr:
                state = ch == LF ? sw_crlf : sw_header;
                break;

            case sw_crlf:
                state = ch == CR ? sw_crlfcr : sw_header;
                break;

            case sw_crlfcr:
            case sw_lf:
                state = ch == LF ? sw_response : sw_header;
                break;

            case sw_response:
                chunk = b->last - p;
                len = chunk;

                if (ctx->resp.len + len >= NGX_RTMP_AUTHEN_MAX_RESPONSE) {
                    len = NGX_RTMP_AUTHEN_MAX_RESPONSE - ctx->resp.len - 1;
                }

                ngx_memcpy(ctx->resp.data, p, len);
                ctx->resp.len += len;

                if (len != chunk) {
                    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                            "connect (authen): response is truncated, "
                            "incompleted response may fail the authentication");
                    goto done;
                }

                p += len;
                break;
            }
        }

        in = in->next;
    }

done:
    ctx->resp.data[ctx->resp.len] = '\0';
    if (ctx->resp.data[0] != '\0') {
        return ngx_rtmp_authen_http_response_decode (s, ctx);
    } else {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "connect (authen): Deny");
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_rtmp_authen_parse_http_retcode(ngx_rtmp_session_t *s, ngx_chain_t *in,
        ngx_rtmp_authen_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_int_t     n;
    u_char        c;

    /* find 10th character */
    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "connect (authen): HTTP retcode: %dxx", (int)(c - '0'));

                if (c == (u_char)'2')
                    return NGX_OK;
                else
                    return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "connect (authen): invalid HTTP retcode: %d..", (int)c);

            return NGX_ERROR;
        }

        n -= (b->last - b->pos);
        in = in->next;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_authen_connect_handle(ngx_rtmp_session_t *s, void *arg,
        ngx_chain_t *in)
{
    ngx_rtmp_authen_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_authen_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_authen_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_authen_module);

        ctx->resp.len  = 0;
        ctx->resp.data = ctx->resp_data;
    }

    if (ngx_rtmp_authen_parse_http_retcode(s, in, ctx) != NGX_OK)
        return NGX_ERROR;

    if (ngx_rtmp_authen_parse_http_response(s, in, ctx) != NGX_OK)
        return NGX_ERROR;

    return next_connect(s, (ngx_rtmp_connect_t *)arg);
}


static ngx_int_t
ngx_rtmp_authen_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_core_app_conf_t      **cacfp;
    ngx_rtmp_authen_app_conf_t     *aacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_uint_t                      n;
    size_t                          len;
    u_char                         *p;

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "connect (authen): duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    p = ngx_strchr (v->app, '?');
    if (p) {
        *p = 0;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect (authen): app='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
            "object_encoding=%ui",
            v->app, v->flashver, v->swf_url, v->tc_url, v->page_url,
            (uint32_t)v->acodecs, (uint32_t)v->vcodecs,
            (ngx_int_t)v->object_encoding);

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v->name);                                        \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v->name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->acodecs = v->acodecs;
    s->vcodecs = v->vcodecs;

    /* find application & set app_conf */
    len = ngx_strlen(v->app);

    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == len
                && !ngx_strncmp((*cacfp)->name.data, v->app, len))
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "connect: application not found: '%s'", v->app);
        return NGX_ERROR;
    }

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_authen_module);
    if (aacf == NULL) {
        goto next;
    }

    if (aacf->connect_url == NULL) {
        goto next;
    }

    ngx_memzero(&ci, sizeof(ci));
    ci.url     = aacf->connect_url;
    ci.create  = ngx_rtmp_authen_connect_create;
    ci.handle  = ngx_rtmp_authen_connect_handle;
    ci.arg     = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci) == NGX_OK ? NGX_AGAIN : NGX_ERROR;

next:
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect (authen): bypassed");
    return next_connect(s, v);
}


static char *
ngx_rtmp_authen_on_connect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_authen_app_conf_t    *aacf;
    ngx_str_t                     *url;
    ngx_url_t                     *u;
    size_t                         add;
    ngx_str_t                     *value;

    value = cf->args->elts;
    url   = &value[1];
    add   = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len  = url->len - add;
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

    aacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_authen_module);
    aacf->connect_url = u;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_authen_postconfiguration(ngx_conf_t *cf)
{
    next_connect     = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_authen_connect;

    return NGX_OK;
}
