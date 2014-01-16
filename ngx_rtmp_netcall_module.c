
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_netcall_module.h"


static ngx_int_t ngx_rtmp_netcall_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_netcall_create_srv_conf(ngx_conf_t *cf);
static char * ngx_rtmp_netcall_merge_srv_conf(ngx_conf_t *cf,
       void *parent, void *child);

static void ngx_rtmp_netcall_close(ngx_connection_t *cc);
static void ngx_rtmp_netcall_detach(ngx_connection_t *cc);

static void ngx_rtmp_netcall_recv(ngx_event_t *rev);
static void ngx_rtmp_netcall_send(ngx_event_t *wev);


typedef struct {
    ngx_msec_t                                  timeout;
    size_t                                      bufsize;
    ngx_log_t                                  *log;
} ngx_rtmp_netcall_srv_conf_t;


typedef struct ngx_rtmp_netcall_session_s {
    ngx_rtmp_session_t                         *session;
    ngx_peer_connection_t                      *pc;
    ngx_url_t                                  *url;
    struct ngx_rtmp_netcall_session_s          *next;
    void                                       *arg;
    ngx_rtmp_netcall_handle_pt                  handle;
    ngx_rtmp_netcall_filter_pt                  filter;
    ngx_rtmp_netcall_sink_pt                    sink;
    ngx_chain_t                                *in;
    ngx_chain_t                                *inlast;
    ngx_chain_t                                *out;
    ngx_msec_t                                  timeout;
    unsigned                                    detached:1;
    size_t                                      bufsize;
} ngx_rtmp_netcall_session_t;


typedef struct {
    ngx_rtmp_netcall_session_t                 *cs;
} ngx_rtmp_netcall_ctx_t;


static ngx_command_t  ngx_rtmp_netcall_commands[] = {

    { ngx_string("netcall_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_netcall_srv_conf_t, timeout),
      NULL },

    { ngx_string("netcall_buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_netcall_srv_conf_t, bufsize),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_netcall_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_netcall_postconfiguration,     /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_netcall_create_srv_conf,       /* create server configuration */
    ngx_rtmp_netcall_merge_srv_conf,        /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_netcall_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_netcall_module_ctx,           /* module context */
    ngx_rtmp_netcall_commands,              /* module directives */
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
ngx_rtmp_netcall_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_netcall_srv_conf_t     *nscf;

    nscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_netcall_srv_conf_t));
    if (nscf == NULL) {
        return NULL;
    }

    nscf->timeout = NGX_CONF_UNSET_MSEC;
    nscf->bufsize = NGX_CONF_UNSET_SIZE;

    nscf->log = &cf->cycle->new_log;

    return nscf;
}


static char *
ngx_rtmp_netcall_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_netcall_srv_conf_t *prev = parent;
    ngx_rtmp_netcall_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 10000);
    ngx_conf_merge_size_value(conf->bufsize, prev->bufsize, 1024);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_netcall_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_netcall_ctx_t         *ctx;
    ngx_rtmp_netcall_session_t     *cs;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    if (ctx) {
        for (cs = ctx->cs; cs; cs = cs->next) {
            ngx_rtmp_netcall_detach(cs->pc->connection);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_netcall_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_rtmp_netcall_session_t   *cs = data;

    pc->sockaddr =(struct sockaddr *)&cs->url->sockaddr;
    pc->socklen = cs->url->socklen;
    pc->name = &cs->url->host;

    return NGX_OK;
}


static void
ngx_rtmp_netcall_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}


ngx_int_t
ngx_rtmp_netcall_create(ngx_rtmp_session_t *s, ngx_rtmp_netcall_init_t *ci)
{
    ngx_rtmp_netcall_ctx_t         *ctx;
    ngx_peer_connection_t          *pc;
    ngx_rtmp_netcall_session_t     *cs;
    ngx_rtmp_netcall_srv_conf_t    *nscf;
    ngx_connection_t               *c, *cc;
    ngx_pool_t                     *pool;
    ngx_int_t                       rc;

    pool = NULL;
    c = s->connection;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_netcall_module);
    if (nscf == NULL) {
        goto error;
    }

    /* get module context */
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool,
                sizeof(ngx_rtmp_netcall_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_netcall_module);
    }

    /* Create netcall pool, connection, session.
     * Note we use shared (app-wide) log because
     * s->connection->log might be unavailable
     * in detached netcall when it's being closed */
    pool = ngx_create_pool(4096, nscf->log);
    if (pool == NULL) {
        goto error;
    }

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto error;
    }

    cs = ngx_pcalloc(pool, sizeof(ngx_rtmp_netcall_session_t));
    if (cs == NULL) {
        goto error;
    }

    /* copy arg to connection pool */
    if (ci->argsize) {
        cs->arg = ngx_pcalloc(pool, ci->argsize);
        if (cs->arg == NULL) {
            goto error;
        }
        ngx_memcpy(cs->arg, ci->arg, ci->argsize);
    }

    cs->timeout = nscf->timeout;
    cs->bufsize = nscf->bufsize;
    cs->url = ci->url;
    cs->session = s;
    cs->filter = ci->filter;
    cs->sink = ci->sink;
    cs->handle = ci->handle;
    if (cs->handle == NULL) {
        cs->detached = 1;
    }

    pc->log = nscf->log;
    pc->get = ngx_rtmp_netcall_get_peer;
    pc->free = ngx_rtmp_netcall_free_peer;
    pc->data = cs;

    /* connect */
    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "netcall: connection failed");
        goto error;
    }

    cc = pc->connection;
    cc->data = cs;
    cc->pool = pool;
    cs->pc = pc;

    cs->out = ci->create(s, ci->arg, pool);
    if (cs->out == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "netcall: creation failed");
        ngx_close_connection(pc->connection);
        goto error;
    }

    cc->write->handler = ngx_rtmp_netcall_send;
    cc->read->handler = ngx_rtmp_netcall_recv;

    if (!cs->detached) {
        cs->next = ctx->cs;
        ctx->cs = cs;
    }

    ngx_rtmp_netcall_send(cc->write);

    return c->destroyed ? NGX_ERROR : NGX_OK;

error:
    if (pool) {
        ngx_destroy_pool(pool);
    }

    return NGX_ERROR;
}


static void
ngx_rtmp_netcall_close(ngx_connection_t *cc)
{
    ngx_rtmp_netcall_session_t         *cs, **css;
    ngx_pool_t                         *pool;
    ngx_rtmp_session_t                 *s;
    ngx_rtmp_netcall_ctx_t             *ctx;
    ngx_buf_t                          *b;

    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    cc->destroyed = 1;

    if (!cs->detached) {
        s = cs->session;
        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

        if (cs->in && cs->sink) {
            cs->sink(cs->session, cs->in);

            b = cs->in->buf;
            b->pos = b->last = b->start;

        }

        for(css = &ctx->cs; *css; css = &((*css)->next)) {
            if (*css == cs) {
                *css = cs->next;
                break;
            }
        }

        if (cs->handle && cs->handle(s, cs->arg, cs->in) != NGX_OK) {
            ngx_rtmp_finalize_session(s);
        }
    }

    pool = cc->pool;
    ngx_close_connection(cc);
    ngx_destroy_pool(pool);
}


static void
ngx_rtmp_netcall_detach(ngx_connection_t *cc)
{
    ngx_rtmp_netcall_session_t         *cs;

    cs = cc->data;
    cs->detached = 1;
}


static void
ngx_rtmp_netcall_recv(ngx_event_t *rev)
{
    ngx_rtmp_netcall_session_t         *cs;
    ngx_connection_t                   *cc;
    ngx_chain_t                        *cl;
    ngx_int_t                           n;
    ngx_buf_t                          *b;

    cc = rev->data;
    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    if (rev->timedout) {
        cc->timedout = 1;
        ngx_rtmp_netcall_close(cc);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {

        if (cs->inlast == NULL ||
            cs->inlast->buf->last == cs->inlast->buf->end)
        {
            if (cs->in && cs->sink) {
                if (!cs->detached) {
                    if (cs->sink(cs->session, cs->in) != NGX_OK) {
                        ngx_rtmp_netcall_close(cc);
                        return;
                    }
                }

                b = cs->in->buf;
                b->pos = b->last = b->start;

            } else {
                cl = ngx_alloc_chain_link(cc->pool);
                if (cl == NULL) {
                    ngx_rtmp_netcall_close(cc);
                    return;
                }

                cl->next = NULL;

                cl->buf = ngx_create_temp_buf(cc->pool, cs->bufsize);
                if (cl->buf == NULL) {
                    ngx_rtmp_netcall_close(cc);
                    return;
                }

                if (cs->in == NULL) {
                    cs->in = cl;
                } else {
                    cs->inlast->next = cl;
                }

                cs->inlast = cl;
            }
        }

        b = cs->inlast->buf;

        n = cc->recv(cc, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_netcall_close(cc);
            return;
        }

        if (n == NGX_AGAIN) {
            if (cs->filter && cs->in
                && cs->filter(cs->in) != NGX_AGAIN)
            {
                ngx_rtmp_netcall_close(cc);
                return;
            }

            ngx_add_timer(rev, cs->timeout);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_rtmp_netcall_close(cc);
            }
            return;
        }

        b->last += n;
    }
}


static void
ngx_rtmp_netcall_send(ngx_event_t *wev)
{
    ngx_rtmp_netcall_session_t         *cs;
    ngx_connection_t                   *cc;
    ngx_chain_t                        *cl;

    cc = wev->data;
    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, cc->log, NGX_ETIMEDOUT,
                "netcall: client send timed out");
        cc->timedout = 1;
        ngx_rtmp_netcall_close(cc);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    cl = cc->send_chain(cc, cs->out, 0);

    if (cl == NGX_CHAIN_ERROR) {
        ngx_rtmp_netcall_close(cc);
        return;
    }

    cs->out = cl;

    /* more data to send? */
    if (cl) {
        ngx_add_timer(wev, cs->timeout);
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_rtmp_netcall_close(cc);
        }
        return;
    }

    /* we've sent everything we had.
     * now receive reply */
    ngx_del_event(wev, NGX_WRITE_EVENT, 0);

    ngx_rtmp_netcall_recv(cc->read);
}


ngx_chain_t *
ngx_rtmp_netcall_http_format_request(ngx_int_t method, ngx_str_t *host,
                                     ngx_str_t *uri, ngx_chain_t *args,
                                     ngx_chain_t *body, ngx_pool_t *pool,
                                     ngx_str_t *content_type)
{
    ngx_chain_t                    *al, *bl, *ret;
    ngx_buf_t                      *b;
    size_t                          content_length;
    static const char              *methods[2] = { "GET", "POST" };
    static const char               rq_tmpl[] = " HTTP/1.0\r\n"
                                                "Host: %V\r\n"
                                                "Content-Type: %V\r\n"
                                                "Connection: Close\r\n"
                                                "Content-Length: %uz\r\n"
                                                "\r\n";

    content_length = 0;
    for (al = body; al; al = al->next) {
        b = al->buf;
        content_length += (b->last - b->pos);
    }

    /* create first buffer */

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof("POST") + /* longest method + 1 */
                                  uri->len);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "%s %V",
                           methods[method], uri);

    al->buf = b;

    ret = al;

    if (args) {
        *b->last++ = '?';
        al->next = args;
        for (al = args; al->next; al = al->next);
    }

    /* create second buffer */

    bl = ngx_alloc_chain_link(pool);
    if (bl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof(rq_tmpl) + host->len +
                            content_type->len + NGX_SIZE_T_LEN);
    if (b == NULL) {
        return NULL;
    }

    bl->buf = b;

    b->last = ngx_snprintf(b->last, b->end - b->last, rq_tmpl,
                           host, content_type, content_length);

    al->next = bl;
    bl->next = body;

    return ret;
}


ngx_chain_t *
ngx_rtmp_netcall_http_format_session(ngx_rtmp_session_t *s, ngx_pool_t *pool)
{
    ngx_chain_t                    *cl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;

    addr_text = &s->connection->addr_text;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
            sizeof("app=") - 1 + s->app.len * 3 +
            sizeof("&flashver=") - 1 + s->flashver.len * 3 +
            sizeof("&swfurl=") - 1 + s->swf_url.len * 3 +
            sizeof("&tcurl=") - 1 + s->tc_url.len * 3 +
            sizeof("&pageurl=") - 1 + s->page_url.len * 3 +
            sizeof("&addr=") - 1 + addr_text->len * 3 +
            sizeof("&clientid=") - 1 + NGX_INT_T_LEN
        );

    if (b == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "app=", sizeof("app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->app.data, s->app.len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&flashver=",
                         sizeof("&flashver=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->flashver.data,
                                       s->flashver.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&swfurl=",
                         sizeof("&swfurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->swf_url.data,
                                       s->swf_url.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&tcurl=",
                         sizeof("&tcurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->tc_url.data,
                                       s->tc_url.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&pageurl=",
                         sizeof("&pageurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->page_url.data,
                                       s->page_url.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&addr=", sizeof("&addr=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, addr_text->data,
                                       addr_text->len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&clientid=",
                         sizeof("&clientid=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", (ngx_uint_t) s->connection->number);

    return cl;
}


ngx_chain_t *
ngx_rtmp_netcall_http_skip_header(ngx_chain_t *in)
{
    ngx_buf_t       *b;

    /* find \n[\r]\n */
    enum {
        normal,
        lf,
        lfcr
    } state = normal;

    if (in == NULL) {
        return NULL;
    }

    b = in->buf;

    for ( ;; ) {

        while (b->pos == b->last) {
            in = in->next;
            if (in == NULL) {
                return NULL;
            }
            b = in->buf;
        }

        switch (*b->pos++) {
            case '\r':
                state = (state == lf) ? lfcr : normal;
                break;

            case '\n':
                if (state != normal) {
                    return in;
                }
                state = lf;
                break;

           default:
                state = normal;
        }
    }
}


ngx_chain_t *
ngx_rtmp_netcall_memcache_set(ngx_rtmp_session_t *s, ngx_pool_t *pool,
        ngx_str_t *key, ngx_str_t *value, ngx_uint_t flags, ngx_uint_t sec)
{
    ngx_chain_t                    *cl;
    ngx_buf_t                      *b;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof("set ") - 1 + key->len +
                            (1 + NGX_INT_T_LEN) * 3 +
                            (sizeof("\r\n") - 1) * 2 + value->len);

    if (b == NULL) {
        return NULL;
    }

    cl->next = NULL;
    cl->buf = b;

    b->last = ngx_sprintf(b->pos, "set %V %ui %ui %ui\r\n%V\r\n",
                          key, flags, sec, (ngx_uint_t) value->len, value);

    return cl;
}


static ngx_int_t
ngx_rtmp_netcall_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_netcall_disconnect;

    return NGX_OK;
}

