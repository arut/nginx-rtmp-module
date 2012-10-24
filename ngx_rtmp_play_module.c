/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_streams.h"


static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_seek_pt                 next_seek;
static ngx_rtmp_pause_pt                next_pause;


static char *ngx_rtmp_play_url(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void *ngx_rtmp_play_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_play_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_play_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_play_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);

static ngx_int_t ngx_rtmp_play_do_init(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_do_done(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_do_start(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_do_stop(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_do_seek(ngx_rtmp_session_t *s,
                                       ngx_uint_t timestamp);

static ngx_int_t ngx_rtmp_play_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_play_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v);
static ngx_int_t ngx_rtmp_play_pause(ngx_rtmp_session_t *s,
                                     ngx_rtmp_pause_t *v);
static void ngx_rtmp_play_send(ngx_event_t *e);
static ngx_int_t ngx_rtmp_play_open(ngx_rtmp_session_t *s, double start);
static ngx_int_t ngx_rtmp_play_remote_handle(ngx_rtmp_session_t *s,
       void *arg, ngx_chain_t *in);
static ngx_chain_t * ngx_rtmp_play_remote_create(ngx_rtmp_session_t *s,
       void *arg, ngx_pool_t *pool);
static ngx_int_t ngx_rtmp_play_open_remote(ngx_rtmp_session_t *s,
       ngx_rtmp_play_t *v);


static ngx_command_t  ngx_rtmp_play_commands[] = {

    { ngx_string("play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_play_url,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("play_temp_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_play_app_conf_t, temp_path),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_play_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_play_postconfiguration,        /* postconfiguration */
    ngx_rtmp_play_create_main_conf,         /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_play_create_app_conf,          /* create app configuration */
    ngx_rtmp_play_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_play_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_play_module_ctx,              /* module context */
    ngx_rtmp_play_commands,                 /* module directives */
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
ngx_rtmp_play_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_play_main_conf_t      *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_play_main_conf_t));

    if (pmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&pmcf->fmts, cf->pool, 1, 
                       sizeof(ngx_rtmp_play_fmt_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return pmcf;
}


static void *
ngx_rtmp_play_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_play_app_conf_t      *pacf;

    pacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_play_app_conf_t));

    if (pacf == NULL) {
        return NULL;
    }

    return pacf;
}


static char *
ngx_rtmp_play_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_play_app_conf_t *prev = parent;
    ngx_rtmp_play_app_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->root, prev->root, "");
    ngx_conf_merge_str_value(conf->temp_path, prev->temp_path, "/tmp");

    return NGX_CONF_OK;
}


static void
ngx_rtmp_play_send(ngx_event_t *e)
{
    ngx_rtmp_session_t     *s = e->data;
    ngx_rtmp_play_ctx_t    *ctx;
    ngx_int_t               rc;
    ngx_uint_t              ts;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL || ctx->fmt == NULL || ctx->fmt->send == NULL) {
        return;
    }

    ts = 0;

    rc = ctx->fmt->send(s, &ctx->file, &ts);

    if (rc > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "play: send schedule %i", rc);

        ngx_add_timer(e, rc);
        return;
    }

    if (rc == NGX_AGAIN) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "play: send buffer full");

        ngx_post_event(e, &s->posted_dry_events);
        return;
    }

    if (rc == NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "play: send restart");

        ngx_post_event(e, &ngx_posted_events);
        return;
    }


    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: send done");

    ngx_rtmp_send_user_stream_eof(s, NGX_RTMP_MSID);

    ngx_rtmp_send_play_status(s, "NetStream.Play.Complete", "status", ts, 0);

    ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stopped");
}


static ngx_int_t
ngx_rtmp_play_do_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->fmt && ctx->fmt->init &&
        ctx->fmt->init(s, &ctx->file) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_do_done(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->fmt && ctx->fmt->done &&
        ctx->fmt->done(s, &ctx->file) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_do_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: start");

    if (ctx->fmt && ctx->fmt->start &&
        ctx->fmt->start(s, &ctx->file) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_post_event((&ctx->send_evt), &ngx_posted_events);

    ctx->playing = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_do_seek(ngx_rtmp_session_t *s, ngx_uint_t timestamp)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: seek timestamp=%ui", timestamp);

    if (ctx->fmt && ctx->fmt->seek &&
        ctx->fmt->seek(s, &ctx->file, timestamp) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ctx->playing) {
        ngx_post_event((&ctx->send_evt), &ngx_posted_events);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_do_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: stop");

    if (ctx->send_evt.timer_set) {
        ngx_del_timer(&ctx->send_evt);
    }

    if (ctx->send_evt.prev) {
        ngx_delete_posted_event((&ctx->send_evt));
    }

    if (ctx->fmt && ctx->fmt->stop &&
        ctx->fmt->stop(s, &ctx->file) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->playing = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: close_stream");

    ngx_rtmp_play_do_stop(s);

    ngx_rtmp_play_do_done(s);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
        ctx->file.fd = NGX_INVALID_FILE;
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_play_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL || ctx->file.fd == NGX_INVALID_FILE) {
        goto next;
    }

    ngx_rtmp_play_do_seek(s, v->offset);

next:
    return next_seek(s, v);
}


static ngx_int_t
ngx_rtmp_play_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL || ctx->file.fd == NGX_INVALID_FILE) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: pause=%i timestamp=%f",
                   (ngx_int_t) v->pause, v->position);

    if (v->pause) {
        ngx_rtmp_play_do_stop(s);
    } else {
        ngx_rtmp_play_do_start(s); /*TODO: v->position? */
    }

next:
    return next_pause(s, v);
}


static ngx_int_t
ngx_rtmp_play_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_play_main_conf_t      *pmcf;
    ngx_rtmp_play_app_conf_t       *pacf;
    ngx_rtmp_play_ctx_t            *ctx;
    u_char                         *p;
    ngx_rtmp_play_fmt_t            *fmt, **pfmt;
    ngx_str_t                      *pfx, *sfx;
    ngx_str_t                       name;
    ngx_uint_t                      n;
    static ngx_str_t                nosfx;
    static u_char                   path[NGX_MAX_PATH];

    pmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_play_module);

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);

    if (pacf == NULL || (pacf->root.len == 0 && pacf->url == NULL)) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: play name='%s' timestamp=%i",
                   v->name, (ngx_int_t) v->start);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx && ctx->file.fd != NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: already playing");
        goto next;
    }

    /* check for double-dot in v->name;
     * we should not move out of play directory */
    for (p = v->name; *p; ++p) {
        if (ngx_path_separator(p[0]) &&
            p[1] == '.' && p[2] == '.' && 
            ngx_path_separator(p[3])) 
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                         "play: bad name '%s'", v->name);
            return NGX_ERROR;
        }
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_play_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_play_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->file.log = s->connection->log;

    name.len = ngx_strlen(v->name);
    name.data = v->name;

    pfmt = pmcf->fmts.elts;
    
    for (n = 0; n < pmcf->fmts.nelts; ++n, ++pfmt) {
        fmt = *pfmt;

        pfx = &fmt->pfx;
        sfx = &fmt->sfx;

        if (pfx->len == 0 && ctx->fmt == NULL) {
            ctx->fmt = fmt;
        }

        if (pfx->len && name.len >= pfx->len &&
            ngx_strncasecmp(pfx->data, name.data, pfx->len) == 0)
        {
            name.data += pfx->len;
            name.len  -= pfx->len;

            ctx->fmt = fmt;
            break;
        }

        if (name.len >= sfx->len &&
            ngx_strncasecmp(sfx->data, name.data + name.len - sfx->len, 
                            sfx->len) == 0)
        {
            ctx->fmt = fmt;
        }
    }

    if (ctx->fmt == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: fmt not found");
        goto next;
    }

    ctx->file.fd = NGX_INVALID_FILE;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "play %s: %V", pacf->url ? "remote" : "local",
                  &ctx->fmt->name);

    sfx = &ctx->fmt->sfx;

    if (name.len >= sfx->len &&
        ngx_strncasecmp(sfx->data, name.data + name.len - sfx->len, 
                        sfx->len) 
        == 0)
    {
        sfx = &nosfx;
    }

    /* remote? */
    if (pacf->url) {
        ctx->name.data = ngx_palloc(s->connection->pool, name.len + sfx->len);
        if (ctx->name.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_sprintf(ctx->name.data, "%V%V", &name, sfx);
        *p = 0;

        ctx->name.len = p - ctx->name.data;

        return ngx_rtmp_play_open_remote(s, v);
    }

    /* open local */

    p = ngx_snprintf(path, sizeof(path), "%V/%V%V", &pacf->root, &name, sfx);
    *p = 0;

    ctx->file.fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 
                                 NGX_FILE_DEFAULT_ACCESS);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "play: error opening file '%s'", path);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: opened local file '%s'", path);

    if (ngx_rtmp_play_open(s, v->start) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_play_open(ngx_rtmp_session_t *s, double start)
{
    ngx_rtmp_play_ctx_t    *ctx;
    ngx_event_t            *e;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    e = &ctx->send_evt;
    e->data = s;
    e->handler = ngx_rtmp_play_send;
    e->log = s->connection->log;

    ngx_rtmp_send_user_recorded(s, 1);

    if (ngx_rtmp_play_do_init(s) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_play_do_seek(s, start < 0 ? 0 : start) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_play_do_start(s) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_chain_t *
ngx_rtmp_play_remote_create(ngx_rtmp_session_t *s, void *arg, ngx_pool_t *pool)
{
    ngx_rtmp_play_t                *v = arg;

    ngx_rtmp_play_app_conf_t       *pacf;
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_chain_t                    *hl;
    ngx_str_t                      *addr_text, uri;
    u_char                         *p;
    size_t                          args_len, len;
    static ngx_str_t                text_plain = ngx_string("text/plain");

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    args_len = ngx_strlen(v->args);
    addr_text = &s->connection->addr_text;

    len = pacf->url->uri.len + 1 + ctx->name.len + 
          sizeof("?addr=") + addr_text->len * 3 +
          1 + args_len;

    uri.data = ngx_palloc(pool, len);
    if (uri.data == NULL) {
        return NULL;
    }

    p = uri.data;

    p = ngx_cpymem(p, pacf->url->uri.data, pacf->url->uri.len);

    if (p == uri.data || p[-1] != '/') {
        *p++ = '/';
    }

    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);
    p = ngx_cpymem(p, (u_char*)"?addr=", sizeof("&addr=") -1);
    p = (u_char*)ngx_escape_uri(p, addr_text->data, addr_text->len, 0);
    if (args_len) {
        *p++ = '&';
        p = (u_char *) ngx_cpymem(p, v->args, args_len);
    }

    uri.len = p - uri.data;

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(NGX_RTMP_NETCALL_HTTP_GET,
            &uri, &pacf->url->host, pool, 0, &text_plain);

    if (hl == NULL) {
        return NULL;
    }

    return hl;
}


static ngx_int_t 
ngx_rtmp_play_remote_handle(ngx_rtmp_session_t *s, void *arg, ngx_chain_t *in)
{
    ngx_rtmp_play_t                *v = arg;

    if (ngx_rtmp_play_open(s, v->start) != NGX_OK) {
        return NGX_ERROR;
    }

    return next_play(s, (ngx_rtmp_play_t *)arg);
}


static ngx_int_t 
ngx_rtmp_play_remote_sink(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_play_ctx_t    *ctx;
    ngx_buf_t              *b;
    ngx_int_t               rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    /* skip HTTP header */
    while (in && ctx->ncrs != 2) {
        b = in->buf;

        for (; b->pos != b->last && ctx->ncrs != 2; ++b->pos) {
            switch (*b->pos) {
                case '\n':
                    ++ctx->ncrs;
                case '\r':
                    break;
                default:
                    ctx->ncrs = 0;
            }
        }

        if (b->pos == b->last) {
            in = in->next;
        }
    }

    /* write to temp file */
    for (; in; in = in->next) {
        b = in->buf;

        if (b->pos == b->last) {
            continue;
        }

        rc = ngx_write_fd(ctx->file.fd, b->pos, b->last - b->pos);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno, 
                          "play: error writing to temp file");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_open_remote(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_play_app_conf_t       *pacf;
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_rtmp_netcall_init_t         ci;
    u_char                         *p;
    ngx_err_t                       err;
    static u_char                   path[NGX_MAX_PATH];
    static ngx_uint_t               counter;

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    for ( ;; ) {
        p = ngx_snprintf(path, sizeof(path), "%V/nginx-rtmp-play%ui",
                         &pacf->temp_path, counter++);
        *p = 0;

        ctx->file.fd = ngx_open_tempfile(path, 0, 0);

        if (ctx->file.fd != NGX_INVALID_FILE) {
            break;
        }

        err = ngx_errno;

        if (err != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, err,
                          "play: failed to create temp file");

            return NGX_ERROR;
        }
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.url = pacf->url;;
    ci.create = ngx_rtmp_play_remote_create;
    ci.sink   = ngx_rtmp_play_remote_sink;
    ci.handle = ngx_rtmp_play_remote_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);
}


static char *
ngx_rtmp_play_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_play_app_conf_t       *pacf = conf;

    ngx_str_t                       url;
    ngx_url_t                      *u;
    size_t                          add;
    ngx_str_t                      *value;

    value = cf->args->elts;

    if (ngx_strncasecmp(value[1].data, (u_char *) "http://", 7)) {

        /* local file */

        pacf->root = value[1];
        return NGX_CONF_OK;
    }
    
    /* http case */

    url = value[1];

    add = sizeof("http://") - 1;

    url.data += add;
    url.len  -= add;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    u->url.len = url.len;
    u->url.data = url.data;
    u->default_port = 80;
    u->uri_part = 1;
    
    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in url \"%V\"", u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }

    pacf->url = u;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_play_postconfiguration(ngx_conf_t *cf)
{
    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_play_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_play_close_stream;

    next_seek = ngx_rtmp_seek;
    ngx_rtmp_seek = ngx_rtmp_play_seek;

    next_pause = ngx_rtmp_pause;
    ngx_rtmp_pause = ngx_rtmp_play_pause;

    return NGX_OK;
}
