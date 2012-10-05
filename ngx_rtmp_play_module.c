/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_streams.h"


static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_seek_pt                 next_seek;
static ngx_rtmp_pause_pt                next_pause;


static void *ngx_rtmp_play_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_play_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_play_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_play_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);
static ngx_int_t ngx_rtmp_play_init(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_done(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_start(ngx_rtmp_session_t *s, double timestamp);
static ngx_int_t ngx_rtmp_play_stop(ngx_rtmp_session_t *s);
static void ngx_rtmp_play_send(ngx_event_t *e);


static ngx_command_t  ngx_rtmp_play_commands[] = {

    { ngx_string("play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_play_app_conf_t, root),
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

    return NGX_CONF_OK;
}


static void
ngx_rtmp_play_send(ngx_event_t *e)
{
    ngx_rtmp_session_t     *s = e->data;
    ngx_rtmp_play_ctx_t    *ctx;
    ngx_int_t               rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL || ctx->fmt == NULL || ctx->fmt->send == NULL) {
        return;
    }

    rc = ctx->fmt->send(s, &ctx->file);

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

    ngx_rtmp_send_play_status(s, "NetStream.Play.Complete", "status", 0, 0);
    ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stopped");
}


static ngx_int_t
ngx_rtmp_play_init(ngx_rtmp_session_t *s)
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
ngx_rtmp_play_done(ngx_rtmp_session_t *s)
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
ngx_rtmp_play_start(ngx_rtmp_session_t *s, double timestamp)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_uint_t                      ts;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_play_stop(s);

    ts = (timestamp > 0 ? (ngx_uint_t) timestamp : 0);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: start timestamp=%ui", ts);

    if (ctx->fmt && ctx->fmt->start &&
        ctx->fmt->start(s, &ctx->file, ts) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_post_event((&ctx->send_evt), &ngx_posted_events);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_stop(ngx_rtmp_session_t *s)
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

    ngx_rtmp_play_stop(s);

    ngx_rtmp_play_done(s);

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

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: seek offset=%f", v->offset);

    ngx_rtmp_play_start(s, v->offset);

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
        ngx_rtmp_play_stop(s);
    } else {
        ngx_rtmp_play_start(s, v->position);
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
    ngx_event_t                    *e;
    ngx_rtmp_play_fmt_t            *fmt, **pfmt;
    ngx_str_t                      *pfx, *sfx;
    ngx_str_t                       name;
    ngx_uint_t                      n;
    static ngx_str_t                nosfx;
    static u_char                   path[NGX_MAX_PATH];

    pmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_play_module);

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);

    if (pacf == NULL || pacf->root.len == 0) {
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

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "play: %V", &ctx->fmt->name);

    sfx = &ctx->fmt->sfx;

    if (name.len >= sfx->len &&
        ngx_strncasecmp(sfx->data, name.data + name.len - sfx->len, 
                        sfx->len) 
        == 0)
    {
        sfx = &nosfx;
    }

    p = ngx_snprintf(path, sizeof(path), "%V/%V%V", &pacf->root, &name, sfx);
    *p = 0;

    ctx->file.fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 
                                 NGX_FILE_DEFAULT_ACCESS);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: error opening file '%s'", path);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: opened file '%s'", path);

    e = &ctx->send_evt;
    e->data = s;
    e->handler = ngx_rtmp_play_send;
    e->log = s->connection->log;

    ngx_rtmp_send_user_recorded(s, 1);

    if (ngx_rtmp_play_init(s) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_play_start(s, v->start) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_play(s, v);
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
