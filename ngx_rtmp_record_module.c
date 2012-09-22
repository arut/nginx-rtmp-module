/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_record_module.h"


ngx_rtmp_record_done_pt             ngx_rtmp_record_done;


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_delete_stream_pt    next_delete_stream;


static char *ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);
static ngx_int_t ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s, 
       ngx_rtmp_record_rec_ctx_t *rctx,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_av(ngx_rtmp_session_t *s,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_av(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_open(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx);
static ngx_int_t ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx);
static void  ngx_rtmp_record_make_path(ngx_rtmp_session_t *s, 
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_str_t *path);
static ngx_int_t ngx_rtmp_record_init(ngx_rtmp_session_t *s);


static ngx_conf_bitmask_t  ngx_rtmp_record_mask[] = {
    { ngx_string("off"),                NGX_RTMP_RECORD_OFF         },
    { ngx_string("all"),                NGX_RTMP_RECORD_AUDIO       |
                                        NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("audio"),              NGX_RTMP_RECORD_AUDIO       },
    { ngx_string("video"),              NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("keyframes"),          NGX_RTMP_RECORD_KEYFRAMES   },
    { ngx_string("manual"),             NGX_RTMP_RECORD_MANUAL      },
    { ngx_null_string,                  0                           }
};


static ngx_command_t  ngx_rtmp_record_commands[] = {

    { ngx_string("record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, flags),
      ngx_rtmp_record_mask },

    { ngx_string("record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, path),
      NULL },
      
    { ngx_string("record_suffix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, suffix),
      NULL },

    { ngx_string("record_unique"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, unique),
      NULL },

    { ngx_string("record_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_size),
      NULL },

    { ngx_string("record_max_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_frames),
      NULL },

    { ngx_string("record_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, interval),
      NULL },

    { ngx_string("recorder"),
      NGX_RTMP_APP_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_record_recorder,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },


      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_record_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_record_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_record_create_app_conf,        /* create app configuration */
    ngx_rtmp_record_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_record_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_record_module_ctx,            /* module context */
    ngx_rtmp_record_commands,               /* module directives */
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
ngx_rtmp_record_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_record_app_conf_t      *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_record_app_conf_t));

    if (racf == NULL) {
        return NULL;
    }

    racf->max_size   = NGX_CONF_UNSET;
    racf->max_frames = NGX_CONF_UNSET;
    racf->interval   = NGX_CONF_UNSET;
    racf->unique     = NGX_CONF_UNSET;
    racf->url        = NGX_CONF_UNSET_PTR;

    ngx_str_set(&racf->id, "default");

    if (ngx_array_init(&racf->rec, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t     *prev = parent;
    ngx_rtmp_record_app_conf_t     *conf = child;
    ngx_rtmp_record_app_conf_t    **rracf;

    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_str_value(conf->suffix, prev->suffix, ".flv");
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 0);
    ngx_conf_merge_size_value(conf->max_frames, prev->max_frames, 0);
    ngx_conf_merge_value(conf->unique, prev->unique, 0);
    ngx_conf_merge_msec_value(conf->interval, prev->interval, 
                              (ngx_msec_t) NGX_CONF_UNSET);
    ngx_conf_merge_bitmask_value(conf->flags, prev->flags, 0);
    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);

    if (conf->flags) {
        rracf = ngx_array_push(&conf->rec);
        if (rracf == NULL) {
            return NGX_CONF_ERROR;
        }

        *rracf = conf;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_record_write_header(ngx_file_t *file)
{
    static u_char       flv_header[] = {
        0x46, /* 'F' */
        0x4c, /* 'L' */
        0x56, /* 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00, 
        0x00, 
        0x00, 
        0x09, /* header size */
        0x00,
        0x00,
        0x00,
        0x00  /* PreviousTagSize0 (not actually a header) */
    };

    return ngx_write_file(file, flv_header, sizeof(flv_header), 0) == NGX_ERROR
           ? NGX_ERROR
           : NGX_OK;
}


static ngx_rtmp_record_rec_ctx_t *
ngx_rtmp_record_get_node_ctx(ngx_rtmp_session_t *s, ngx_uint_t n)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;

    if (ngx_rtmp_record_init(s) != NGX_OK) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (n >= ctx->rec.nelts) {
        return NULL;
    }

    rctx = ctx->rec.elts;

    return &rctx[n];
}


ngx_int_t
ngx_rtmp_record_open(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: #%ui manual open", n);

    rctx = ngx_rtmp_record_get_node_ctx(s, n);

    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_record_node_open(s, rctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (path) {
        ngx_rtmp_record_make_path(s, rctx, path);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: #%ui manual close", n);

    rctx = ngx_rtmp_record_get_node_ctx(s, n);

    if (rctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_record_node_close(s, rctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (path) {
        ngx_rtmp_record_make_path(s, rctx, path);
    }

    return NGX_OK;
}


/* This funcion returns pointer to a static buffer */
static void
ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_rec_ctx_t *rctx, ngx_str_t *path)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_app_conf_t     *rracf;
    u_char                         *p, *l;

    static u_char                   buf[NGX_TIME_T_LEN + 1];
    static u_char                   pbuf[NGX_MAX_PATH + 1];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    rracf = rctx->conf;

    /* create file path */
    p = pbuf;
    l = pbuf + sizeof(pbuf) - 1;

    p = ngx_cpymem(p, rracf->path.data, 
                ngx_min(rracf->path.len, (size_t)(l - p - 1)));
    *p++ = '/';
    p = (u_char *)ngx_escape_uri(p, ctx->name, ngx_min(ngx_strlen(ctx->name),
                (size_t)(l - p)), NGX_ESCAPE_URI_COMPONENT);

    /* append timestamp */
    if (rracf->unique) {
        p = ngx_cpymem(p, buf, ngx_min(ngx_sprintf(buf, "-%T", 
                       rctx->timestamp) - buf, l - p));
    }

    p = ngx_cpymem(p, rracf->suffix.data, 
                   ngx_min(rracf->suffix.len, (size_t)(l - p)));
    *p = 0;

    path->data = pbuf;
    path->len  = p - pbuf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V path: '%V'", &rracf->id, path);
}


static ngx_int_t
ngx_rtmp_record_node_open(ngx_rtmp_session_t *s, 
                          ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t *rracf;
    ngx_err_t                   err;
    ngx_str_t                   path;

    rracf = rctx->conf;

    if (rctx->file.fd != NGX_INVALID_FILE) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V opening", &rracf->id);

    rctx->timestamp = ngx_cached_time->sec;

    ngx_rtmp_record_make_path(s, rctx, &path);

    rctx->nframes = 0;

    ngx_memzero(&rctx->file, sizeof(rctx->file));

    rctx->last = *ngx_cached_time;
    rctx->file.offset = 0;
    rctx->file.log = s->connection->log;
    rctx->file.fd = ngx_open_file(path.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                  NGX_FILE_DEFAULT_ACCESS);

    if (rctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                          "record: %V failed to open file '%V'",
                          &rracf->id, &path);
        }

        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V opened '%V'", &rracf->id, &path);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf, **rracf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx) {
        return NGX_OK;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->rec.nelts == 0) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_record_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);

    if (ngx_array_init(&ctx->rec, s->connection->pool, racf->rec.nelts,
                       sizeof(ngx_rtmp_record_rec_ctx_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rracf = racf->rec.elts;

    rctx = ngx_array_push_n(&ctx->rec, racf->rec.nelts);

    if (rctx == NULL) {
        return NGX_ERROR;
    }

    for (n = 0; n < racf->rec.nelts; ++n, ++rracf, ++rctx) {
        ngx_memzero(rctx, sizeof(*rctx));

        rctx->conf = *rracf;
        rctx->file.fd = NGX_INVALID_FILE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p;
    ngx_uint_t                      n;
    ngx_rtmp_record_rec_ctx_t     *rctx;

    if (s->auto_pushed) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->rec.nelts == 0) {
        goto next;
    }

    if (ngx_rtmp_record_init(s) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: publish %ui nodes",
                   racf->rec.nelts);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    ngx_memcpy(ctx->name, v->name, sizeof(ctx->name));
    ngx_memcpy(ctx->args, v->args, sizeof(ctx->args));

    /* terminate name on /../ */
    for (p = ctx->name; *p; ++p) {
        if (ngx_path_separator(p[0]) &&
            p[1] == '.' && p[2] == '.' && 
            ngx_path_separator(p[3])) 
        {
            *p = 0;
            break;
        }
    }

    rctx = ctx->rec.elts;

    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        if (rctx->conf->flags & (NGX_RTMP_RECORD_OFF|NGX_RTMP_RECORD_MANUAL)) {
            continue;
        }

        ngx_rtmp_record_node_open(s, rctx);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
                           ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t *rracf;
    ngx_err_t                   err;
    void                      **app_conf;
    ngx_int_t                   rc;
    ngx_rtmp_record_done_t      v;

    rracf = rctx->conf;

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (ngx_close_file(rctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                      "record: %V error closing file", &rracf->id);
    }

    rctx->file.fd = NGX_INVALID_FILE;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V closed", &rracf->id);

    app_conf = s->app_conf;

    if (rracf->rec_conf) {
        s->app_conf = rracf->rec_conf;
    }

    v.recorder = rracf->id;
    ngx_rtmp_record_make_path(s, rctx, &v.path);

    rc = ngx_rtmp_record_done(s, &v);

    s->app_conf = app_conf;

    return rc;
}


static ngx_int_t
ngx_rtmp_record_delete_stream(ngx_rtmp_session_t *s, 
                              ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_record_ctx_t      *ctx;
    ngx_rtmp_record_rec_ctx_t *rctx;
    ngx_uint_t                  n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: delete_stream %ui nodes",
                   ctx->rec.nelts);

    rctx = ctx->rec.elts;

    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_close(s, rctx);
    }

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s, 
                            ngx_rtmp_record_rec_ctx_t *rctx,
                            ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    u_char                      hdr[11], *p, *ph;
    uint32_t                    timestamp, tag_size;
    ngx_rtmp_record_app_conf_t *rracf;

    rracf = rctx->conf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V frame: mlen=%uD",
                   &rracf->id, h->mlen);

    timestamp = h->timestamp - rctx->epoch;

    /* write tag header */
    ph = hdr;

    *ph++ = (u_char)h->type;

    p = (u_char*)&h->mlen;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    tag_size = (ph - hdr) + h->mlen;

    if (ngx_write_file(&rctx->file, hdr, ph - hdr, rctx->file.offset)
        == NGX_ERROR) 
    {
        return NGX_ERROR;
    }

    /* write tag body
     * FIXME: NGINX
     * ngx_write_chain seems to fit best
     * but it suffers from uncontrollable
     * allocations.
     * we're left with plain writing */
    for(; in; in = in->next) {
        if (in->buf->pos == in->buf->last) {
            continue;
        }

        if (ngx_write_file(&rctx->file, in->buf->pos, in->buf->last 
                           - in->buf->pos, rctx->file.offset)
            == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    /* write tag size */
    ph = hdr;
    p = (u_char*)&tag_size;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    if (ngx_write_file(&rctx->file, hdr, ph - hdr, 
                       rctx->file.offset)
        == NGX_ERROR) 
    {
        return NGX_ERROR;
    }

    ++rctx->nframes;

    /* watch max size */
    if ((rracf->max_size && rctx->file.offset >= (ngx_int_t) rracf->max_size) ||
        (rracf->max_frames && rctx->nframes >= rracf->max_frames))
    {
        ngx_rtmp_record_node_close(s, rctx);
    }

    return NGX_OK;
}


static size_t
ngx_rtmp_record_get_chain_mlen(ngx_chain_t *in)
{
    size_t                          ret;

    for (ret = 0; in; in = in->next) {
        ret += (in->buf->last - in->buf->pos);
    }

    return ret;
}


static ngx_int_t
ngx_rtmp_record_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
                   ngx_chain_t *in)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    rctx = ctx->rec.elts;

    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_av(s, rctx, h, in);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_node_av(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t *rctx,
                        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_time_t                      next;
    ngx_rtmp_header_t               ch;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_int_t                       keyframe, brkframe;
    ngx_rtmp_record_app_conf_t     *rracf;

    rracf = rctx->conf;

    if (rracf->flags & NGX_RTMP_RECORD_OFF) {
        ngx_rtmp_record_node_close(s, rctx);
        return NGX_OK;
    }

    keyframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME)
             : 0;

    brkframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? keyframe
             : (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0;
    /* break frame only if video keyframe or if we are not recording video*/

    if (brkframe && (rracf->flags & NGX_RTMP_RECORD_MANUAL) == 0) {

        if (rracf->interval != (ngx_msec_t) NGX_CONF_UNSET) {

            next = rctx->last;
            next.msec += rracf->interval;
            next.sec  += (next.msec / 1000);
            next.msec %= 1000;

            if (ngx_cached_time->sec  > next.sec ||
               (ngx_cached_time->sec == next.sec &&
                ngx_cached_time->msec > next.msec))
            {
                ngx_rtmp_record_node_close(s, rctx);
                ngx_rtmp_record_node_open(s, rctx);
            }

        } else {
            ngx_rtmp_record_node_open(s, rctx);
        }
    }

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_AUDIO &&
       (rracf->flags & NGX_RTMP_RECORD_AUDIO) == 0)
    {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO &&
       (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0 &&
       ((rracf->flags & NGX_RTMP_RECORD_KEYFRAMES) == 0 || !keyframe))
    {
        return NGX_OK;
    }

    if (rctx->file.offset == 0) {
        rctx->epoch = h->timestamp;

        if (ngx_rtmp_record_write_header(&rctx->file) != NGX_OK) {
            ngx_rtmp_record_node_close(s, rctx);
            return NGX_OK;
        }

        codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
        if (codec_ctx) {
            ch = *h;

#if 0
            /* metadata */
            if (codec_ctx->meta) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                        "record: writing metadata");
                ch.type = NGX_RTMP_MSG_AMF_META;
                ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->meta);
                if (ngx_rtmp_record_write_frame(s, &ch, codec_ctx->meta)
                        != NGX_OK) 
                {
                    return NGX_OK;
                }
            }
#endif
            /* AAC header */
            if (codec_ctx->aac_header && (rracf->flags & NGX_RTMP_RECORD_AUDIO))
            {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                               "record: %V writing AAC header", &rracf->id);

                ch.type = NGX_RTMP_MSG_AUDIO;
                ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->aac_header);

                if (ngx_rtmp_record_write_frame(s, rctx, &ch, codec_ctx->aac_header)
                    != NGX_OK) 
                {
                    return NGX_OK;
                }
            }

            /* AVC header */
            if (codec_ctx->avc_header && 
                (rracf->flags & (NGX_RTMP_RECORD_VIDEO|
                                 NGX_RTMP_RECORD_KEYFRAMES)))
            {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                               "record: %V writing AVC header", &rracf->id);

                ch.type = NGX_RTMP_MSG_VIDEO;
                ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->avc_header);

                if (ngx_rtmp_record_write_frame(s, rctx, &ch, codec_ctx->avc_header)
                    != NGX_OK) 
                {
                    return NGX_OK;
                }
            }
        }
    }

    return ngx_rtmp_record_write_frame(s, rctx, h, in);
}


static ngx_int_t
ngx_rtmp_record_done_init(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    return NGX_OK;
}


static char *
ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_core_app_conf_t   *cacf, **pcacf, *rcacf;
    ngx_rtmp_record_app_conf_t *racf, **pracf, *rracf;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;

    value = cf->args->elts;

    cacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_record_module);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;

    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf  = pctx->srv_conf;

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_app_conf) {
            ctx->app_conf[ngx_modules[i]->ctx_index] = 
                                module->create_app_conf(cf);
            if (ctx->app_conf[ngx_modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* add to sub-applications */
    rcacf = ctx->app_conf[ngx_rtmp_core_module.ctx_index];
    rcacf->app_conf = ctx->app_conf;
    pcacf = ngx_array_push(&cacf->applications);
    if (pcacf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pcacf = rcacf;

    /* add to recorders */
    rracf = ctx->app_conf[ngx_rtmp_record_module.ctx_index];
    rracf->rec_conf = ctx->app_conf;
    pracf = ngx_array_push(&racf->rec);
    if (pracf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pracf = rracf;

    rracf->id = value[1];


    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_REC_CONF;

    rv = ngx_conf_parse(cf, NULL);
    *cf= save;

    return rv;
}


static ngx_int_t
ngx_rtmp_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    ngx_rtmp_record_done = ngx_rtmp_record_done_init;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_record_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_record_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_record_publish;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_record_delete_stream;

    return NGX_OK;
}
