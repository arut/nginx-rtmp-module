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


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_delete_stream_pt    next_delete_stream;


static char *ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char * ngx_rtmp_notify_on_record_done(ngx_conf_t *cf, 
       ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);
static ngx_int_t ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s, 
       ngx_rtmp_record_node_ctx_t *rctx,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_av(ngx_rtmp_session_t *s,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_av(ngx_rtmp_session_t *s,
       ngx_rtmp_record_node_ctx_t *rctx, ngx_rtmp_header_t *h, ngx_chain_t *in);


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
      offsetof(ngx_rtmp_record_app_conf_t, def.flags),
      ngx_rtmp_record_mask },

    { ngx_string("record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.path),
      NULL },

    { ngx_string("record_suffix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.suffix),
      NULL },

    { ngx_string("record_unique"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.unique),
      NULL },

    { ngx_string("record_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.max_size),
      NULL },

    { ngx_string("record_max_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.max_frames),
      NULL },

    { ngx_string("record_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, def.interval),
      NULL },

    { ngx_string("on_record_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_record_done,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
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

    racf->def.max_size   = NGX_CONF_UNSET;
    racf->def.max_frames = NGX_CONF_UNSET;
    racf->def.interval   = NGX_CONF_UNSET;
    racf->def.unique     = NGX_CONF_UNSET;

    ngx_str_set(&racf->def.id, "default");

    if (ngx_array_init(&racf->nodes, cf->pool, 1, 
                       sizeof(ngx_rtmp_record_node_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t *prev = parent;
    ngx_rtmp_record_app_conf_t *conf = child;
    ngx_rtmp_record_node_t    **node;

    ngx_conf_merge_str_value(conf->def.path, prev->def.path, "");
    ngx_conf_merge_str_value(conf->def.suffix, prev->def.suffix, ".flv");
    ngx_conf_merge_size_value(conf->def.max_size, prev->def.max_size, 0);
    ngx_conf_merge_size_value(conf->def.max_frames, prev->def.max_frames, 0);
    ngx_conf_merge_value(conf->def.unique, prev->def.unique, 0);
    ngx_conf_merge_msec_value(conf->def.interval, prev->def.interval, 
                              (ngx_msec_t) NGX_CONF_UNSET);
    ngx_conf_merge_bitmask_value(conf->def.flags, prev->def.flags, 0);

    if (conf->def.flags) {
        node = ngx_array_push(&conf->nodes);
        if (node == NULL) {
            return NGX_CONF_ERROR;
        }

        *node = &conf->def;
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


/* This funcion returns pointer to a static buffer */
u_char *
ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_node_ctx_t *rctx)
{
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p, *l;
    ngx_rtmp_record_node_t         *rc;

    static u_char                   buf[NGX_TIME_T_LEN + 1];
    static u_char                   path[NGX_MAX_PATH + 1];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    rc = rctx->conf;

    /* create file path */
    p = path;
    l = path + sizeof(path) - 1;

    p = ngx_cpymem(p, rc->path.data, 
                ngx_min(rc->path.len, (size_t)(l - p - 1)));
    *p++ = '/';
    p = (u_char *)ngx_escape_uri(p, ctx->name, ngx_min(ngx_strlen(ctx->name),
                (size_t)(l - p)), NGX_ESCAPE_URI_COMPONENT);

    /* append timestamp */
    if (rc->unique) {
        p = ngx_cpymem(p, buf, ngx_min(ngx_sprintf(buf, "-%T", 
                       rctx->timestamp) - buf, l - p));
    }

    p = ngx_cpymem(p, rc->suffix.data, 
                   ngx_min(rc->suffix.len, (size_t)(l - p)));
    *p = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V path: '%s'", &rc->id, path);

    return path;
}


ngx_int_t
ngx_rtmp_record_open(ngx_rtmp_session_t *s, ngx_rtmp_record_node_ctx_t *rctx)
{
    ngx_rtmp_record_node_t     *rc;
    ngx_err_t                   err;
    u_char                     *path;

    rc = rctx->conf;

    if (rctx->file.fd != NGX_INVALID_FILE) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V opening", &rc->id);

    rctx->timestamp = ngx_cached_time->sec;

    path = ngx_rtmp_record_make_path(s, rctx);

    rctx->nframes = 0;

    ngx_memzero(&rctx->file, sizeof(rctx->file));

    rctx->last = *ngx_cached_time;
    rctx->file.offset = 0;
    rctx->file.log = s->connection->log;
    rctx->file.fd = ngx_open_file(path, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                  NGX_FILE_DEFAULT_ACCESS);

    if (rctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                          "record: %V failed to open file '%s'",
                          &rc->id, path);
        }

        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V opened '%s'", &rc->id, path);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p;
    ngx_uint_t                      n;
    ngx_rtmp_record_node_t        **node;
    ngx_rtmp_record_node_ctx_t     *rctx;

    if (s->auto_pushed) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->nodes.nelts == 0) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: publish %ui nodes",
                   racf->nodes.nelts);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_record_ctx_t));

        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);

        if (ngx_array_init(&ctx->nodes, s->connection->pool, racf->nodes.nelts,
                           sizeof(ngx_rtmp_record_node_ctx_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        node = racf->nodes.elts;

        rctx = ngx_array_push_n(&ctx->nodes, racf->nodes.nelts);

        if (rctx == NULL) {
            return NGX_ERROR;
        }

        for (n = 0; n < racf->nodes.nelts; ++n, ++node, ++rctx) {
            ngx_memzero(rctx, sizeof(*rctx));

            rctx->conf = *node;
            rctx->file.fd = NGX_INVALID_FILE;
        }
    }

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

    rctx = ctx->nodes.elts;

    for (n = 0; n < ctx->nodes.nelts; ++n, ++rctx) {
        if (rctx->conf->flags & (NGX_RTMP_RECORD_OFF|NGX_RTMP_RECORD_MANUAL)) {
            continue;
        }

        ngx_rtmp_record_open(s, rctx);
    }

next:
    return next_publish(s, v);
}


static ngx_chain_t *
ngx_rtmp_record_notify_create(ngx_rtmp_session_t *s, void *arg, 
                              ngx_pool_t *pool)
{
    ngx_rtmp_record_node_ctx_t     *rctx = arg;

    ngx_rtmp_record_ctx_t          *ctx;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    size_t                          path_len, name_len, args_len;
    u_char                         *path;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

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

    path = ngx_rtmp_record_make_path(s, rctx);

    path_len  = ngx_strlen(path);
    name_len  = ngx_strlen(ctx->name);
    args_len  = ngx_strlen(ctx->args);
    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=record_done") +
                            sizeof("&addr=") + addr_text->len +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&path=") + path_len * 3 +
                            + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=record_done", 
                         sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&addr=", sizeof("&addr=") -1);
    b->last = (u_char*)ngx_escape_uri(b->last, addr_text->data, 
                                      addr_text->len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&name=", sizeof("&name=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, ctx->name, name_len, 0);

    b->last = ngx_cpymem(b->last, (u_char*)"&path=", sizeof("&path=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, path, path_len, 0);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *)ngx_cpymem(b->last, ctx->args, args_len);
    }

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(rctx->conf->url, pool,
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
ngx_rtmp_record_notify(ngx_rtmp_session_t *s, ngx_rtmp_record_node_ctx_t *rctx)
{
    ngx_rtmp_netcall_init_t     ci;
    ngx_rtmp_record_node_t     *rc;

    rc = rctx->conf;

    if (rc->url == NULL) {
        return NGX_OK;
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.url    = rc->url;
    ci.create = ngx_rtmp_record_notify_create;
    ci.arg    = rctx;

    return ngx_rtmp_netcall_create(s, &ci);
}


ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s, ngx_rtmp_record_node_ctx_t *rctx)
{
    ngx_rtmp_record_node_t     *rc;
    ngx_err_t                   err;

    rc = rctx->conf;

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (ngx_close_file(rctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                      "record: %V error closing file", &rc->id);
    }

    rctx->file.fd = NGX_INVALID_FILE;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: %V closed", &rc->id);

    return ngx_rtmp_record_notify(s, rctx);
}


static ngx_int_t
ngx_rtmp_record_delete_stream(ngx_rtmp_session_t *s, 
                              ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_record_ctx_t      *ctx;
    ngx_rtmp_record_node_ctx_t *rctx;
    ngx_uint_t                  n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "record: delete_stream %ui nodes",
                   ctx->nodes.nelts);

    rctx = ctx->nodes.elts;

    for (n = 0; n < ctx->nodes.nelts; ++n, ++rctx) {
        ngx_rtmp_record_close(s, rctx);
    }

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s, 
                            ngx_rtmp_record_node_ctx_t *rctx,
                            ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    u_char                      hdr[11], *p, *ph;
    uint32_t                    timestamp, tag_size;
    ngx_rtmp_record_node_t     *rc;

    rc = rctx->conf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V frame: mlen=%uD", &rc->id, h->mlen);

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
    if ((rc->max_size && rctx->file.offset >= (ngx_int_t) rc->max_size) ||
        (rc->max_frames && rctx->nframes >= rc->max_frames))
    {
        ngx_rtmp_record_close(s, rctx);
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
    ngx_rtmp_record_node_ctx_t     *rctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    rctx = ctx->nodes.elts;

    for (n = 0; n < ctx->nodes.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_av(s, rctx, h, in);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_node_av(ngx_rtmp_session_t *s, ngx_rtmp_record_node_ctx_t *rctx,
                        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_time_t                      next;
    ngx_rtmp_header_t               ch;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_int_t                       keyframe;
    ngx_rtmp_record_node_t         *rc;

    rc = rctx->conf;

    if (rc->flags & NGX_RTMP_RECORD_OFF) {
        ngx_rtmp_record_close(s, rctx);
        return NGX_OK;
    }

    keyframe = (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME);

    if (keyframe && (rc->flags & NGX_RTMP_RECORD_MANUAL) == 0) {

        if (rc->interval != (ngx_msec_t) NGX_CONF_UNSET) {

            next = rctx->last;
            next.msec += rc->interval;
            next.sec  += (next.msec / 1000);
            next.msec %= 1000;

            if (ngx_cached_time->sec  > next.sec ||
               (ngx_cached_time->sec == next.sec &&
                ngx_cached_time->msec > next.msec))
            {
                ngx_rtmp_record_close(s, rctx);
                ngx_rtmp_record_open(s, rctx);
            }

        } else {
            ngx_rtmp_record_open(s, rctx);
        }
    }

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_AUDIO &&
       (rc->flags & NGX_RTMP_RECORD_AUDIO) == 0)
    {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO &&
       (rc->flags & NGX_RTMP_RECORD_VIDEO) == 0 &&
       ((rc->flags & NGX_RTMP_RECORD_KEYFRAMES) == 0 || !keyframe))
    {
        return NGX_OK;
    }

    if (rctx->file.offset == 0) {
        rctx->epoch = h->timestamp;

        if (ngx_rtmp_record_write_header(&rctx->file) != NGX_OK) {
            ngx_rtmp_record_close(s, rctx);
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
            if (codec_ctx->aac_header && (rc->flags & NGX_RTMP_RECORD_AUDIO)) 
            {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                               "record: %V writing AAC header", &rc->id);

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
                (rc->flags & (NGX_RTMP_RECORD_VIDEO|NGX_RTMP_RECORD_KEYFRAMES)))
            {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                               "record: %V writing AVC header", &rc->id);

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


static char *
ngx_rtmp_notify_on_record_done(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_str_t                      *url;
    ngx_url_t                      *u;
    size_t                          add;
    ngx_str_t                      *value;

    value = cf->args->elts;
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

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_record_module);

    racf->def.url = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv, *rvm;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_record_app_conf_t *racf, *rracf;
    ngx_rtmp_record_node_t    **prc, *rc;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;

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

    prc = ngx_array_push(&racf->nodes);
    if (prc == NULL) {
        return NGX_CONF_ERROR;
    }

    rracf = ctx->app_conf[ngx_rtmp_record_module.ctx_index];

    rc = &rracf->def;

    value = cf->args->elts;
    rc->id = value[1];

    *prc = rc;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_REC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    rvm = ngx_rtmp_record_merge_app_conf(cf, racf, rracf);
    if (rvm != NGX_CONF_OK) {
        return rvm;
    }

    *cf= save;

    return rv;
}


static ngx_int_t
ngx_rtmp_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

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
