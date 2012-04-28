/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_delete_stream_pt    next_delete_stream;

static ngx_int_t ngx_rtmp_record_open(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_record_close(ngx_rtmp_session_t *s);


static char * ngx_rtmp_notify_on_record_done(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


typedef struct {
    ngx_uint_t                          flags;
    ngx_str_t                           path;
    size_t                              max_size;
    size_t                              max_frames;
    ngx_msec_t                          interval;
    ngx_str_t                           suffix;
    ngx_url_t                          *url;
} ngx_rtmp_record_app_conf_t;


typedef struct {
    ngx_file_t                          file;
    u_char                              path[NGX_MAX_PATH + 1];
    ngx_uint_t                          nframes;
    uint32_t                            epoch;
    ngx_time_t                          last;
} ngx_rtmp_record_ctx_t;


#define NGX_RTMP_RECORD_OFF             0x01
#define NGX_RTMP_RECORD_AUDIO           0x02
#define NGX_RTMP_RECORD_VIDEO           0x04
#define NGX_RTMP_RECORD_KEYFRAMES       0x08


static ngx_conf_bitmask_t  ngx_rtmp_record_mask[] = {
    { ngx_string("off"),                NGX_RTMP_RECORD_OFF         },
    { ngx_string("all"),                NGX_RTMP_RECORD_AUDIO       |
                                        NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("audio"),              NGX_RTMP_RECORD_AUDIO       },
    { ngx_string("video"),              NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("keyframes"),          NGX_RTMP_RECORD_KEYFRAMES   },
    { ngx_null_string,                  0                           }
};


static ngx_command_t  ngx_rtmp_record_commands[] = {

    { ngx_string("record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, flags),
      ngx_rtmp_record_mask },

    { ngx_string("record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, path),
      NULL },

    { ngx_string("record_suffix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, suffix),
      NULL },

    { ngx_string("record_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_size),
      NULL },

    { ngx_string("record_max_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_frames),
      NULL },

    { ngx_string("record_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, interval),
      NULL },

    { ngx_string("on_record_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_record_done,
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

    racf->max_size = NGX_CONF_UNSET;
    racf->max_frames = NGX_CONF_UNSET;
    racf->interval = NGX_CONF_UNSET;

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t *prev = parent;
    ngx_rtmp_record_app_conf_t *conf = child;

    ngx_conf_merge_bitmask_value(conf->flags, prev->flags, 
            (NGX_CONF_BITMASK_SET|NGX_RTMP_RECORD_OFF));
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_str_value(conf->suffix, prev->suffix, ".flv");
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 0);
    ngx_conf_merge_size_value(conf->max_frames, prev->max_frames, 0);
    ngx_conf_merge_msec_value(conf->interval, prev->interval, 0);

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


static ngx_int_t
ngx_rtmp_record_open(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_err_t                       err;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL || ctx->file.fd != NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    /* open file */
    ctx->nframes = 0;
    ngx_memzero(&ctx->file, sizeof(ctx->file));
    ctx->file.offset = 0;
    ctx->file.log = s->connection->log;
    ctx->file.fd = ngx_open_file(ctx->path, NGX_FILE_WRONLY, 
            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                    "record: failed to open file" " \"%s\" failed", 
                    ctx->path);
        }
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "record: opened '%s'", ctx->path);

    if (ngx_rtmp_record_write_header(&ctx->file) != NGX_OK) {
        ngx_rtmp_record_close(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p, *l;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->flags & NGX_RTMP_RECORD_OFF) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, 
                sizeof(ngx_rtmp_record_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->file.fd = NGX_INVALID_FILE;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);
    }

    /* create file path */
    p = ctx->path;
    l = ctx->path + sizeof(ctx->path) - 1;
    p = ngx_cpymem(p, racf->path.data, 
                ngx_min(racf->path.len, (size_t)(l - p - 1)));
    *p++ = '/';
    p = (u_char *)ngx_escape_uri(p, v->name, ngx_min(ngx_strlen(v->name), 
                (size_t)(l - p)), NGX_ESCAPE_URI_COMPONENT);
    p = ngx_cpymem(p, racf->suffix.data, 
            ngx_min(racf->suffix.len, (size_t)(l - p)));
    *p = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "record: path '%s'", ctx->path);

    if (ngx_rtmp_record_open(s) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_publish(s, v);
}


static ngx_chain_t *
ngx_rtmp_record_notify_create(ngx_rtmp_session_t *s, void *arg, 
        ngx_pool_t *pool)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;
    size_t                          len;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return NULL;
    }

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

    len = ngx_strlen(ctx->path);

    b = ngx_create_temp_buf(pool,
            sizeof("&call=record_done") +
            sizeof("&path=") + len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=record_done", 
            sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&path=", sizeof("&path=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, ctx->path, len, 0);

    /* HTTP header */
    hl = ngx_rtmp_netcall_http_format_header(racf->url, pool,
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
ngx_rtmp_record_notify(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_netcall_init_t         ci;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL || racf->url == NULL) {
        return NGX_OK;
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.url = racf->url;
    ci.create = ngx_rtmp_record_notify_create;

    return ngx_rtmp_netcall_create(s, &ci);
}


static ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_err_t                       err;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL || ctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                "record: error closing file");
    }
    ctx->file.fd = NGX_INVALID_FILE;
    ctx->last = *ngx_cached_time;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "record: closed");

    return ngx_rtmp_record_notify(s);
}


static ngx_int_t
ngx_rtmp_record_delete_stream(ngx_rtmp_session_t *s, 
        ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_record_close(s);

    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_record_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_connection_t               *c;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_app_conf_t     *racf;
    u_char                          hdr[11], *p, *ph;
    uint32_t                        timestamp, tag_size;
    ngx_time_t                      next;

    c = s->connection;
    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (racf == NULL || ctx == NULL || racf->flags & NGX_RTMP_RECORD_OFF) {
        return NGX_OK;
    }

    if (ctx->file.fd == NGX_INVALID_FILE && racf->interval 
            && (ctx->last.sec || ctx->last.msec)) 
    {
        next = ctx->last;
        next.msec += racf->interval;
        next.sec += (next.msec / 1000);
        next.msec %= 1000;
        if (ngx_cached_time->sec > next.sec
                || (ngx_cached_time->sec == next.sec
                    && ngx_cached_time->msec > next.msec))
        {
            if (ngx_rtmp_record_open(s) != NGX_OK) {
                ngx_log_error(NGX_LOG_CRIT, s->connection->log, 0,
                        "record: '%s' failed", ctx->path);
            }
        }
    }

    if (ctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    /* filter frames */
    if (h->type == NGX_RTMP_MSG_AUDIO &&
       (racf->flags & NGX_RTMP_RECORD_AUDIO) == 0)
    {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO &&
       (racf->flags & NGX_RTMP_RECORD_VIDEO) == 0 &&
       ((racf->flags & NGX_RTMP_RECORD_KEYFRAMES) == 0
            || ngx_rtmp_get_video_frame_type(in) != NGX_RTMP_VIDEO_KEY_FRAME))
    {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "record: av: mlen=%uD", h->mlen);

    if (ctx->file.offset == 0) {
        ctx->epoch = h->timestamp;
    }

    timestamp = h->timestamp - ctx->epoch;

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

    if (ngx_write_file(&ctx->file, hdr, ph - hdr, 
                ctx->file.offset) == NGX_ERROR) 
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
        if (ngx_write_file(&ctx->file, in->buf->pos, in->buf->last 
                    - in->buf->pos, ctx->file.offset) == NGX_ERROR) 
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

    if (ngx_write_file(&ctx->file, hdr, ph - hdr, 
                ctx->file.offset) == NGX_ERROR) 
    {
        return NGX_ERROR;
    }

    ++ctx->nframes;

    /* watch max size */
    if ((racf->max_size && ctx->file.offset >= (ngx_int_t)racf->max_size)
        || (racf->max_frames && ctx->nframes >= racf->max_frames))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                "record: closed");
        ngx_rtmp_record_close(s);
    }

    return NGX_OK;
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

    racf->url = u;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register event handlers */
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_record_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_record_av;

    /* chain handlers */
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_record_publish;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_record_delete_stream;

    return NGX_OK;
}
