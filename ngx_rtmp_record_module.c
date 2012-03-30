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


static char * ngx_rtmp_notify_on_record_done(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


typedef struct {
    ngx_str_t                           root;
    size_t                              max_size;
    ngx_url_t                          *url;
} ngx_rtmp_record_app_conf_t;


static ngx_command_t  ngx_rtmp_record_commands[] = {

    { ngx_string("record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, root),
      NULL },

    { ngx_string("record_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_size),
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


typedef struct {
    ngx_file_t                              file;
    ngx_str_t                               path;
    ngx_int_t                               counter;
    ngx_time_t                              last;
    uint32_t                                epoch;
} ngx_rtmp_record_ctx_t;


static void *
ngx_rtmp_record_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_record_app_conf_t      *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_record_app_conf_t));
    if (racf == NULL) {
        return NULL;
    }

    racf->max_size = NGX_CONF_UNSET;

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t *prev = parent;
    ngx_rtmp_record_app_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->root, prev->root, "");
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 
            (size_t)NGX_CONF_UNSET);

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
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_time_t                     *tod;
    ngx_err_t                       err;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->root.len == 0) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, 
                sizeof(ngx_rtmp_record_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);
    }

    if (ctx->path.len) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, NGX_ERROR,
                "record: already recording");
        return NGX_ERROR;
    }

    /* create file name */
    tod = ngx_timeofday();
    ctx->path.data = ngx_pcalloc(s->connection->pool, NGX_MAX_PATH + 1);
    if (ctx->path.data == NULL) {
        return NGX_ERROR;
    }

    if (tod->sec == ctx->last.sec
            && tod->msec == ctx->last.msec) 
    {
        ++ctx->counter;
    } else {
        ctx->counter = 0;
    }

    ctx->last = *tod;

    /* TODO: can use 'name' here
     * but need to check for bad symbols first 
     * it comes right from user */
    ctx->path.len = ngx_snprintf(ctx->path.data, NGX_MAX_PATH,
        "%V/rec-%T.%M.%d.flv", &racf->root, tod->sec, tod->msec, 
        ctx->counter) - ctx->path.data;
    ctx->path.data[ctx->path.len] = 0;

    /* open file */
    ngx_memzero(&ctx->file, sizeof(ctx->file));
    ctx->file.log = s->connection->log;
    ctx->file.fd = ngx_open_file(ctx->path.data, NGX_FILE_WRONLY, 
            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                    "record: failed to open file" " \"%V\" failed", 
                    ctx->path);
        }
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "record: opened '%V'", &ctx->path);

    if (ngx_rtmp_record_write_header(&ctx->file) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_publish(s, v);
}


static ngx_chain_t *
ngx_rtmp_record_notify_create(ngx_rtmp_session_t *s, void *arg, 
        ngx_pool_t *pool)
{
    ngx_str_t                      *path = arg;

    ngx_rtmp_record_app_conf_t     *racf;
    ngx_chain_t                    *hl, *cl, *pl;
    ngx_buf_t                      *b;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (path == NULL) {
        return NGX_OK;
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

    b = ngx_create_temp_buf(pool,
            sizeof("&call=record_done") +
            sizeof("&path=") + path->len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;

    b->last = ngx_cpymem(b->last, (u_char*)"&call=record_done", 
            sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char*)"&path=", sizeof("&path=") - 1);
    b->last = (u_char*)ngx_escape_uri(b->last, path->data, path->len, 0);

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
ngx_rtmp_record_notify(ngx_rtmp_session_t *s, ngx_str_t *path)
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
    ci.arg = path;

    return ngx_rtmp_netcall_create(s, &ci);
}


static ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_err_t                       err;
    ngx_str_t                       path;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL || ctx->path.len == 0) {
        return NGX_OK;
    }

    path = ctx->path;
    ngx_str_null(&ctx->path);

    if (ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                "record: error closing file");
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "record: closed");

    return ngx_rtmp_record_notify(s, &path);
}


static ngx_int_t
ngx_rtmp_record_delete_stream(ngx_rtmp_session_t *s, 
        ngx_rtmp_delete_stream_t *v)
{
    if (ngx_rtmp_record_close(s) != NGX_OK) {
        return NGX_ERROR;
    }

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

    c = s->connection;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || ctx == NULL || ctx->path.len == 0) {
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

    /* watch max size */
    if (racf->max_size != (size_t)NGX_CONF_UNSET
            && ctx->file.offset >= (ngx_int_t)racf->max_size) 
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                "record: closed on size limit");
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
