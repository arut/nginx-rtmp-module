/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"


static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_seek_pt                 next_seek;
static ngx_rtmp_pause_pt                next_pause;


static ngx_int_t ngx_rtmp_play_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_play_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_play_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);
static void ngx_rtmp_play_send(ngx_event_t *e);
static void ngx_rtmp_play_read_meta(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_start(ngx_rtmp_session_t *s, ngx_int_t offset);
static ngx_int_t ngx_rtmp_play_stop(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_play_timestamp_to_offset(ngx_rtmp_session_t *s, 
                 ngx_int_t timestamp);


typedef struct {
    ngx_str_t                           root;
} ngx_rtmp_play_app_conf_t;


typedef struct {
    ngx_uint_t                          nelts;
    ngx_uint_t                          offset;
} ngx_rtmp_play_index_t;


typedef struct {
    ngx_file_t                          file;
    ngx_int_t                           offset;
    ngx_int_t                           start_timestamp;
    ngx_event_t                         write_evt;
    uint32_t                            last_audio;
    uint32_t                            last_video;
    ngx_uint_t                          msg_mask;
    uint32_t                            epoch;

    unsigned                            meta_read:1;
    ngx_rtmp_play_index_t               filepositions;
    ngx_rtmp_play_index_t               times;
} ngx_rtmp_play_ctx_t;


#define NGX_RTMP_PLAY_BUFFER            (1024*1024)
#define NGX_RTMP_PLAY_DEFAULT_BUFLEN    1000
#define NGX_RTMP_PLAY_TAG_HEADER        11
#define NGX_RTMP_PLAY_DATA_OFFSET       13


static u_char                           ngx_rtmp_play_buffer[
                                        NGX_RTMP_PLAY_BUFFER];
static u_char                           ngx_rtmp_play_header[
                                        NGX_RTMP_PLAY_TAG_HEADER];


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
    NULL,                                   /* create main configuration */
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


static ngx_int_t
ngx_rtmp_play_fill_index(ngx_rtmp_amf_ctx_t *ctx, ngx_rtmp_play_index_t *idx)
{
    uint32_t                        nelts;
    ngx_buf_t                      *b;

    /* we have AMF array pointed by context;
     * need to extract its size (4 bytes) &
     * save offset of actual array data */
    b = ctx->link->buf;
    if (b->last - b->pos < (ngx_int_t) ctx->offset + 4) {
        return NGX_ERROR;
    }

    ngx_rtmp_rmemcpy(&nelts, b->pos + ctx->offset, 4);
    idx->nelts = nelts;
    idx->offset = ctx->offset + 4;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_init_index(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_play_ctx_t            *ctx;

    static ngx_rtmp_amf_ctx_t       filepositions_ctx;
    static ngx_rtmp_amf_ctx_t       times_ctx;

    static ngx_rtmp_amf_elt_t       in_keyframes[] = {

        { NGX_RTMP_AMF_ARRAY | NGX_RTMP_AMF_CONTEXT, 
          ngx_string("filepositions"),
          &filepositions_ctx, 0 },

        { NGX_RTMP_AMF_ARRAY | NGX_RTMP_AMF_CONTEXT, 
          ngx_string("times"),
          &times_ctx, 0 }
    };

    static ngx_rtmp_amf_elt_t       in_inf[] = {

        { NGX_RTMP_AMF_OBJECT, 
          ngx_string("keyframes"),
          in_keyframes, sizeof(in_keyframes) }
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT, 
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL || in == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: init index");

    ngx_memzero(&filepositions_ctx, sizeof(filepositions_ctx));
    ngx_memzero(&times_ctx, sizeof(times_ctx));

    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                             sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: init index error");
        return NGX_OK;
    }

    if (filepositions_ctx.link && ngx_rtmp_play_fill_index(&filepositions_ctx, 
                                                           &ctx->filepositions)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: failed to init filepositions");
        return NGX_ERROR;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: filepositions nelts=%ui offset=%ui",
                   ctx->filepositions.nelts, ctx->filepositions.offset);

    if (times_ctx.link && ngx_rtmp_play_fill_index(&times_ctx,
                                                   &ctx->times)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: failed to init times");
        return NGX_ERROR;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: times nelts=%ui offset=%ui",
                   ctx->times.nelts, ctx->times.offset);

    return  NGX_OK;
}


static double
ngx_rtmp_play_index_value(void *src)
{
    double      v;

    ngx_rtmp_rmemcpy(&v, src, 8);
    return v;
}


static ngx_int_t
ngx_rtmp_play_timestamp_to_offset(ngx_rtmp_session_t *s, ngx_int_t timestamp)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ssize_t                         n, size;
    ngx_uint_t                      offset, index, ret, nelts;
    double                          v;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        goto rewind;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: lookup index start timestamp=%i", 
                   timestamp);

    if (ctx->meta_read == 0) {
        ngx_rtmp_play_read_meta(s);
        ctx->meta_read = 1;
    }

    if (timestamp <= 0 || ctx->filepositions.nelts == 0
                       || ctx->times.nelts == 0) 
    {
        goto rewind;
    }

    /* read index table from file given offset */
    offset = NGX_RTMP_PLAY_DATA_OFFSET + NGX_RTMP_PLAY_TAG_HEADER
             + ctx->times.offset;

    /* index should fit in the buffer */
    nelts = ngx_min(ctx->times.nelts, sizeof(ngx_rtmp_play_buffer) / 9);
    size = nelts * 9;
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_buffer, size, offset);
    if (n != size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: could not read times index");
        goto rewind;
    }

    /*TODO: implement binary search */
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: lookup times nelts=%ui", nelts);

    for (index = 0; index < nelts - 1; ++index) {
        v = ngx_rtmp_play_index_value(ngx_rtmp_play_buffer 
                                      + index * 9 + 1) * 1000;

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "play: lookup times index=%ui value=%ui", 
                      index, (ngx_uint_t) v);

        if (timestamp < v) {
            break;
        }
    }

    if (index >= ctx->filepositions.nelts) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: index out of bounds: %ui>=%ui", 
                     index, ctx->filepositions.nelts);
        goto rewind;
    }

    /* take value from filepositions */
    offset = NGX_RTMP_PLAY_DATA_OFFSET + NGX_RTMP_PLAY_TAG_HEADER
           + ctx->filepositions.offset + index * 9;
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_buffer, 8, offset + 1);
    if (n != 8) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: could not read filepositions index");
        goto rewind;
    }
    ret = ngx_rtmp_play_index_value(ngx_rtmp_play_buffer);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: lookup index timestamp=%i offset=%ui", 
                   timestamp, ret);

    return ret;

rewind:
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: lookup index timestamp=%i offset=begin", 
                   timestamp);
    
    return NGX_RTMP_PLAY_DATA_OFFSET;
}


static void
ngx_rtmp_play_read_meta(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ssize_t                         n;
    ngx_rtmp_header_t               h;
    ngx_chain_t                    *out, in;
    ngx_buf_t                       in_buf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    uint32_t                        size;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: read meta");
    
    /* read tag header */
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_header, 
                      sizeof(ngx_rtmp_play_header), NGX_RTMP_PLAY_DATA_OFFSET);
    if (n != sizeof(ngx_rtmp_play_header)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: could not read metadata tag header");
        return;
    }

    if (ngx_rtmp_play_header[0] != NGX_RTMP_MSG_AMF_META) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "play: first tag is not metadata, giving up");
        return;
    }

    ngx_memzero(&h, sizeof(h));
    h.type = NGX_RTMP_MSG_AMF_META;
    h.msid = NGX_RTMP_LIVE_MSID;
    h.csid = NGX_RTMP_LIVE_CSID_META;
    size = 0;
    ngx_rtmp_rmemcpy(&size, ngx_rtmp_play_header + 1, 3);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: metadata size=%D", size);

    if (size > sizeof(ngx_rtmp_play_buffer)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: too big metadata");
        return;
    }

    /* read metadata */
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_buffer, 
                      size, sizeof(ngx_rtmp_play_header) + 
                      NGX_RTMP_PLAY_DATA_OFFSET);
    if (n != size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: could not read metadata");
        return;
    }

    /* prepare input chain */
    ngx_memzero(&in, sizeof(in));
    ngx_memzero(&in_buf, sizeof(in_buf));
    in.buf = &in_buf;
    in_buf.pos = ngx_rtmp_play_buffer;
    in_buf.last = ngx_rtmp_play_buffer + size;

    ngx_rtmp_play_init_index(s, &in);

    /* output chain */
    out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);
    ngx_rtmp_prepare_message(s, &h, NULL, out);
    ngx_rtmp_send_message(s, out, 0);
    ngx_rtmp_free_shared_chain(cscf, out);
}


static void
ngx_rtmp_play_send(ngx_event_t *e)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_play_ctx_t            *ctx;
    uint32_t                        last_timestamp;
    ngx_rtmp_header_t               h, lh;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_chain_t                    *out, in;
    ngx_buf_t                       in_buf;
    ssize_t                         n;
    uint32_t                        buflen, end_timestamp, size;

    s = e->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->offset == -1) {
        ctx->offset = ngx_rtmp_play_timestamp_to_offset(s,
                                                        ctx->start_timestamp);
        ctx->start_timestamp = -1; /* set later from actual timestamp */
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: read tag at offset=%i", ctx->offset);

    /* read tag header */
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_header, 
                      sizeof(ngx_rtmp_play_header), ctx->offset);
    if (n != sizeof(ngx_rtmp_play_header)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: could not read flv tag header");
        ngx_rtmp_send_user_stream_eof(s, 1);
        return;
    }

    /* parse header fields */
    ngx_memzero(&h, sizeof(h));
    h.msid = NGX_RTMP_LIVE_MSID;
    h.type = ngx_rtmp_play_header[0];
    size = 0;
    ngx_rtmp_rmemcpy(&size, ngx_rtmp_play_header + 1, 3);
    ngx_rtmp_rmemcpy(&h.timestamp, ngx_rtmp_play_header + 4, 3);
    ((u_char *) &h.timestamp)[3] = ngx_rtmp_play_header[7];

    ctx->offset += (sizeof(ngx_rtmp_play_header) + size + 4);

    last_timestamp = 0;

    switch (h.type) {
        case NGX_RTMP_MSG_AUDIO:
            h.csid = NGX_RTMP_LIVE_CSID_AUDIO;
            last_timestamp = ctx->last_audio;
            ctx->last_audio = h.timestamp;
            break;

        case NGX_RTMP_MSG_VIDEO:
            h.csid = NGX_RTMP_LIVE_CSID_VIDEO;
            last_timestamp = ctx->last_video;
            ctx->last_video = h.timestamp;
            break;

        default:
            goto skip;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: read tag type=%i size=%uD timestamp=%uD "
                  "last_timestamp=%uD", 
                  (ngx_int_t) h.type,size, h.timestamp, last_timestamp);

    lh = h;
    lh.timestamp = last_timestamp;

    if (size > sizeof(ngx_rtmp_play_buffer)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: too big message: %D>%uz", size, 
                      sizeof(ngx_rtmp_play_buffer));
        goto next;
    }

    /* read tag body */
    n = ngx_read_file(&ctx->file, ngx_rtmp_play_buffer, size, 
                      ctx->offset - size - 4);
    if (n != size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: could not read flv tag");
        return;
    }

    /* prepare input chain */
    ngx_memzero(&in, sizeof(in));
    ngx_memzero(&in_buf, sizeof(in_buf));
    in.buf = &in_buf;
    in_buf.pos = ngx_rtmp_play_buffer;
    in_buf.last = ngx_rtmp_play_buffer + size;

    /* output chain */
    out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);
    ngx_rtmp_prepare_message(s, &h, ctx->msg_mask & (1 << h.type) ? 
                             &lh : NULL, out);
    ngx_rtmp_send_message(s, out, 0); /* TODO: priority */
    ngx_rtmp_free_shared_chain(cscf, out);

    ctx->msg_mask |= (1 << h.type);

next:
    if (ctx->start_timestamp == -1) {
        ctx->start_timestamp = h.timestamp;
        ctx->epoch = ngx_current_msec;
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "play: start_timestamp=%i", ctx->start_timestamp);
        goto skip;
    }

    buflen = (s->buflen ? s->buflen : NGX_RTMP_PLAY_DEFAULT_BUFLEN);
    end_timestamp = (ngx_current_msec - ctx->epoch) +
                     ctx->start_timestamp + buflen;

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "play: %s wait=%D timestamp=%D end_timestamp=%D bufen=%i",
            h.timestamp > end_timestamp ? "schedule" : "advance",
            h.timestamp > end_timestamp ? h.timestamp - end_timestamp : 0,
            h.timestamp, end_timestamp, (ngx_int_t) buflen);

    /* too much data sent; schedule timeout */
    if (h.timestamp > end_timestamp) {
        ngx_add_timer(e, h.timestamp - end_timestamp);
        return;
    }

skip:
    ngx_post_event(e, &ngx_posted_events);
}


static ngx_int_t
ngx_rtmp_play_start(ngx_rtmp_session_t *s, ngx_int_t timestamp)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: start timestamp=%i", timestamp);

    ngx_rtmp_play_stop(s);

    ctx->start_timestamp = timestamp;
    ctx->offset = -1;
    ctx->msg_mask = 0;

    ngx_post_event((&ctx->write_evt), &ngx_posted_events)

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: stop");

    if (ctx->write_evt.timer_set) {
        ngx_del_timer(&ctx->write_evt);
    }

    if (ctx->write_evt.prev) {
        ngx_delete_posted_event((&ctx->write_evt));
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
                  "play: seek timestamp=%i", (ngx_int_t) v->offset);

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
                  "play: pause=%i timestamp=%i",
                   (ngx_int_t) v->pause, (ngx_int_t) v->position);

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
    ngx_rtmp_play_app_conf_t       *pacf;
    ngx_rtmp_play_ctx_t            *ctx;
    u_char                         *p;
    ngx_event_t                    *e;
    size_t                          len, slen;
    static u_char                   path[NGX_MAX_PATH];

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

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_play_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_play_module);
    }
    ngx_memzero(ctx, sizeof(*ctx));

    ctx->file.log = s->connection->log;

    /* make file path */
    /*TODO: escape*/
    len = ngx_strlen(v->name);
    slen = sizeof(".flv") - 1;
    p = ngx_snprintf(path, sizeof(path), "%V/%s%s", &pacf->root, v->name,
                     len > slen && ngx_strncasecmp((u_char *) ".flv", 
                     v->name + len - slen, slen) == 0 ? "" : ".flv");
    *p = 0;

    /* open file */
    ctx->file.fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 
                                 NGX_FILE_DEFAULT_ACCESS);
    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "play: error opening file %s", path);
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "play: opened file '%s'", path);

    e = &ctx->write_evt;
    e->data = s;
    e->handler = ngx_rtmp_play_send;
    e->log = s->connection->log;

    ngx_rtmp_send_user_recorded(s, 1);

    ngx_rtmp_play_start(s, v->start);

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
