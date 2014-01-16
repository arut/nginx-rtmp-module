
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_streams.h"


static ngx_int_t ngx_rtmp_flv_postconfiguration(ngx_conf_t *cf);
static void ngx_rtmp_flv_read_meta(ngx_rtmp_session_t *s, ngx_file_t *f);
static ngx_int_t ngx_rtmp_flv_timestamp_to_offset(ngx_rtmp_session_t *s,
       ngx_file_t *f, ngx_int_t timestamp);
static ngx_int_t ngx_rtmp_flv_init(ngx_rtmp_session_t *s, ngx_file_t *f,
       ngx_int_t aindex, ngx_int_t vindex);
static ngx_int_t ngx_rtmp_flv_start(ngx_rtmp_session_t *s, ngx_file_t *f);
static ngx_int_t ngx_rtmp_flv_seek(ngx_rtmp_session_t *s, ngx_file_t *f,
       ngx_uint_t offset);
static ngx_int_t ngx_rtmp_flv_stop(ngx_rtmp_session_t *s, ngx_file_t *f);
static ngx_int_t ngx_rtmp_flv_send(ngx_rtmp_session_t *s, ngx_file_t *f,
                                   ngx_uint_t *ts);


typedef struct {
    ngx_uint_t                          nelts;
    ngx_uint_t                          offset;
} ngx_rtmp_flv_index_t;


typedef struct {
    ngx_int_t                           offset;
    ngx_int_t                           start_timestamp;
    ngx_event_t                         write_evt;
    uint32_t                            last_audio;
    uint32_t                            last_video;
    ngx_uint_t                          msg_mask;
    uint32_t                            epoch;

    unsigned                            meta_read:1;
    ngx_rtmp_flv_index_t                filepositions;
    ngx_rtmp_flv_index_t                times;
} ngx_rtmp_flv_ctx_t;


#define NGX_RTMP_FLV_BUFFER             (1024*1024)
#define NGX_RTMP_FLV_BUFLEN_ADDON       1000
#define NGX_RTMP_FLV_TAG_HEADER         11
#define NGX_RTMP_FLV_DATA_OFFSET        13


static u_char                           ngx_rtmp_flv_buffer[
                                        NGX_RTMP_FLV_BUFFER];
static u_char                           ngx_rtmp_flv_header[
                                        NGX_RTMP_FLV_TAG_HEADER];


static ngx_rtmp_module_t  ngx_rtmp_flv_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_flv_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_flv_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_flv_module_ctx,               /* module context */
    NULL,                                   /* module directives */
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


static ngx_int_t
ngx_rtmp_flv_fill_index(ngx_rtmp_amf_ctx_t *ctx, ngx_rtmp_flv_index_t *idx)
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
ngx_rtmp_flv_init_index(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_flv_ctx_t             *ctx;

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

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL || in == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: init index");

    ngx_memzero(&filepositions_ctx, sizeof(filepositions_ctx));
    ngx_memzero(&times_ctx, sizeof(times_ctx));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: init index error");
        return NGX_OK;
    }

    if (filepositions_ctx.link && ngx_rtmp_flv_fill_index(&filepositions_ctx,
                                                          &ctx->filepositions)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: failed to init filepositions");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: filepositions nelts=%ui offset=%ui",
                   ctx->filepositions.nelts, ctx->filepositions.offset);

    if (times_ctx.link && ngx_rtmp_flv_fill_index(&times_ctx,
                                                  &ctx->times)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: failed to init times");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: times nelts=%ui offset=%ui",
                   ctx->times.nelts, ctx->times.offset);

    return  NGX_OK;
}


static double
ngx_rtmp_flv_index_value(void *src)
{
    double      v;

    ngx_rtmp_rmemcpy(&v, src, 8);

    return v;
}


static ngx_int_t
ngx_rtmp_flv_timestamp_to_offset(ngx_rtmp_session_t *s, ngx_file_t *f,
    ngx_int_t timestamp)
{
    ngx_rtmp_flv_ctx_t             *ctx;
    ssize_t                         n, size;
    ngx_uint_t                      offset, index, ret, nelts;
    double                          v;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        goto rewind;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: lookup index start timestamp=%i",
                   timestamp);

    if (ctx->meta_read == 0) {
        ngx_rtmp_flv_read_meta(s, f);
        ctx->meta_read = 1;
    }

    if (timestamp <= 0 || ctx->filepositions.nelts == 0
                       || ctx->times.nelts == 0)
    {
        goto rewind;
    }

    /* read index table from file given offset */
    offset = NGX_RTMP_FLV_DATA_OFFSET + NGX_RTMP_FLV_TAG_HEADER +
             ctx->times.offset;

    /* index should fit in the buffer */
    nelts = ngx_min(ctx->times.nelts, sizeof(ngx_rtmp_flv_buffer) / 9);
    size = nelts * 9;

    n = ngx_read_file(f, ngx_rtmp_flv_buffer, size, offset);

    if (n != size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: could not read times index");
        goto rewind;
    }

    /*TODO: implement binary search */
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: lookup times nelts=%ui", nelts);

    for (index = 0; index < nelts - 1; ++index) {
        v = ngx_rtmp_flv_index_value(ngx_rtmp_flv_buffer +
                                     index * 9 + 1) * 1000;

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "flv: lookup times index=%ui value=%ui",
                      index, (ngx_uint_t) v);

        if (timestamp < v) {
            break;
        }
    }

    if (index >= ctx->filepositions.nelts) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: index out of bounds: %ui>=%ui",
                     index, ctx->filepositions.nelts);
        goto rewind;
    }

    /* take value from filepositions */
    offset = NGX_RTMP_FLV_DATA_OFFSET + NGX_RTMP_FLV_TAG_HEADER +
             ctx->filepositions.offset + index * 9;

    n = ngx_read_file(f, ngx_rtmp_flv_buffer, 8, offset + 1);

    if (n != 8) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: could not read filepositions index");
        goto rewind;
    }

    ret = (ngx_uint_t) ngx_rtmp_flv_index_value(ngx_rtmp_flv_buffer);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: lookup index timestamp=%i offset=%ui",
                   timestamp, ret);

    return ret;

rewind:
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: lookup index timestamp=%i offset=begin",
                   timestamp);

    return NGX_RTMP_FLV_DATA_OFFSET;
}


static void
ngx_rtmp_flv_read_meta(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_flv_ctx_t             *ctx;
    ssize_t                         n;
    ngx_rtmp_header_t               h;
    ngx_chain_t                    *out, in;
    ngx_buf_t                       in_buf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    uint32_t                        size;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: read meta");

    /* read tag header */
    n = ngx_read_file(f, ngx_rtmp_flv_header, sizeof(ngx_rtmp_flv_header),
                      NGX_RTMP_FLV_DATA_OFFSET);

    if (n != sizeof(ngx_rtmp_flv_header)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: could not read metadata tag header");
        return;
    }

    if (ngx_rtmp_flv_header[0] != NGX_RTMP_MSG_AMF_META) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "flv: first tag is not metadata, giving up");
        return;
    }

    ngx_memzero(&h, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_META;
    h.msid = NGX_RTMP_MSID;
    h.csid = NGX_RTMP_CSID_AMF;

    size = 0;
    ngx_rtmp_rmemcpy(&size, ngx_rtmp_flv_header + 1, 3);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: metadata size=%D", size);

    if (size > sizeof(ngx_rtmp_flv_buffer)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: too big metadata");
        return;
    }

    /* read metadata */
    n = ngx_read_file(f, ngx_rtmp_flv_buffer, size,
                      sizeof(ngx_rtmp_flv_header) +
                      NGX_RTMP_FLV_DATA_OFFSET);

    if (n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "flv: could not read metadata");
        return;
    }

    /* prepare input chain */
    ngx_memzero(&in, sizeof(in));
    ngx_memzero(&in_buf, sizeof(in_buf));

    in.buf = &in_buf;
    in_buf.pos  = ngx_rtmp_flv_buffer;
    in_buf.last = ngx_rtmp_flv_buffer + size;

    ngx_rtmp_flv_init_index(s, &in);

    /* output chain */
    out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);

    ngx_rtmp_prepare_message(s, &h, NULL, out);
    ngx_rtmp_send_message(s, out, 0);
    ngx_rtmp_free_shared_chain(cscf, out);
}


static ngx_int_t
ngx_rtmp_flv_send(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_uint_t *ts)
{
    ngx_rtmp_flv_ctx_t             *ctx;
    uint32_t                        last_timestamp;
    ngx_rtmp_header_t               h, lh;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_chain_t                    *out, in;
    ngx_buf_t                       in_buf;
    ngx_int_t                       rc;
    ssize_t                         n;
    uint32_t                        buflen, end_timestamp, size;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->offset == -1) {
        ctx->offset = ngx_rtmp_flv_timestamp_to_offset(s, f,
                                                       ctx->start_timestamp);
        ctx->start_timestamp = -1; /* set later from actual timestamp */
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: read tag at offset=%i", ctx->offset);

    /* read tag header */
    n = ngx_read_file(f, ngx_rtmp_flv_header,
                      sizeof(ngx_rtmp_flv_header), ctx->offset);

    if (n != sizeof(ngx_rtmp_flv_header)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: could not read flv tag header");
        return NGX_DONE;
    }

    /* parse header fields */
    ngx_memzero(&h, sizeof(h));

    h.msid = NGX_RTMP_MSID;
    h.type = ngx_rtmp_flv_header[0];

    size = 0;

    ngx_rtmp_rmemcpy(&size, ngx_rtmp_flv_header + 1, 3);
    ngx_rtmp_rmemcpy(&h.timestamp, ngx_rtmp_flv_header + 4, 3);

    ((u_char *) &h.timestamp)[3] = ngx_rtmp_flv_header[7];

    ctx->offset += (sizeof(ngx_rtmp_flv_header) + size + 4);

    last_timestamp = 0;

    switch (h.type) {

        case NGX_RTMP_MSG_AUDIO:
            h.csid = NGX_RTMP_CSID_AUDIO;
            last_timestamp = ctx->last_audio;
            ctx->last_audio = h.timestamp;
            break;

        case NGX_RTMP_MSG_VIDEO:
            h.csid = NGX_RTMP_CSID_VIDEO;
            last_timestamp = ctx->last_video;
            ctx->last_video = h.timestamp;
            break;

        default:
            return NGX_OK;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: read tag type=%i size=%uD timestamp=%uD "
                  "last_timestamp=%uD",
                  (ngx_int_t) h.type,size, h.timestamp, last_timestamp);

    lh = h;
    lh.timestamp = last_timestamp;

    if (size > sizeof(ngx_rtmp_flv_buffer)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: too big message: %D>%uz", size,
                      sizeof(ngx_rtmp_flv_buffer));
        goto next;
    }

    /* read tag body */
    n = ngx_read_file(f, ngx_rtmp_flv_buffer, size,
                      ctx->offset - size - 4);

    if (n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "flv: could not read flv tag");
        return NGX_ERROR;
    }

    /* prepare input chain */
    ngx_memzero(&in, sizeof(in));
    ngx_memzero(&in_buf, sizeof(in_buf));

    in.buf = &in_buf;
    in_buf.pos  = ngx_rtmp_flv_buffer;
    in_buf.last = ngx_rtmp_flv_buffer + size;

    /* output chain */
    out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);

    ngx_rtmp_prepare_message(s, &h, ctx->msg_mask & (1 << h.type) ?
                             &lh : NULL, out);
    rc = ngx_rtmp_send_message(s, out, 0);
    ngx_rtmp_free_shared_chain(cscf, out);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->msg_mask |= (1 << h.type);

next:
    if (ctx->start_timestamp == -1) {
        ctx->start_timestamp = h.timestamp;
        ctx->epoch = ngx_current_msec;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "flv: start_timestamp=%i", ctx->start_timestamp);
        return NGX_OK;
    }

    buflen = s->buflen + NGX_RTMP_FLV_BUFLEN_ADDON;

    end_timestamp = (ngx_current_msec - ctx->epoch) +
                     ctx->start_timestamp + buflen;

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "flv: %s wait=%D timestamp=%D end_timestamp=%D bufen=%i",
            h.timestamp > end_timestamp ? "schedule" : "advance",
            h.timestamp > end_timestamp ? h.timestamp - end_timestamp : 0,
            h.timestamp, end_timestamp, (ngx_int_t) buflen);

    s->current_time = h.timestamp;

    /* too much data sent; schedule timeout */
    if (h.timestamp > end_timestamp) {
        return h.timestamp - end_timestamp;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_init(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_int_t aindex,
                  ngx_int_t vindex)
{
    ngx_rtmp_flv_ctx_t             *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_flv_ctx_t));

        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_flv_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_start(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_flv_ctx_t             *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: start");

    ctx->offset = -1;
    ctx->msg_mask = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_seek(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_uint_t timestamp)
{
    ngx_rtmp_flv_ctx_t             *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: seek timestamp=%ui", timestamp);

    ctx->start_timestamp = timestamp;
    ctx->epoch = ngx_current_msec;
    ctx->offset = -1;
    ctx->msg_mask = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_stop(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_flv_ctx_t             *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "flv: stop");

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_play_main_conf_t      *pmcf;
    ngx_rtmp_play_fmt_t           **pfmt, *fmt;

    pmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_play_module);

    pfmt = ngx_array_push(&pmcf->fmts);

    if (pfmt == NULL) {
        return NGX_ERROR;
    }

    fmt = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_play_fmt_t));

    if (fmt == NULL) {
        return NGX_ERROR;
    }

    *pfmt = fmt;

    ngx_str_set(&fmt->name, "flv-format");

    ngx_str_null(&fmt->pfx); /* default fmt */
    ngx_str_set(&fmt->sfx, ".flv");

    fmt->init  = ngx_rtmp_flv_init;
    fmt->start = ngx_rtmp_flv_start;
    fmt->seek  = ngx_rtmp_flv_seek;
    fmt->stop  = ngx_rtmp_flv_stop;
    fmt->send  = ngx_rtmp_flv_send;

    return NGX_OK;
}
