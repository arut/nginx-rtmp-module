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
static ngx_int_t ngx_rtmp_play_restart(ngx_rtmp_session_t *s, uint32_t);
static ngx_int_t ngx_rtmp_play_stop(ngx_rtmp_session_t *s);


typedef struct {
    ngx_str_t                           root;
} ngx_rtmp_play_app_conf_t;


typedef struct {
    ngx_file_t                          file;
    ngx_uint_t                          offset;
    ngx_event_t                         write_evt;
    uint32_t                            last_audio;
    uint32_t                            last_video;
    ngx_uint_t                          msg_mask;
    uint32_t                            epoch;
    uint32_t                            start_timestamp;
    unsigned                            meta_seeking:1;
    unsigned                            key_seeking:1;
} ngx_rtmp_play_ctx_t;


#define NGX_RTMP_PLAY_BUFFER            (1024*1024)
#define NGX_RTMP_PLAY_DEFAULT_BUFLEN    1000


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
ngx_rtmp_play_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_rtmp_play_app_conf_t       *pacf;

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);
    if (pacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_rtmp_play_stop(s);

    if (ctx->file.fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->file.fd);
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_play_restart(ngx_rtmp_session_t *s, uint32_t offset)
{
    ngx_rtmp_play_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_rtmp_play_stop(s);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: restart offset=%D", offset);

    /*TODO: lookup metadata keyframe map
     * for start_timestamp/ctx->offset */

    ctx->offset = 13; /* header + zero tag size */
    ctx->epoch = ngx_current_msec;
    ctx->start_timestamp = offset;
    ctx->msg_mask = 0;
    if (offset) {
        ctx->key_seeking = 1;
    }

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

    if (ctx->write_evt.timer_set) {
        ngx_del_timer(&ctx->write_evt);
    }

    if (ctx->write_evt.prev) {
        ngx_delete_posted_event((&ctx->write_evt));
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: stop");

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_play_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_rtmp_play_app_conf_t       *pacf;

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);
    if (pacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: seek offset=%i", (ngx_int_t) v->offset);

    ngx_rtmp_play_restart(s, v->offset);

next:
    return next_seek(s, v);
}


static ngx_int_t
ngx_rtmp_play_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_play_ctx_t            *ctx;
    ngx_rtmp_play_app_conf_t       *pacf;

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_play_module);
    if (pacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->file.fd == NGX_INVALID_FILE) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: pause pause=%i position=%i",
                   (ngx_int_t) v->pause, (ngx_int_t) v->position);

    if (v->pause) {
        ngx_rtmp_play_stop(s);
    } else {
        ngx_rtmp_play_restart(s, v->position);
    }

next:
    return next_pause(s, v);
}


static void
ngx_rtmp_play_send(ngx_event_t *e)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_play_ctx_t            *ctx;
    uint8_t                         type;
    uint32_t                        size;
    uint32_t                        timestamp, last_timestamp;
    ngx_rtmp_header_t               h, lh;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_chain_t                    *out, in;
    ngx_buf_t                       in_buf;
    ssize_t                         n;
    uint32_t                        buflen, end_timestamp;

    static u_char                   header[11];
    static u_char                   buffer[NGX_RTMP_PLAY_BUFFER];

    s = e->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);
    if (ctx == NULL) {
        return;
    }

    /* read tag header */
    n = ngx_read_file(&ctx->file, header, sizeof(header), ctx->offset);
    if (n != sizeof(header)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: could not read flv tag header");
        ngx_rtmp_send_user_stream_eof(s, 1);
        if (ctx->msg_mask == 0) {
            ngx_rtmp_play_restart(s, 0);
        }
        return;
    }
    ctx->offset += sizeof(header);

    /* parse header fields */
    type = header[0];
    size = 0;
    ngx_rtmp_rmemcpy(&size, header + 1, 3);
    ngx_rtmp_rmemcpy(&timestamp, header + 4, 3);
    ((u_char *) &timestamp)[3] = header[7];

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: type=%i offset=%ui size=%D timestamp=%D",
                   type, ctx->offset, size, timestamp);

    /* expect meta packet at the beginning;
     * if missing then do not look it up */
    if (ctx->meta_seeking && type != NGX_RTMP_MSG_AMF_META) {
        ctx->meta_seeking = 0;
        ngx_rtmp_play_restart(s, ctx->start_timestamp);
        return;
    }

    /* skip early audio/video frames */
    if ((type == NGX_RTMP_MSG_AUDIO || type == NGX_RTMP_MSG_VIDEO) &&
       ctx->start_timestamp && timestamp < ctx->start_timestamp) 
    {
        goto skip;
    }

    /* fill RTMP header & last pseudo-header */
    ngx_memzero(&h, sizeof(h));
    h.type = type;
    h.msid = NGX_RTMP_LIVE_MSID;
    h.timestamp = timestamp;
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

        case NGX_RTMP_MSG_AMF_META:
            h.csid = NGX_RTMP_LIVE_CSID_META;
            h.timestamp = 0;
            last_timestamp = 0;
            break;
    }

    lh = h;
    lh.timestamp = last_timestamp;

    if (size > sizeof(buffer)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: too big message: %D>%uz", size, sizeof(buffer));
        goto next;
    }

    /* read tag body */
    n = ngx_read_file(&ctx->file, buffer, size, ctx->offset);
    if (n != size) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "play: could not read flv tag");
        return;
    }

    /* prepare input chain */
    ngx_memzero(&in, sizeof(in));
    ngx_memzero(&in_buf, sizeof(in_buf));
    in.buf = &in_buf;
    in_buf.pos = buffer;
    in_buf.last = buffer + size;

    /* skip until keyframe? */
    if (ctx->key_seeking) {
        if (h.type != NGX_RTMP_MSG_VIDEO || size == 0 || 
            ngx_rtmp_get_video_frame_type(&in) != NGX_RTMP_VIDEO_KEY_FRAME)
        {
            goto skip;
        }
        ctx->key_seeking = 0;
        ctx->start_timestamp = timestamp;
    }

    /* create output chain */
    out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);
    ngx_rtmp_prepare_message(s, &h, ctx->msg_mask & (1 << h.type) ? 
                             &lh : NULL, out);

    /* output chain */
    ngx_rtmp_send_message(s, out, 0); /* TODO: priority */

    ngx_rtmp_free_shared_chain(cscf, out);
    ctx->msg_mask |= (1 << h.type);

    if (ctx->meta_seeking) {
        ctx->meta_seeking = 0;
        ngx_rtmp_play_restart(s, ctx->start_timestamp);
        return;
    }

next:
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
        ctx->offset += (size + 4);
        ngx_add_timer(e, h.timestamp - end_timestamp);
        return;
    }

skip:
    ctx->offset += (size + 4);
    ngx_post_event(e, &ngx_posted_events);
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

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: play: name='%s' start=%i duration=%i",
                   v->name, (ngx_int_t) v->start, (ngx_int_t) v->duration);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_play_module);

    if (ctx && (ctx->file.fd != NGX_INVALID_FILE
                || ctx->write_evt.timer_set)) 
    {
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

    /*TODO: escape*/
    len = ngx_strlen(v->name);
    slen = sizeof(".flv") - 1;
    p = ngx_snprintf(path, sizeof(path), "%V/%s%s", &pacf->root, v->name,
            len > slen && ngx_strncasecmp((u_char *) ".flv", 
                                           v->name + len - slen, slen) == 0
            ? "" : ".flv");
    *p = 0;

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

    ctx->meta_seeking = 1;

    ngx_rtmp_send_user_recorded(s, 1);

    ngx_rtmp_play_restart(s, v->start < 0 ? 0 : v->start);

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
