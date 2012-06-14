/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>


#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/log.h>


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_delete_stream_pt        next_delete_stream;


static ngx_int_t ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);


static ngx_log_t *ngx_rtmp_hls_log;

static void 
ngx_rtmp_hls_av_log_callback(void* avcl, int level, const char* fmt, 
        va_list args) 
{
    char           *p;
    static char     buf[1024];
    int             n;


    n = vsnprintf(buf, sizeof(buf), fmt, args);
    buf[n] = 0;

    for (p = buf; *p; ++p) {
        if (*p == (u_char)'\n' || *p == (u_char)'\r') {
            *p = ' ';
        }
    }

    ngx_log_error_core(NGX_LOG_ERR, ngx_rtmp_hls_log, 0, "hls: av: %s", buf);
}


#define NGX_RTMP_HLS_MAX_FRAGS          128

#define NGX_RTMP_HLS_PUBLISHING         0x01
#define NGX_RTMP_HLS_AUDIO              0x02
#define NGX_RTMP_HLS_VIDEO              0x04
#define NGX_RTMP_HLS_VIDEO_HEADER_SENT  0x08


#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)


typedef struct {
    AVCodecContext                     *codec_ctx;
    AVCodec                            *codec;
} ngx_rtmp_hls_input_t;


typedef struct {
    ngx_uint_t                          flags;
    ngx_event_t                         restart_evt;

    ngx_int_t                           opened;

    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           name;

    ngx_int_t                           frag;

    ngx_uint_t                          vcodec;
    ngx_uint_t                          acodec;

    ngx_int_t                           out_vstream;
    ngx_int_t                           out_astream;

    u_char                             *header;
    size_t                              header_len;

    AVFormatContext                    *out_format;

} ngx_rtmp_hls_ctx_t;


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          playlen;
    size_t                              nfrags;
    ngx_rtmp_hls_ctx_t                **ctx;
    ngx_uint_t                          nbuckets;
    ngx_str_t                           path;
} ngx_rtmp_hls_app_conf_t;


static ngx_command_t ngx_rtmp_hls_commands[] = {

    { ngx_string("hls"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, hls),
      NULL },

    { ngx_string("hls_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, fraglen),
      NULL },

    { ngx_string("hls_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, path),
      NULL },

    { ngx_string("hls_playlist_length"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, playlen),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hls_module_ctx = {
	NULL,                               /* preconfiguration */
	ngx_rtmp_hls_postconfiguration,     /* postconfiguration */

	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */

	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */

	ngx_rtmp_hls_create_app_conf,       /* create location configuration */
	ngx_rtmp_hls_merge_app_conf,        /* merge location configuration */
};


ngx_module_t  ngx_rtmp_hls_module = {
	NGX_MODULE_V1,
	&ngx_rtmp_hls_module_ctx,           /* module context */
	ngx_rtmp_hls_commands,              /* module directives */
	NGX_RTMP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};


/* convert Flash codec id to FFmpeg codec id */
static enum CodecID
ngx_rtmp_hls_get_video_codec(ngx_int_t cid)
{
    switch (cid) {
        case 1:
            return CODEC_ID_JPEG2000;   /* JPEG */
        case 2:
            return CODEC_ID_FLV1;       /* Sorensen H.263 */
        case 3:
            return CODEC_ID_FLASHSV;    /* Screen video */
        case 4:
            return CODEC_ID_VP6F;       /* On2 VP6 */
        case 5:
            return CODEC_ID_VP6A;       /* On2 VP6 Alpha */
        case 6:
            return CODEC_ID_FLASHSV2;   /* Screen Video 2 */
        case 7:
            return CODEC_ID_H264;       /* H264 / MPEG4-AVC */
        default:
            return CODEC_ID_NONE;
    }
}


static enum CodecID
ngx_rtmp_hls_get_audio_codec(ngx_int_t cid)
{
    switch (cid) {
        case 0:
            return CODEC_ID_NONE;       /* Uncompressed */
        case 1:
            return CODEC_ID_ADPCM_SWF;  /* ADPCM */
        case 2:
        case 14:
            return CODEC_ID_MP3;        /* Mp3 */
        case 4:
        case 5:
        case 6:
            return CODEC_ID_NELLYMOSER; /* Nellymoser */
        case 7:
            return CODEC_ID_PCM_ALAW;   /* G711 */
        case 8:
            return CODEC_ID_PCM_MULAW;  /* G711Mu */
        case 10:
            return CODEC_ID_AAC;        /* AAC */
        case 11:
            return CODEC_ID_SPEEX;      /* Speex */
        default:
            return CODEC_ID_NONE;
    }
}


static ngx_int_t
ngx_rtmp_hls_init_out_video(ngx_rtmp_session_t *s)
{
    AVStream                       *stream;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_hls_app_conf_t        *hacf;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->vcodec == 0 || (ctx->flags & NGX_RTMP_HLS_VIDEO)) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: adding video stream; codec=%ui", ctx->vcodec);

    stream = avformat_new_stream(ctx->out_format, NULL);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed (video)");
        return NGX_ERROR;
    }

    stream->codec->codec_id = ctx->vcodec;
    stream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codec->time_base.den = 25;
    stream->codec->time_base.num = 1;
    stream->codec->width  = 256;
    stream->codec->height = 256;
    /*
    stream->codec->pix_fmt = PIX_FMT_YUV420P;
    stream->codec->frame_number = 0;
    stream->codec->gop_size = 12;
    stream->codec->max_b_frames = 2;
    */
    /*stream->codec->bit_rate = 96 * 1024 2000000*/;

    if (ctx->out_format->oformat->flags & AVFMT_GLOBALHEADER) {
        stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
    }

    /*
    if (avcodec_open2(stream->codec, codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed (video out)");
        return NGX_ERROR;
    }*/

    /*ctx->out_vcodec = stream->codec;*/
    ctx->out_vstream = stream->index;
    ctx->flags |= NGX_RTMP_HLS_VIDEO;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: video stream: %i", ctx->out_vstream);

    return NGX_OK;
}

/*
static ngx_int_t
ngx_rtmp_hls_init_out_audio(ngx_rtmp_session_t *s, const char *cname, 
        ngx_int_t sample_rate)
{
    AVCodec                    *codec;
    AVStream                   *stream;
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec = avcodec_find_encoder_by_name(cname);
    if (codec == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_find_encoder_by_name failed (%s)", cname);
        return NGX_ERROR;
    }
    stream = avformat_new_stream(ctx->out_format, codec);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed (audio)");
        return NGX_ERROR;
    }

    stream->codec->codec_id = CODEC_ID_NONE;
    stream->codec->codec_type = AVMEDIA_TYPE_UNKNOWN;
    stream->codec->sample_fmt = AV_SAMPLE_FMT_S32;
    stream->codec->sample_rate = sample_rate;
    stream->codec->bit_rate = 128000;
    stream->codec->channels = 1;

    if (avcodec_open2(stream->codec, codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed (audio out)");
        return NGX_ERROR;
    }

    ctx->out_acodec = stream->codec;
    ctx->out_astream = stream->index;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: audio stream: %i", ctx->out_astream);

    return NGX_OK;
}
*/

static ngx_int_t
ngx_rtmp_hls_update_playlist(ngx_rtmp_session_t *s)
{
    static u_char                   buffer[1024];
    int                             fd;
    u_char                         *p;
    ngx_rtmp_hls_ctx_t             *ctx;
    ssize_t                         n;
    ngx_int_t                       ffrag;
    ngx_rtmp_hls_app_conf_t        *hacf;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY, 
            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                "hls: open failed: '%V'", 
                &ctx->playlist_bak);
        return NGX_ERROR;
    }

    ffrag = ctx->frag - hacf->nfrags;
    if (ffrag < 1) {
        ffrag = 1;
    }

    p = ngx_snprintf(buffer, sizeof(buffer), 
            "#EXTM3U\r\n"
            "#EXT-X-TARGETDURATION:%i\r\n"
            "#EXT-X-MEDIA-SEQUENCE:%i\r\n\r\n",
            /*TODO: float*/(ngx_int_t)(hacf->fraglen / 1000), ffrag);
    n = write(fd, buffer, p - buffer);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                "hls: write failed: '%V'", 
                &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    for (; ffrag < ctx->frag; ++ffrag) {
        p = ngx_snprintf(buffer, sizeof(buffer), 
                "#EXTINF: %i,\r\n"
                "%V-%i.ts\r\n", 
                /*TODO:float*/(ngx_int_t)(hacf->fraglen / 1000),
                &ctx->name, ffrag);
        n = write(fd, buffer, p - buffer);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                    "hls: write failed: '%V'", 
                    &ctx->playlist_bak);
            ngx_close_file(fd);
            return NGX_ERROR;
        }
    }

    ngx_close_file(fd);

    if (ngx_rename_file(ctx->playlist_bak.data, ctx->playlist.data)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                "hls: rename failed: '%V'->'%V'", 
                &ctx->playlist_bak, &ctx->playlist);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_open_file(ngx_rtmp_session_t *s, u_char *fpath)
{
    ngx_rtmp_hls_ctx_t             *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: open stream file '%s'", fpath);

#if 0
    /* create video stream */
    if (ctx->width && ctx->height && ctx->out_vcodec == NULL && 0) {
        ngx_rtmp_hls_init_out_video(s, "mpeg2video", ctx->width, 
                ctx->height);
    }

    /* create audio stream */
    /*if (ctx->sample_rate && ctx->out_acodec == NULL) {*/
    if (ctx->sample_rate && 0) {
        ngx_rtmp_hls_init_out_audio(s, "libmp3lame", ctx->sample_rate);
    }
#endif

    /* write header */
    if (ctx->frag < 2) {
        return NGX_OK;
    }

    if (ngx_rtmp_hls_init_out_video(s) != NGX_OK) {
        return NGX_ERROR;
    }
    /* open file */
    if (avio_open(&ctx->out_format->pb, (char *)fpath, AVIO_FLAG_WRITE) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_open failed");
        return NGX_ERROR;
    }
  /*  ngx_rtmp_hls_init_out_audio(s, "libmp3lame", ctx->sample_rate);*/
    if (avformat_write_header(ctx->out_format, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avformat_write_header failed");
        avformat_free_context(ctx->out_format);
        ctx->out_format = NULL;
        return NGX_ERROR;
    }
    ctx->opened = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_close_file(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (!ctx->opened) {
        return NGX_OK;
    }

    avio_flush(ctx->out_format->pb);

    if (avio_close(ctx->out_format->pb) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_close failed");
    }

    ctx->opened = 0;

    return NGX_OK;
}


static void 
ngx_rtmp_hls_restart(ngx_event_t *hev)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_connection_t               *c;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_hls_ctx_t             *ctx;


    c = hev->data;
    s = c->data;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    if (ctx->out_format == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: restart frag=%i", ctx->frag);

    ngx_rtmp_hls_close_file(s);

    /* remember we have preallocated memory in ctx->stream */

    /* erase old file */
    if (ctx->frag > (ngx_int_t)hacf->nfrags) {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%i.ts", 
                ctx->frag - hacf->nfrags) = 0;
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: delete stream file '%s'", ctx->stream.data);
        ngx_delete_file(ctx->stream.data);
    }

    ++ctx->frag;

    /* create new one */
    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%i.ts", 
            ctx->frag) = 0;
    ngx_rtmp_hls_open_file(s, ctx->stream.data);

    /* update playlist */
    ngx_rtmp_hls_update_playlist(s);

    ngx_add_timer(hev, hacf->fraglen);
}


static ngx_int_t
ngx_rtmp_hls_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_event_t                    *e;
    size_t                          len;
    u_char                         *p;
    AVOutputFormat                 *format;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls || hacf->path.len == 0) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: publish: name='%s' type='%s'",
            v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    } else {
        ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));
    }

    ctx->flags |= NGX_RTMP_HLS_PUBLISHING;
    e = &ctx->restart_evt;
    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_hls_restart;
    ngx_add_timer(e, hacf->fraglen);

    len = ngx_strlen(v->name);

    ctx->name.len = len + (ngx_uint_t)ngx_escape_uri(NULL, v->name, len, 
            NGX_ESCAPE_URI_COMPONENT);
    ctx->name.data = ngx_palloc(s->connection->pool,
            ctx->name.len);
    ngx_escape_uri(ctx->name.data, v->name, len, NGX_ESCAPE_URI_COMPONENT);

    ctx->playlist.data = ngx_palloc(s->connection->pool,
        hacf->path.len + 1 + ctx->name.len + sizeof(".m3u8"));
    p = ngx_cpymem(ctx->playlist.data, hacf->path.data, hacf->path.len);
    if (p[-1] != '/') {
        *p++ = '/';
    }
    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);

    /* ctx->stream_path holds initial part of stream file path 
     * however the space for the whole stream path
     * is allocated */
    ctx->stream.len = p - ctx->playlist.data;
    ctx->stream.data = ngx_palloc(s->connection->pool,
            ctx->stream.len + 1 + NGX_OFF_T_LEN + sizeof(".ts"));
    ngx_memcpy(ctx->stream.data, ctx->playlist.data, ctx->stream.len);

    /* playlist path */
    p = ngx_cpymem(p, ".m3u8", sizeof(".m3u8") - 1);
    ctx->playlist.len = p - ctx->playlist.data;
    *p = 0;

    /* playlist bak (new playlist) path */
    ctx->playlist_bak.data = ngx_palloc(s->connection->pool, 
        ctx->playlist.len + sizeof(".bak"));
    p = ngx_cpymem(ctx->playlist_bak.data, ctx->playlist.data, 
            ctx->playlist.len);
    p = ngx_cpymem(p, ".bak", sizeof(".bak") - 1);
    ctx->playlist_bak.len = p - ctx->playlist_bak.data;
    *p = 0;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: playlist='%V' playlist_bak='%V' stream_pattern='%V'",
            &ctx->playlist, &ctx->playlist_bak, &ctx->stream);

    /* create output format */
    format = av_guess_format("mpegts", NULL, NULL);
    if (format == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_guess_format failed");
        return NGX_ERROR;
    }
    ctx->out_format = avformat_alloc_context();
    if (ctx->out_format == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avformat_alloc_context failed");
        return NGX_ERROR;
    }
    ctx->out_format->oformat = format;

    ngx_rtmp_hls_restart(e);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_hls_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls || ctx == NULL 
            || (ctx->flags & NGX_RTMP_HLS_PUBLISHING) == 0) 
    {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: delete");

    ctx->flags &= ~NGX_RTMP_HLS_PUBLISHING;
    if (ctx->restart_evt.timer_set) {
        ngx_del_timer(&ctx->restart_evt);
    }

    if (av_write_trailer(ctx->out_format) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_write_trailer failed");
    }

    ngx_rtmp_hls_close_file(s);

    avformat_free_context(ctx->out_format);
    ctx->out_format = NULL;

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_hls_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    AVPacket                        packet, hpacket;
    u_char                         *p;
    size_t                          size, space;
    uint8_t                         fmt, f;
    uint32_t                        nsize;

    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];



    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls || ctx == NULL 
                     || (ctx->flags & NGX_RTMP_HLS_PUBLISHING) == 0) 
    {
        return NGX_OK;
    }

    if ((h->type != NGX_RTMP_MSG_VIDEO && h->type != NGX_RTMP_MSG_AUDIO)
            || h->mlen <= 1) 
    {
        return NGX_OK;
    }

    /*ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: %s: len='%D' timestamp=%D", h->type == NGX_RTMP_MSG_VIDEO ? 
            "video" : "audio", h->mlen, h->timestamp);*/

    fmt = in->buf->pos[0];
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        ctx->vcodec = ngx_rtmp_hls_get_video_codec(fmt & 0x0f);
    } else {
        ctx->acodec = ngx_rtmp_hls_get_audio_codec((fmt & 0xf0) >> 4);
        return NGX_OK;
    }

    /* prepare input buffer */
    p = buffer + 8;
    space = sizeof(buffer) - 8;
    for (; in; in = in->next) {
        size = in->buf->last - in->buf->pos;
        if (size + FF_INPUT_BUFFER_PADDING_SIZE > space) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: too big input frame");
            return NGX_OK;
        }
        p = ngx_cpymem(p, in->buf->pos, size);
        space -= size;
    }
    ngx_memzero(p, space);

    /* prepare input packet;
     * first byte belongs to RTMP, not codec */
    av_init_packet(&packet);
    packet.data = buffer + 8 + 1;
    packet.size = p - buffer + 8 - 1;
    packet.dts = h->timestamp * 100;
    packet.pts = packet.dts;
    packet.stream_index = (h->type == NGX_RTMP_MSG_AUDIO
        ? ctx->out_astream : ctx->out_vstream);
    if (((fmt & 0xf0) >> 4) == 1) {
        packet.flags |= AV_PKT_FLAG_KEY;
    }

    if (h->type != NGX_RTMP_MSG_VIDEO 
            || ctx->vcodec != CODEC_ID_H264
            || packet.size < 4) 
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: bad frame");
    }
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "hls: frame_fmt: %i", (ngx_int_t)packet.data[0]);
    f = packet.data[0];
    switch (f) {
        case 0:
            /* AVC sequence header */
            if (ctx->header == NULL) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "hls: initial sequence header: v=%d", (ngx_int_t)packet.data[1]);
                packet.data -= 3;
                packet.size += 3;
                packet.data[0] = 0;
                packet.data[1] = 0;
                packet.data[2] = 0;
                packet.data[3] = 1;
                ctx->header_len = packet.size;
                ctx->header = ngx_palloc(s->connection->pool, ctx->header_len);
                if (ctx->header == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(ctx->header, packet.data, ctx->header_len);
            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "hls: repeated sequence header");
            }
            return NGX_OK;

        case 1:
            /* NALU payload */
            packet.data += 4;
            packet.size -= 4;
            break;
    }

    if (ctx->out_format == NULL) {
        return NGX_OK;
    }

    if ((ctx->flags & NGX_RTMP_HLS_VIDEO_HEADER_SENT) == 0
            && ctx->header) 
    {
        av_init_packet(&hpacket);
        hpacket.data = ctx->header;
        hpacket.size = ctx->header_len;
        hpacket.stream_index = ctx->out_vstream;
    hpacket.dts = h->timestamp * 100-1;
    hpacket.pts = packet.dts;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: sending sequence header: %uz bytes",
                hpacket.size);

        if (ctx->out_format->streams) {
        if (av_interleaved_write_frame(ctx->out_format, &hpacket) < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: av_interleaved_write_frame failed on header");
            return NGX_OK;
        }
        }

        ctx->flags |= NGX_RTMP_HLS_VIDEO_HEADER_SENT;
    }

    if (!((h->type == NGX_RTMP_MSG_VIDEO 
                    && (ctx->flags & NGX_RTMP_HLS_VIDEO)) ||
          (h->type == NGX_RTMP_MSG_AUDIO 
                    && (ctx->flags & NGX_RTMP_HLS_AUDIO))))
    {
        return NGX_OK;
    }

    /* extract NALUs & write them */
    size = packet.size;
    for ( ;; ) {
        if (size <= 4) {
            return NGX_OK;
        }

        /*FIXME: NALU size size is not a constant! */
        ngx_rtmp_rmemcpy(&nsize, packet.data, 4);
        packet.data[0] = 0;
        packet.data[1] = 0;
        packet.data[2] = 0;
        packet.data[3] = 1;
        packet.size = nsize;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: NALU size=%uD", nsize);

        if (nsize + 4 > size) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: NALU is too big %L<%z", nsize, size + 4);
            return NGX_OK;
        }

if (ctx->out_format->streams) {
        if (av_interleaved_write_frame(ctx->out_format, &packet) < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: av_interleaved_write_frame failed");
        }}

        packet.data += 4;
        packet.data += nsize;
        size -= 4;
        size -= nsize;
        break;
    }

    return NGX_OK;
}


static void *
ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf)
{
	ngx_rtmp_hls_app_conf_t       *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hls_app_conf_t));
	if (conf == NULL) {
		return NULL;
	}

    conf->hls = NGX_CONF_UNSET;
    conf->fraglen = NGX_CONF_UNSET;
    conf->playlen = NGX_CONF_UNSET;
    conf->nbuckets = 1024;

	return conf;
}


static char *
ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_rtmp_hls_app_conf_t       *prev = parent;
	ngx_rtmp_hls_app_conf_t       *conf = child;

	ngx_conf_merge_value(conf->hls, prev->hls, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    conf->ctx = ngx_pcalloc(cf->pool, 
            sizeof(ngx_rtmp_hls_ctx_t *) * conf->nbuckets);
    if (conf->ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    if (conf->fraglen) {
        conf->nfrags = conf->playlen / conf->fraglen;
    }

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_handler_pt            *h;

    /* av handler */
    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hls_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hls_av;

    /* chain handlers */
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hls_publish;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_hls_delete_stream;

    /* register all ffmpeg stuff */
    av_register_all();
    ngx_rtmp_hls_log = &cf->cycle->new_log;
    av_log_set_callback(ngx_rtmp_hls_av_log_callback);

	return NGX_OK;
}

