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


#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)

static u_char 
ngx_rtmp_hls_out_buffer[NGX_RTMP_HLS_BUFSIZE];

static u_char 
ngx_rtmp_hls_in_buffer[NGX_RTMP_HLS_BUFSIZE];


typedef struct {
    AVCodecContext                     *codec_ctx;
    AVCodec                            *codec;
} ngx_rtmp_hls_input_t;


typedef struct {
    ngx_uint_t                          flags;
    ngx_event_t                         restart_evt;

    ngx_int_t                           frag;

    ngx_uint_t                          width;
    ngx_uint_t                          height;

    ngx_int_t                           in_vcodec_id;
    ngx_int_t                           in_acodec_id;

    AVCodecContext                     *in_vcodec;
    AVCodecContext                     *in_acodec;

    ngx_int_t                           out_vstream;
    ngx_int_t                           out_astream;

    AVCodecContext                     *out_vcodec;
    AVCodecContext                     *out_acodec;

    AVFrame                            *frame;
    AVFormatContext                    *out_format;

} ngx_rtmp_hls_ctx_t;


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          fraglen;
    ngx_rtmp_hls_ctx_t                **ctx;
    ngx_uint_t                          nbuckets;
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
            return CODEC_ID_MP3;        /* Mp3 */
        case 5:
            return CODEC_ID_NELLYMOSER; /* Nellymoser 8khz */
        case 6:
            return CODEC_ID_NELLYMOSER; /* Nellymoser */
        case 11:
            return CODEC_ID_SPEEX;      /* Speex */
        default:
            return CODEC_ID_NONE;
    }
}


static struct AVCodecContext *
ngx_rtmp_hls_init_in_codec(ngx_rtmp_session_t *s, enum CodecID codec_id)
{
    AVCodec                *codec;
    AVCodecContext         *context;


    codec = avcodec_find_decoder(codec_id);
    if (codec == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_find_decoder failed ('%i')", 
                (ngx_int_t)codec_id);
        return NULL;
    }

    context = avcodec_alloc_context3(codec);
    if (context == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_alloc_context3 failed (in)");
        return NULL;
    }

    if (avcodec_open2(context, codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed (in)");
    }

    return context;
}


static ngx_int_t
ngx_rtmp_hls_init_in_video(ngx_rtmp_session_t *s, ngx_int_t cid)
{
    enum CodecID            codec_id;
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->in_vcodec && cid == ctx->in_vcodec_id) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: input video codec=%i", cid);

    codec_id = ngx_rtmp_hls_get_video_codec(cid);
    if (codec_id == CODEC_ID_NONE) {
        return NGX_ERROR;
    }

    if (ctx->in_vcodec) {
        av_free(ctx->in_vcodec);
        ctx->in_vcodec = NULL;
    }

    ctx->in_vcodec_id = cid;
    ctx->in_vcodec = ngx_rtmp_hls_init_in_codec(s, codec_id);

    return ctx->in_vcodec ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_hls_init_in_audio(ngx_rtmp_session_t *s, ngx_int_t cid)
{
    enum CodecID            codec_id;
    ngx_rtmp_hls_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->in_acodec && cid == ctx->in_acodec_id) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: input audio codec=%i", cid);

    codec_id = ngx_rtmp_hls_get_audio_codec(cid);
    if (codec_id == CODEC_ID_NONE) {
        return NGX_ERROR;
    }

    if (ctx->in_acodec) {
        av_free(ctx->in_acodec);
        ctx->in_acodec = NULL;
    }

    ctx->in_acodec_id = cid;
    ctx->in_acodec = ngx_rtmp_hls_init_in_codec(s, codec_id);

    return ctx->in_acodec ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_hls_init_out_video(ngx_rtmp_session_t *s, const char *cname,
        ngx_uint_t width, ngx_uint_t height)
{
    AVCodec                *codec;
    AVStream               *stream;
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec = avcodec_find_encoder_by_name(cname);
    if (codec == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_find_encoder_by_name('%s') failed", cname);
        return NGX_ERROR;
    }

    stream = avformat_new_stream(ctx->out_format, codec);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed (video)");
        return NGX_ERROR;
    }

    stream->codec->codec_id = CODEC_ID_NONE;
    stream->codec->codec_type = AVMEDIA_TYPE_UNKNOWN;
    stream->codec->pix_fmt = PIX_FMT_YUV420P;
    stream->codec->frame_number = 0;
    stream->codec->gop_size = 12;
    stream->codec->max_b_frames = 2;
    stream->codec->time_base.den = 25;
    stream->codec->time_base.num = 1;
    stream->codec->width  = width;
    stream->codec->height = height;
    stream->codec->bit_rate = 2000000;

    if (avcodec_open2(stream->codec, codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed (video out)");
        return NGX_ERROR;
    }

    ctx->out_vcodec = stream->codec;
    ctx->out_vstream = stream->index;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_init_out_audio(ngx_rtmp_session_t *s, const char *cname)
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
    stream->codec->sample_fmt = AV_SAMPLE_FMT_S16;
    stream->codec->sample_rate = 44100;
    stream->codec->bit_rate = 128000;
    stream->codec->channels = 1;

    if (avcodec_open2(stream->codec, codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed (audio out)");
        return NGX_ERROR;
    }

    ctx->out_acodec = stream->codec;
    ctx->out_astream = stream->index;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_open_file(ngx_rtmp_session_t *s, const char *fpath)
{
    AVOutputFormat         *format;
    ngx_rtmp_hls_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

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

    /* create video stream */
    if (ctx->width && ctx->height) {
        ngx_rtmp_hls_init_out_video(s, "mpeg2video", ctx->width, 
                ctx->height);
    }

    /* create audio stream */
    ngx_rtmp_hls_init_out_audio(s, "libmp3lame");

    /* open file */
    if (avio_open(&ctx->out_format->pb, fpath, AVIO_FLAG_WRITE) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_open failed");
        return NGX_ERROR;
    }

    /* write header */
    if (avformat_write_header(ctx->out_format, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avformat_write_header failed");
        avformat_free_context(ctx->out_format);
        ctx->out_format = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_close_file(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->out_format == NULL) {
        return NGX_OK;
    }

    if (av_write_trailer(ctx->out_format) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_write_trailer failed");
    }

    if (avio_close(ctx->out_format->pb) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_close failed");
    }

    avformat_free_context(ctx->out_format);

    ctx->out_format = NULL;
    ctx->out_acodec = ctx->out_vcodec = NULL;

    return NGX_OK;
}


static void 
ngx_rtmp_hls_restart(ngx_event_t *hev)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_connection_t               *c;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_hls_ctx_t             *ctx;
    static u_char                   path[NGX_MAX_PATH];


    c = hev->data;
    s = c->data;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ++ctx->frag;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: restart frag=%i", ctx->frag);

    ngx_rtmp_hls_close_file(s);

    /*TODO: escape path name */
    *ngx_snprintf(path, sizeof(path), "/tmp/frag%i.ts", ctx->frag) = 0;
    ngx_rtmp_hls_open_file(s, (const char *)path);

    ngx_add_timer(hev, hacf->fraglen);
}


static ngx_int_t
ngx_rtmp_hls_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_event_t                    *e;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls) {
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

    ctx->frame = avcodec_alloc_frame();
    if (ctx->frame == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_alloc_frame failed");
        goto cleanup;
    }

    ctx->flags |= NGX_RTMP_HLS_PUBLISHING;
    e = &ctx->restart_evt;
    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_hls_restart;
    ngx_add_timer(e, hacf->fraglen);

    ngx_rtmp_hls_restart(e);

next:
    return next_publish(s, v);

cleanup:
    /*TODO*/
    goto next;
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

    ngx_rtmp_hls_close_file(s);

    if (ctx->frame) {
        av_free(ctx->frame);
        ctx->frame = NULL;
    }

    if (ctx->in_vcodec) {
        av_free(ctx->in_vcodec);
        ctx->in_vcodec = NULL;
    }

    if (ctx->in_acodec) {
        av_free(ctx->in_acodec);
        ctx->in_acodec = NULL;
    }

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_hls_process_video(ngx_rtmp_session_t *s,
        uint8_t fmt, AVPacket *in_packet, AVPacket *out_packet)
{
    int                     got_frame, n;
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    /* decode input frame */
    if (ngx_rtmp_hls_init_in_video(s, fmt & 0x0f) != NGX_OK) {
        return NGX_ERROR;
    }

    got_frame = 0;
    n = avcodec_decode_video2(ctx->in_vcodec, ctx->frame, 
                              &got_frame, in_packet);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_decode_video2 failed");
        return NGX_ERROR;
    }
    if (!got_frame) {
        return NGX_AGAIN;
    }

    ctx->width  = ctx->in_vcodec->width;
    ctx->height = ctx->in_vcodec->height;

    /* encode frame */
    if (ctx->out_vcodec == NULL) {
        return NGX_AGAIN;
    }

    out_packet->stream_index = ctx->out_vstream;

    got_frame = 0;
    n = avcodec_encode_video2(ctx->out_vcodec, out_packet,
            ctx->frame, &got_frame);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_encode_video2 failed");
        return NGX_ERROR;
    }
    if (!got_frame) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_process_audio(ngx_rtmp_session_t *s,
        uint8_t fmt, AVPacket *in_packet, AVPacket *out_packet)
{
    int                     got_frame, n;
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    /* decode input frame */
    if (ngx_rtmp_hls_init_in_audio(s, (fmt & 0xf0) >> 4) != NGX_OK) {
        return NGX_ERROR;
    }

    got_frame = 0;
    n = avcodec_decode_audio4(ctx->in_acodec, ctx->frame, 
                              &got_frame, in_packet);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_decode_audio4 failed");
        return NGX_ERROR;
    }
    if (!got_frame) {
        return NGX_AGAIN;
    }

    /* encode frame */
    if (ctx->out_acodec == NULL) {
        return NGX_AGAIN;
    }

    out_packet->stream_index = ctx->out_astream;

    got_frame = 0;
    n = avcodec_encode_audio2(ctx->out_acodec, out_packet,
            ctx->frame, &got_frame);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_encode_audio2 failed");
        return NGX_ERROR;
    }
    if (!got_frame) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}



static ngx_int_t
ngx_rtmp_hls_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    AVPacket                        in_packet;
    AVPacket                        out_packet;
    int                             n;
    u_char                         *p;
    size_t                          size, space;
    uint8_t                         fmt;


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

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: %s: len='%D' timestamp=%D", h->type == NGX_RTMP_MSG_VIDEO ? 
            "video" : "audio", h->mlen, h->timestamp);

    /* prepare input buffer */
    p = ngx_rtmp_hls_in_buffer;
    space = sizeof(ngx_rtmp_hls_in_buffer);
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
    fmt = ngx_rtmp_hls_in_buffer[0];
    av_init_packet(&in_packet);
    in_packet.data = ngx_rtmp_hls_in_buffer + 1;
    in_packet.size = p - ngx_rtmp_hls_in_buffer - 1;
    in_packet.dts  = 0;/*h->timestamp;*/

    /* prepare output packet */
    av_init_packet(&out_packet);
    out_packet.data = ngx_rtmp_hls_out_buffer;
    out_packet.size = sizeof(ngx_rtmp_hls_out_buffer);
    /*out_packet.pts = AV_NOPTS_VALUE;
    out_packet.dts = h->timestamp;*/

    n = h->type == NGX_RTMP_MSG_VIDEO
        ? ngx_rtmp_hls_process_video(s, fmt, &in_packet, &out_packet) 
        : ngx_rtmp_hls_process_audio(s, fmt, &in_packet, &out_packet);

    if (n != NGX_OK) {
        goto done;
    }

    /* write output frame */
    if (ctx->out_format 
            && av_interleaved_write_frame(ctx->out_format, &out_packet) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_interleaved_write_frame failed");
    }

done:
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
    conf->ctx = ngx_pcalloc(cf->pool, 
            sizeof(ngx_rtmp_hls_ctx_t *) * conf->nbuckets);
    if (conf->ctx == NULL) {
        return NGX_CONF_ERROR;
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

