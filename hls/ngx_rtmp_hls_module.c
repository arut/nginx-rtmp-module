/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>


#include </home/rarutyunyan/root/include/libavcodec/avcodec.h>
#include </home/rarutyunyan/root/include/libavformat/avformat.h>
#include </home/rarutyunyan/root/include/libavutil/log.h>


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
    ngx_uint_t                          flags;
    ngx_event_t                         reset_evt;

    AVFrame                            *frame;

    /* input */
    AVCodecContext                     *in_codec_ctx;
    AVCodec                            *in_codec;

    /* output */
    AVOutputFormat                     *out_format;
    AVFormatContext                    *out_format_ctx;
    AVStream                           *out_stream;
    AVCodec                            *out_codec;
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


static void 
ngx_rtmp_hls_reset(ngx_event_t *hev)
{
    ngx_connection_t               *c;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_hls_app_conf_t        *hacf;

    c = hev->data;
    s = c->data;
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    /*TODO: move current fragment */

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
    } else{
        ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));
    }

    ctx->frame = avcodec_alloc_frame();
    if (ctx->frame == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_alloc_frame failed");
        goto cleanup;
    }

    /* input */
    ctx->in_codec = avcodec_find_decoder_by_name("flv"); /*TODO*/
    if (ctx->in_codec == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_find_decoder_by_name failed");
        goto cleanup;
    }
    
    ctx->in_codec_ctx = avcodec_alloc_context3(ctx->in_codec);
    if (ctx->in_codec_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_alloc_context3 failed");
        goto cleanup;
    }

    if (avcodec_open2(ctx->in_codec_ctx, ctx->in_codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed: %p", ctx->in_codec);
        goto cleanup;
    }

    /* output */
    ctx->out_format = av_guess_format("mpegts", NULL, NULL);
    if (ctx->out_format == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_guess_format failed");
        goto cleanup;
    }
    ctx->out_format_ctx = avformat_alloc_context();
    if (ctx->out_format_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avformat_alloc_context failed");
        goto cleanup;
    }
    ctx->out_format_ctx->oformat = ctx->out_format;

    /* add stream */
    ctx->out_codec = avcodec_find_encoder_by_name("mpeg2video");
    if (ctx->out_codec == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_find_encoder_by_name failed");
        goto cleanup;
    }
    ctx->out_stream = avformat_new_stream(ctx->out_format_ctx, ctx->out_codec);
    if (ctx->out_stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed");
        goto cleanup;
    }

    /*TODO: set good values */
    ctx->out_stream->codec->codec_id = CODEC_ID_NONE;
    ctx->out_stream->codec->codec_type = AVMEDIA_TYPE_UNKNOWN;
    ctx->out_stream->codec->pix_fmt = PIX_FMT_YUV420P;
    ctx->out_stream->codec->frame_number = 0;
    ctx->out_stream->codec->gop_size = 12;
    ctx->out_stream->codec->max_b_frames = 2;
    ctx->out_stream->codec->time_base.den = 25;
    ctx->out_stream->codec->time_base.num = 1;
    ctx->out_stream->codec->width  = 256;
    ctx->out_stream->codec->height = 256;
    ctx->out_stream->codec->bit_rate = 2000000;

    if (avcodec_open2(ctx->out_stream->codec, ctx->out_codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed");
        goto cleanup;
    }
    if (avio_open(&ctx->out_format_ctx->pb, "/tmp/frag.ts", 
                AVIO_FLAG_WRITE) < 0) 
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avoi_open failed");
        goto cleanup;
    }
    if (avcodec_open2(ctx->out_stream->codec, ctx->out_codec, NULL) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_open2 failed");
        goto cleanup;
    }

    avformat_write_header(ctx->out_format_ctx, NULL);

    ctx->flags |= NGX_RTMP_HLS_PUBLISHING;
    e = &ctx->reset_evt;
    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_hls_reset;
    ngx_add_timer(e, hacf->fraglen);

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
    if (ctx->reset_evt.timer_set) {
        ngx_del_timer(&ctx->reset_evt);
    }

    /* delete HLS stream */
    av_write_trailer(ctx->out_format_ctx);

    avio_close(ctx->out_format_ctx->pb);

    /*TODO: a lot of free's here */

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_hls_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    AVPacket                        in_packet;
    AVPacket                        out_packet;
    int                             got_frame, n;
    u_char                         *p;
    size_t                          size, space;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls || ctx == NULL 
                     || (ctx->flags & NGX_RTMP_HLS_PUBLISHING) == 0) 
    {
        return NGX_OK;
    }

    if (h->type != NGX_RTMP_MSG_VIDEO || h->mlen <= 1) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: av: len='%D'", h->mlen);

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
    av_init_packet(&in_packet);
    in_packet.data = ngx_rtmp_hls_in_buffer + 1;
    in_packet.size = p - ngx_rtmp_hls_in_buffer - 1;
    in_packet.dts  = h->timestamp;

    /* decode input frame */
    got_frame = 0;
    n = avcodec_decode_video2(ctx->in_codec_ctx, ctx->frame, 
                              &got_frame, &in_packet);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_decode_video2 failed");
        goto done;
    }
    if (in->buf->pos == in->buf->last) {
        in = in->next;
    }
    if (!got_frame) {
        goto done;
    }

    /* prepare output frame */
    av_init_packet(&out_packet);
    out_packet.stream_index = ctx->out_stream->index;
    out_packet.data = ngx_rtmp_hls_out_buffer;
    out_packet.size = sizeof(ngx_rtmp_hls_out_buffer);

    /* encode frame */
    got_frame = 0;
    n = avcodec_encode_video2(ctx->out_stream->codec, &out_packet,
            ctx->frame, &got_frame);
    if (n < 0)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avcodec_encode_video2 failed");
        goto done;
    }

    if (!got_frame) {
        goto done;
    }

    /* write output frame */
    n = av_interleaved_write_frame(ctx->out_format_ctx, 
            &out_packet);
    if (n < 0) {
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
    if (h == NULL) {
        return NGX_ERROR;
    }
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

