/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>


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


#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)

#define NGX_RTMP_HLS_DIR_ACCESS         0744


typedef struct {
    ngx_uint_t                          flags;
    ngx_msec_t                          frag_start;

    unsigned                            publishing:1;
    unsigned                            opened:1;
    unsigned                            audio:1;
    unsigned                            video:1;
    unsigned                            header_sent:1;

    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           name;

    ngx_int_t                           frag;

    ngx_int_t                           out_vstream;
    ngx_int_t                           out_astream;
    int8_t                              nal_bytes;

    int64_t                             aframe_base;
    int64_t                             aframe_num;

    AVFormatContext                    *out_format;

} ngx_rtmp_hls_ctx_t;


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          muxdelay;
    ngx_msec_t                          sync;
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

    { ngx_string("hls_muxdelay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, muxdelay),
      NULL },

    { ngx_string("hls_sync"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, sync),
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
#if 0
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
#endif

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


static size_t
ngx_rtmp_hls_chain2buffer(u_char *buffer, size_t size, ngx_chain_t *in, 
        size_t skip)
{
    ngx_buf_t                       out;

    out.pos  = buffer;
    out.last = buffer + size - FF_INPUT_BUFFER_PADDING_SIZE;

    for (; in; in = in->next) {
        size = in->buf->last - in->buf->pos;
        if (size < skip) {
            skip -= size;
            continue;
        }
        out.pos = ngx_cpymem(out.pos, in->buf->pos + skip, ngx_min(
                    size - skip, (size_t)(out.last - out.pos)));
        skip = 0;
    }

    return out.pos - buffer;
}


static ngx_int_t
ngx_rtmp_hls_init_video(ngx_rtmp_session_t *s)
{
    AVStream                       *stream;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL 
            || codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264
            || ctx->video == 1
            || ctx->out_format == NULL)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: adding video stream");

    stream = avformat_new_stream(ctx->out_format, NULL);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed (video)");
        return NGX_ERROR;
    }

    stream->codec->codec_id = CODEC_ID_H264;
    stream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codec->pix_fmt = PIX_FMT_YUV420P;
    stream->codec->time_base.den = 25;
    stream->codec->time_base.num = 1;
    stream->codec->width  = 100;
    stream->codec->height = 100;

    if (ctx->out_format->oformat->flags & AVFMT_GLOBALHEADER) {
        stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
    }

    ctx->out_vstream = stream->index;
    ctx->video = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: video stream: %i", ctx->out_vstream);

    if (ctx->header_sent) {
        if (av_write_trailer(ctx->out_format) < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: av_write_trailer failed");
        }
        ctx->header_sent = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_init_audio(ngx_rtmp_session_t *s)
{
    AVStream                       *stream;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    enum CodecID                    cid;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL || ctx->audio == 1 || ctx->out_format == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: adding audio stream");

    cid = ngx_rtmp_hls_get_audio_codec(codec_ctx->audio_codec_id);
    if (cid == CODEC_ID_NONE) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: no audio");
        return NGX_OK;
    }

    stream = avformat_new_stream(ctx->out_format, NULL);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_new_stream failed (audio)");
        return NGX_ERROR;
    }

    stream->codec->codec_id = cid;
    stream->codec->codec_type = AVMEDIA_TYPE_AUDIO;
    stream->codec->sample_fmt = (codec_ctx->sample_size == 1 ?
            AV_SAMPLE_FMT_U8 : AV_SAMPLE_FMT_S16);
    stream->codec->sample_rate = 48000;/*codec_ctx->sample_rate;*/
    stream->codec->bit_rate = 2000000;
    stream->codec->channels = codec_ctx->audio_channels;

    ctx->out_astream = stream->index;
    ctx->audio = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: audio stream: %i %iHz", 
            ctx->out_astream, codec_ctx->sample_rate);

    if (ctx->header_sent) {
        if (av_write_trailer(ctx->out_format) < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: av_write_trailer failed");
        }
        ctx->header_sent = 0;
    }

    return NGX_OK;
}


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
    ngx_int_t                       nretry;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    nretry = 0;

retry:
    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY, 
            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                "hls: open failed: '%V'", 
                &ctx->playlist_bak);
        /* try to create parent folder */
        if (nretry == 0 && 
            ngx_create_dir(hacf->path.data, NGX_RTMP_HLS_DIR_ACCESS) != 
            NGX_INVALID_FILE)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "hls: creating target folder: '%V'", &hacf->path);
            ++nretry;
            goto retry;
        }
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
                "#EXTINF:%i,\r\n"
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
ngx_rtmp_hls_initialize(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_hls_app_conf_t        *hacf;
    AVOutputFormat                 *format;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL || ctx->out_format || ctx->publishing == 0) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: initialize stream");

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
    ctx->out_format->max_delay = (int64_t)hacf->muxdelay * AV_TIME_BASE / 1000;

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_hls_open_file(ngx_rtmp_session_t *s, u_char *fpath)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    AVStream                       *astream;
    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL || ctx->out_format == NULL) {
        return NGX_OK;
    }

    if (!ctx->video && !ctx->audio) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: open stream file '%s'", fpath);

    /* open file */
    if (avio_open(&ctx->out_format->pb, (char *)fpath, AVIO_FLAG_WRITE) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_open failed");
        return NGX_ERROR;
    }

    astream = NULL;
    if (codec_ctx && codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC
            && codec_ctx->aac_header && codec_ctx->aac_header->buf->last -
                codec_ctx->aac_header->buf->pos > 2
            && ctx->audio)
    {
        astream = ctx->out_format->streams[ctx->out_astream];
        astream->codec->extradata = buffer;
        astream->codec->extradata_size = ngx_rtmp_hls_chain2buffer(buffer, 
                sizeof(buffer), codec_ctx->aac_header, 2);
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: setting AAC extradata %i bytes", 
            (ngx_int_t)astream->codec->extradata_size);
    }

    /* write header */
    if (!ctx->header_sent &&
        avformat_write_header(ctx->out_format, NULL) < 0) 
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avformat_write_header failed");
        return NGX_ERROR;
    }
    ctx->header_sent = 1;

    if (astream) {
        astream->codec->extradata = NULL;
        astream->codec->extradata_size = 0;
    }

    ctx->opened = 1;
    ctx->nal_bytes = -1;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n, 
        ngx_chain_t **in)
{
    u_char     *last;
    size_t      pn;

    if (*in == NULL) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        last = (*in)->buf->last;
        if ((size_t)(last - *src) >= n) {
            if (dst) {
                ngx_memcpy(dst, *src, n);
            }
            *src += n;
            while (*in && *src == (*in)->buf->last) {
                *in = (*in)->next;
                if (*in) {
                    *src = (*in)->buf->pos;
                }
            }
            return NGX_OK;
        }

        pn = last - *src;
        if (dst) {
            ngx_memcpy(dst, *src, pn);
            dst = (u_char *)dst + pn;
        }
        n -= pn;
        *in = (*in)->next;
        if (*in == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: failed to read %uz byte(s)", n);
            return NGX_ERROR;
        }
        *src = (*in)->buf->pos;
    }
}


static ngx_int_t
ngx_rtmp_hls_append_avc_header(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    u_char                         *p;
    ngx_chain_t                    *in;
    ngx_rtmp_hls_ctx_t             *ctx;
    int8_t                          nnals;
    uint16_t                        len, rlen;
    ngx_int_t                       n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL || codec_ctx == NULL) {
        return NGX_ERROR;
    }


    in = codec_ctx->avc_header;

    if (in == NULL) {
        return NGX_ERROR;
    }
    p = in->buf->pos;

    /* skip bytes:
     * - flv fmt
     * - H264 CONF/PICT (0x00)
     * - 0
     * - 0
     * - 0
     * - version
     * - profile
     * - compatibility
     * - level */
    if (ngx_rtmp_hls_copy(s, NULL, &p, 9, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* NAL size length (1,2,4) */
    if (ngx_rtmp_hls_copy(s, &ctx->nal_bytes, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->nal_bytes &= 0x03; /* 2 lsb */
    ++ctx->nal_bytes;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: NAL size bytes: %uz", ctx->nal_bytes);

    /* number of SPS NALs */
    if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }
    nnals &= 0x1f; /* 5lsb */
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: SPS number: %uz", nnals);

    /* SPS */
    for (n = 0; ; ++n) {
        for (; nnals; --nnals) {
            /* NAL length */
            if (ngx_rtmp_hls_copy(s, &rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_rtmp_rmemcpy(&len, &rlen, 2);
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "hls: header NAL length: %uz", (size_t)len);

            /* AnnexB prefix */
            if (out->last - out->pos < 4) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "hls: too small buffer for header NAL length");
                return NGX_ERROR;
            }
            *out->pos++ = 0;
            *out->pos++ = 0;
            *out->pos++ = 0;
            *out->pos++ = 1;

            /* NAL body */
            if (out->last - out->pos < len) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "hls: too small buffer for header NAL");
                return NGX_ERROR;
            }
            if (ngx_rtmp_hls_copy(s, out->pos, &p, len, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            out->pos += len;
        }

        if (n == 1) {
            break;
        }

        /* number of PPS NALs */
        if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: PPS number: %uz", nnals);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_close_file(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t     *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    /*
    if (av_write_trailer(ctx->out_format) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_write_trailer failed");
    }*/

    avio_flush(ctx->out_format->pb);

    if (avio_close(ctx->out_format->pb) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: avio_close failed");
    }

    ctx->opened = 0;

    return NGX_OK;
}


static void 
ngx_rtmp_hls_restart(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (ctx == NULL || hacf == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: restart frag=%i", ctx->frag);

    if (ctx->opened) {
        ngx_rtmp_hls_close_file(s);
    }

    if (ngx_rtmp_hls_initialize(s) != NGX_OK) {
        return;
    }

    if (ngx_rtmp_hls_init_video(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: video init failed");
    }

    if (ngx_rtmp_hls_init_audio(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: audio init failed");
    }

    /* remember we have preallocated memory in ctx->stream */

    /* erase old file;
     * we should keep old fragments available
     * whole next cycle */
    if (ctx->frag > (ngx_int_t)hacf->nfrags * 2) {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%i.ts", 
                ctx->frag - hacf->nfrags * 2) = 0;
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: delete stream file '%s'", ctx->stream.data);
        ngx_delete_file(ctx->stream.data);
    }

    ++ctx->frag;
    ctx->frag_start = ngx_current_msec;

    /* create new one */
    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%i.ts", 
            ctx->frag) = 0;
    ngx_rtmp_hls_open_file(s, ctx->stream.data);

    /* update playlist */
    ngx_rtmp_hls_update_playlist(s);
}


static ngx_int_t
ngx_rtmp_hls_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    size_t                          len;
    u_char                         *p;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL || !hacf->hls || hacf->path.len == 0) {
        goto next;
    }

    if (s->auto_pushed) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: publish: name='%s' type='%s'",
            v->name, v->type);

    /* create context */
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    }
    ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));

    /* init names & paths */
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

    /* schedule restart event */
    ctx->publishing = 1;
    ctx->frag_start = ngx_current_msec - hacf->fraglen - 1;

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
            || ctx->publishing == 0)
    {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: delete");

    ctx->publishing = 0;

    if (ctx->out_format == NULL) {
        goto next;
    }

    if (ctx->opened) {
        ngx_rtmp_hls_close_file(s);
    }

    if (ctx->out_format) {
        avformat_free_context(ctx->out_format);
        ctx->out_format = NULL;
    }

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_hls_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    AVPacket                        packet;
    int64_t                         dts, ddts;
    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (hacf == NULL || !hacf->hls || ctx == NULL || codec_ctx == NULL  ||
            h->mlen < 1) 
    {
        return NGX_OK;
    }

    /* fragment is restarted in video handler;
     * however if video stream is missing then do it here */
    if (ctx->video == 0
            && ngx_current_msec - ctx->frag_start > hacf->fraglen) 
    {
        ngx_rtmp_hls_restart(s);
    }

    if (!ctx->opened || !ctx->audio) {
        return NGX_OK;
    }

    /* write to file */
    av_init_packet(&packet);
    packet.dts = h->timestamp * 90L;
    packet.stream_index = ctx->out_astream;
    packet.data = buffer;
    packet.size = ngx_rtmp_hls_chain2buffer(buffer, sizeof(buffer), in, 1);

    if (hacf->sync && codec_ctx->sample_rate) {
        
        /* TODO: We assume here AAC frame size is 1024
         *       Need to handle AAC frames with frame size of 960 */

        dts = ctx->aframe_base + ctx->aframe_num * 90000 * 1024 /
                                 codec_ctx->sample_rate;
        ddts = dts - packet.dts;

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: sync stat ddts=%L (%.5fs)",
                       ddts, ddts / 90000.);

        if (ddts > (int64_t) hacf->sync * 90 ||
            ddts < (int64_t) hacf->sync * -90)
        {
            ctx->aframe_base = packet.dts;
            ctx->aframe_num  = 0;

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: sync breakup ddts=%L (%.5fs)",
                           ddts, ddts / 90000.);
        } else {
            packet.dts = dts;
        }

        ctx->aframe_num++;
    }

    packet.pts = packet.dts;

    if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC) {
        if (packet.size == 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: malformed AAC packet");
            return NGX_OK;
        }
        ++packet.data;
        --packet.size;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: audio buffer %uD", *(uint32_t*)packet.data);

    if (av_interleaved_write_frame(ctx->out_format, &packet) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_interleaved_write_frame failed");
    }
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    AVPacket                        packet;
    u_char                         *p;
    uint8_t                         fmt, ftype, htype, llen;
    uint32_t                        len, rlen;
    ngx_buf_t                       out;
    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];
    int32_t                         cts;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (hacf == NULL || !hacf->hls || ctx == NULL || codec_ctx == NULL 
            || h->mlen < 1)
    {
        return NGX_OK;
    }

    /* Only H264 is supported */
    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_rtmp_hls_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame */
    ftype = (fmt & 0xf0) >> 4;

    /* H264 HDR/PICT */
    if (ngx_rtmp_hls_copy(s, &htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }
    /* proceed only with PICT */
    if (htype != 1) {
        return NGX_OK;
    }
    
    /* 3 bytes: decoder delay */
    if (ngx_rtmp_hls_copy(s, &cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }
    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) 
        | (cts & 0x0000FF00);

    out.pos = buffer;
    out.last = buffer + sizeof(buffer) - FF_INPUT_BUFFER_PADDING_SIZE;
    
    /* keyframe? */
    if (ftype == 1) {
        if (ngx_current_msec - ctx->frag_start > hacf->fraglen) {
            ngx_rtmp_hls_restart(s);
        }

        /* Prepend IDR frame with H264 header for random seeks */
        if (ngx_rtmp_hls_append_avc_header(s, &out) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: error appenging H264 header");
        }
    }

    if (!ctx->opened || !ctx->video) {
        return NGX_OK;
    }

    if (ctx->nal_bytes == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: nal length size is unknown, "
                "waiting for IDR to parse header");
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "hls: parsing NALs");

    while (in) {
        llen = ctx->nal_bytes;
        if (ngx_rtmp_hls_copy(s, &rlen, &p, llen, &in) != NGX_OK) {
            return NGX_OK;
        }
        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, llen);

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "hls: NAL type=%i llen=%i len=%uD unit_type=%i",
                (ngx_int_t)ftype, (ngx_int_t)llen, len, (ngx_int_t)(*p & 0x1f));

        /* AnnexB prefix */
        if (out.last - out.pos < 4) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: not enough buffer for AnnexB prefix");
            return NGX_OK;
        }

        /* first AnnexB prefix is long (4 bytes) */
        if (out.pos == buffer) {
            *out.pos++ = 0;
        }
        *out.pos++ = 0;
        *out.pos++ = 0;
        *out.pos++ = 1;

        /* NAL body */
        if (out.last - out.pos < (ngx_int_t) len) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls: not enough buffer for NAL");
            return NGX_OK;
        }
        if (ngx_rtmp_hls_copy(s, out.pos, &p, len, &in) != NGX_OK) {
            return NGX_ERROR;
        }
        out.pos += len;
    }

    av_init_packet(&packet);
    packet.dts = h->timestamp * 90L;
    packet.pts = packet.dts + cts * 90;
    packet.stream_index = ctx->out_vstream;

    if (ftype == 1) {
        packet.flags |= AV_PKT_FLAG_KEY;
    }

    packet.data = buffer;
    packet.size = out.pos - buffer;

    if (av_interleaved_write_frame(ctx->out_format, &packet) < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "hls: av_interleaved_write_frame failed");
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
    conf->muxdelay = NGX_CONF_UNSET;
    conf->sync = NGX_CONF_UNSET;
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
    ngx_conf_merge_msec_value(conf->muxdelay, prev->muxdelay, 700);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 0);
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
    *h = ngx_rtmp_hls_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hls_audio;

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

