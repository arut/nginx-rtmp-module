

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_mp4.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static ngx_int_t ngx_rtmp_dash_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_dash_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_dash_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_DASH_BUFSIZE            (1024*1024)
#define NGX_RTMP_DASH_DIR_ACCESS         0744
#define NGX_RTMP_DASH_MAX_SIZE           (800*1024)
#define NGX_RTMP_DASH_MAX_SAMPLES        512


typedef struct {
    ngx_uint_t                          video_earliest_pres_time;
    ngx_uint_t                          video_latest_pres_time;
    ngx_uint_t                          audio_earliest_pres_time;
    ngx_uint_t                          audio_latest_pres_time;
    unsigned                            SAP:1;
    uint32_t                            id;
} ngx_rtmp_dash_frag_t;


typedef struct {
    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           name;
    ngx_str_t                           stream;
    ngx_str_t                           start_time;

    unsigned                            opened:1;
    unsigned                            video:1;
    unsigned                            audio:1;

    ngx_file_t                          video_file;
    ngx_file_t                          audio_file;

    uint32_t                            frag;
    uint32_t                            nfrags;
    ngx_rtmp_dash_frag_t               *frags;

    ngx_buf_t                          *buffer;

    ngx_uint_t                          video_mdat_size;
    uint32_t                            video_sample_count;
    uint32_t                            video_sample_sizes[NGX_RTMP_DASH_MAX_SAMPLES];
    ngx_str_t                           video_fragment;

    ngx_uint_t                          audio_mdat_size;
    uint32_t                            audio_sample_count;
    uint32_t                            audio_sample_sizes[NGX_RTMP_DASH_MAX_SAMPLES];
    ngx_str_t                           audio_fragment;
} ngx_rtmp_dash_ctx_t;


typedef struct {
    ngx_str_t                           path;
    ngx_msec_t                          playlen;
} ngx_rtmp_dash_cleanup_t;


typedef struct {
    ngx_flag_t                          dash;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          playlen;
    ngx_str_t                           path;
    ngx_uint_t                          winfrags;
    ngx_flag_t                          cleanup;
    ngx_path_t                         *slot;
} ngx_rtmp_dash_app_conf_t;


static ngx_command_t ngx_rtmp_dash_commands[] = {

    { ngx_string("dash"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_dash_app_conf_t, dash),
      NULL },

    { ngx_string("dash_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_dash_app_conf_t, fraglen),
      NULL },

    { ngx_string("dash_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_dash_app_conf_t, path),
      NULL },

    { ngx_string("dash_playlist_length"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_dash_app_conf_t, playlen),
      NULL },

    { ngx_string("dash_cleanup"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_dash_app_conf_t, cleanup),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_dash_module_ctx = {
  NULL,                               /* preconfiguration */
  ngx_rtmp_dash_postconfiguration,    /* postconfiguration */

  NULL,                               /* create main configuration */
  NULL,                               /* init main configuration */

  NULL,                               /* create server configuration */
  NULL,                               /* merge server configuration */

  ngx_rtmp_dash_create_app_conf,      /* create location configuration */
  ngx_rtmp_dash_merge_app_conf,       /* merge location configuration */
};


ngx_module_t  ngx_rtmp_dash_module = {
  NGX_MODULE_V1,
  &ngx_rtmp_dash_module_ctx,          /* module context */
  ngx_rtmp_dash_commands,             /* module directives */
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


static ngx_rtmp_dash_frag_t *
ngx_rtmp_dash_get_frag(ngx_rtmp_session_t *s, ngx_int_t n)
{
    ngx_rtmp_dash_ctx_t         *ctx;
    ngx_rtmp_dash_app_conf_t    *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    return &ctx->frags[(ctx->frag + n) % (hacf->winfrags * 2 + 1)];
}


static ngx_int_t
ngx_rtmp_dash_rename_file(u_char *src, u_char *dst)
{
    /* rename file with overwrite */

#if (NGX_WIN32)
    return MoveFileEx((LPCTSTR) src, (LPCTSTR) dst, MOVEFILE_REPLACE_EXISTING);
#else
    return ngx_rename_file(src, dst);
#endif
}


static ngx_int_t
ngx_rtmp_dash_write_playlist(ngx_rtmp_session_t *s)
{
    static u_char                   buffer[2048];
    int                             fd;
    u_char                         *p;
    ngx_rtmp_dash_app_conf_t       *hacf;
    ngx_rtmp_dash_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_live_ctx_t            *live_ctx;
    ssize_t                         n;
    ngx_str_t                       playlist, playlist_bak;
    ngx_rtmp_dash_frag_t           *f;
    uint32_t                        audio_dur;
    
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    live_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (hacf == NULL || ctx == NULL || codec_ctx == NULL || 
              live_ctx == NULL || live_ctx->stream == NULL) {
        return NGX_ERROR;
    }

    /* done playlists */

    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY, 
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: open failed: '%V'", &ctx->playlist_bak);

        return NGX_ERROR;
    }

#define NGX_RTMP_DASH_MANIFEST_HEADER                                           \
    "<?xml version=\"1.0\"?>\n"                                                 \
    "<MPD type=\"dynamic\" xmlns=\"urn:mpeg:dash:schema:mpd:2011\" "            \
    "minimumUpdatePeriod=\"PT30M0S\" availabilityStartTime=\"%V\" "             \
    "minBufferTime=\"PT3S\" mediaPresentationDuration=\"PT0H0M0.00S\" "         \
    "profiles=\"urn:mpeg:dash:profile:isoff-live:2011\">\n"                     \
    " <Period start=\"PT0S\" id=\"dash\" duration=\"PT0H0M0.00S\">\n"
#define NGX_RTMP_DASH_MANIFEST_VIDEO                                            \
    "  <AdaptationSet segmentAlignment=\"true\" maxWidth=\"%uL\" "              \
    "maxHeight=\"%uL\" maxFrameRate=\"%uL\">\n"                                 \
    "   <Representation id=\"video\" mimeType=\"video/mp4\" "                   \
    "codecs=\"avc1.42c028\" width=\"%uL\" height=\"%uL\" frameRate=\"%uL\" "    \
    "sar=\"1:1\" startWithSAP=\"1\" bandwidth=\"%uL\">\n"                       \
    "     <SegmentTemplate presentationTimeOffset=\"%uL\" timescale=\"1000\" "  \
    "duration=\"%uL\" media=\"%V-$Number$.m4v\" startNumber=\"0\" "             \
    "initialization=\"%V-init-video.dash\"/>\n"                                 \
    "   </Representation>\n"                                                    \
    "  </AdaptationSet>\n"
#define NGX_RTMP_DASH_MANIFEST_AUDIO                                            \
    "  <AdaptationSet segmentAlignment=\"true\">\n"\
    "   <AudioChannelConfiguration "                                            \
    "schemeIdUri=\"urn:mpeg:dash:23003:3:audio_channel_configuration:2011\" "   \
    "value=\"1\"/>\n"                                                           \
    "   <Representation id=\"audio\" mimeType=\"audio/mp4\" "                   \
    "codecs=\"mp4a.40.2\" audioSamplingRate=\"%uL\" startWithSAP=\"1\" "        \
    "bandwidth=\"130685\">\n"                                                   \
    "     <SegmentTemplate presentationTimeOffset=\"%uL\" timescale=\"%uL\" "   \
    "duration=\"%uL\" media=\"%V-$Number$.m4a\" startNumber=\"0\" "             \
    "initialization=\"%V-init-audio.dash\"/>\n"                                 \
    "   </Representation>\n"                                                    \
    "  </AdaptationSet>\n"
#define NGX_RTMP_DASH_MANIFEST_FOOTER                                           \
    " </Period>\n"                                                              \
    "</MPD>\n"

    f = ngx_rtmp_dash_get_frag(s, hacf->winfrags/2);

    audio_dur = f->id > 0 ? (uint32_t)(codec_ctx->sample_rate * 
                      ((float)(f->video_latest_pres_time/f->id)/1000.0)) : 
                      (uint32_t)(codec_ctx->sample_rate*(hacf->fraglen/1000));

    p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_DASH_MANIFEST_HEADER,
                                                     &ctx->start_time);
    n = ngx_write_fd(fd, buffer, p - buffer);

    if (ctx->video) {
        p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_DASH_MANIFEST_VIDEO, 
                         codec_ctx->width, 
                         codec_ctx->height,
                         codec_ctx->frame_rate, 
                         codec_ctx->width, 
                         codec_ctx->height,
                         codec_ctx->frame_rate, 
                         (uint32_t)(live_ctx->stream->bw_in.bandwidth*8), 
                         f->video_earliest_pres_time,
                         f->id > 0 ? (uint32_t)(f->video_latest_pres_time / 
                                      f->id) : hacf->fraglen, 
                         &ctx->name, 
                         &ctx->name);
        n = ngx_write_fd(fd, buffer, p - buffer);      
    }

    if (ctx->audio) {
        p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_DASH_MANIFEST_AUDIO, 
                         codec_ctx->sample_rate, 
                         (uint32_t)(f->audio_earliest_pres_time * 
                          ((float)codec_ctx->sample_rate/1000.0)),
                         codec_ctx->sample_rate,
                         audio_dur, 
                         &ctx->name, 
                         &ctx->name);
        n = ngx_write_fd(fd, buffer, p - buffer);
    }

    p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_DASH_MANIFEST_FOOTER);
    n = ngx_write_fd(fd, buffer, p - buffer);
    
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: write failed: '%V'", &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_close_file(fd);

    if (ngx_rename_file(ctx->playlist_bak.data, ctx->playlist.data)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: rename failed: '%V'->'%V'", 
                      &playlist_bak, &playlist);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_dash_write_init_segments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    int                             rc;
    ngx_file_t                      file;
    static u_char                   path[1024];
    ngx_buf_t                      *b;
    ngx_rtmp_mp4_metadata_t         metadata;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (!ctx || !codec_ctx) {
        return NGX_ERROR;
    }

    ngx_memzero(&path, sizeof(path));
    ngx_str_set(&file.name, "dash-init-video");
    ngx_snprintf(path, sizeof(path), "%Vinit-video.dash",&ctx->stream);

    file.fd = ngx_open_file(path, NGX_FILE_RDWR,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating video init file");
        return NGX_ERROR;
    }

    file.log = s->connection->log;

    b = ngx_pcalloc(s->connection->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->start = ngx_palloc(s->connection->pool, 1024);
    if (b->start == NULL) {
        return NGX_ERROR;
    }
    
    b->end = b->start + 1024;
    b->pos = b->last = b->start;

    metadata.width = codec_ctx->width;
    metadata.height = codec_ctx->height;
    metadata.audio = 0;
    metadata.video = 1;
    metadata.sample_rate = codec_ctx->sample_rate;
    metadata.frame_rate = codec_ctx->frame_rate;

    ngx_rtmp_mp4_write_ftyp(b, NGX_RTMP_MP4_FILETYPE_INIT, metadata); 
    ngx_rtmp_mp4_write_moov(s, b, metadata);
    rc = ngx_write_file(&file, b->start, b->last-b->start, 0); 
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: writing video init failed");
    }
    ngx_close_file(file.fd);

    ngx_memzero(&path, sizeof(path));
    ngx_snprintf(path, sizeof(path), "%Vinit-audio.dash",&ctx->stream);

    file.fd = ngx_open_file(path, NGX_FILE_RDWR,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating dash audio init file");
        return NGX_ERROR;
    }

    file.log = s->connection->log;
    b->pos = b->last = b->start;

    metadata.video = 0;
    metadata.audio = 1;
    ngx_rtmp_mp4_write_ftyp(b, NGX_RTMP_MP4_FILETYPE_INIT, metadata); 
    ngx_rtmp_mp4_write_moov(s, b, metadata);
    rc = ngx_write_file(&file, b->start, b->last-b->start, 0); 
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: writing video init failed");
    }
    ngx_close_file(file.fd);

    ctx->buffer = b;

    return NGX_OK; 
}


static ngx_int_t
ngx_rtmp_dash_rewrite_segments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_buf_t                      *b, file_b;
    ssize_t                         written = 0, size, write_size;
    ngx_file_t                      file;
    ngx_int_t                       rc;
    ngx_rtmp_mp4_metadata_t         metadata;
    u_char                         *pos, *pos1;
    ngx_rtmp_dash_frag_t           *f;

    static u_char                   buffer[4096];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (!ctx->opened) {
        return NGX_OK;
    }

    b = ctx->buffer;

    f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);

    /* rewrite video segment */
    ngx_memzero(&buffer, sizeof(buffer));
    file_b.start = buffer;
    file_b.end = file_b.start + sizeof(buffer);
    file_b.pos = file_b.start;
    file_b.last = file_b.pos;

    b->pos = b->last = b->start;

    ngx_rtmp_mp4_write_ftyp(b, NGX_RTMP_MP4_FILETYPE_SEG, metadata); 
    pos = b->last;
    b->last += 44; /* leave room for sidx */
    ngx_rtmp_mp4_write_moof(b, f->video_earliest_pres_time, 
                            ctx->video_sample_count, ctx->video_sample_sizes,
                            (ctx->nfrags+ctx->frag),0);
    pos1 = b->last;
    b->last = pos;
    ngx_rtmp_mp4_write_sidx(s, b, ctx->video_mdat_size+8+(pos1-(pos+44)), 
                            f->video_earliest_pres_time, 
                            f->video_latest_pres_time,0);
    b->last = pos1;
    ngx_rtmp_mp4_write_mdat(b, ctx->video_mdat_size+8);

    /* move the data down to make room for the headers */
    size = (ssize_t) ctx->video_mdat_size;

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "v-temp") = 0;

    ngx_memzero(&file, sizeof(file));
    file.log = s->connection->log;
    file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating dash temp video file");
        return NGX_ERROR;
    }

    ngx_str_set(&file.name, "temp");

    ctx->video_file.offset = 0;
    ngx_rtmp_mp4_write_data(s, &file, b);
    do {
        file_b.pos = file_b.last = file_b.start;
        if ((ssize_t)(written + sizeof(buffer)) > size) {
            ngx_read_file(&ctx->video_file, file_b.start, size-written, 
                          ctx->video_file.offset);
            file_b.last += size-written;
        }
        else {
            ngx_read_file(&ctx->video_file, file_b.start, sizeof(buffer), 
                          ctx->video_file.offset);
            file_b.last += sizeof(buffer);
        }
        write_size = ngx_rtmp_mp4_write_data(s, &file, &file_b);
        if (write_size == 0) {
            break;
        }
        written += write_size;
    } while (written < size);

    ngx_close_file(ctx->video_file.fd);
    ngx_close_file(file.fd);
    rc = ngx_rtmp_dash_rename_file(ctx->stream.data, ctx->video_fragment.data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: rename failed: '%s'->'%s'",ctx->stream.data, 
                      ctx->video_fragment.data);
        return NGX_ERROR;
    }

    /* rewrite audio segment */
    written = 0;
    ngx_memzero(&buffer, sizeof(buffer));
    file_b.pos = file_b.last = file_b.start;
    b->pos = b->last = b->start;
    ngx_rtmp_mp4_write_ftyp(b, NGX_RTMP_MP4_FILETYPE_SEG, metadata); 
    pos = b->last;
    b->last += 44; /* leave room for sidx */
    ngx_rtmp_mp4_write_moof(b, f->audio_earliest_pres_time, 
                            ctx->audio_sample_count, ctx->audio_sample_sizes, 
                            (ctx->nfrags+ctx->frag), codec_ctx->sample_rate);
    pos1 = b->last;
    b->last = pos;
    ngx_rtmp_mp4_write_sidx(s, b, ctx->audio_mdat_size+8+(pos1-(pos+44)), 
                            f->audio_earliest_pres_time, 
                            f->audio_latest_pres_time, codec_ctx->sample_rate);
    b->last = pos1;
    ngx_rtmp_mp4_write_mdat(b, ctx->audio_mdat_size+8);

    /* move the data down to make room for the headers */
    size = (ssize_t) ctx->audio_mdat_size;

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "a-temp") = 0;

    ngx_memzero(&file, sizeof(file));
    file.log = s->connection->log;
    file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating temp audio file");
        return NGX_ERROR;
    }

    ngx_str_set(&file.name, "temp");

    ctx->audio_file.offset = 0;
    ngx_rtmp_mp4_write_data(s, &file, b);
    do {
        file_b.pos = file_b.last = file_b.start;
        if ((ssize_t)(written + sizeof(buffer)) > size) {
            ngx_read_file(&ctx->audio_file, file_b.start, size-written, 
                          ctx->audio_file.offset);
            file_b.last += size-written;
        }
        else {
            ngx_read_file(&ctx->audio_file, file_b.start, sizeof(buffer), 
                          ctx->audio_file.offset);
            file_b.last += sizeof(buffer);
        }
        write_size = ngx_rtmp_mp4_write_data(s, &file, &file_b);
        if (write_size == 0) {
            break;
        }
        written += write_size;
    } while (written < size);

    ngx_close_file(ctx->audio_file.fd);
    ngx_close_file(file.fd);
    rc = ngx_rtmp_dash_rename_file(ctx->stream.data, ctx->audio_fragment.data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: rename failed: '%s'->'%s'",ctx->stream.data, 
                      ctx->audio_fragment.data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_dash_close_fragments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t             *ctx;
    ngx_rtmp_dash_app_conf_t        *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_rtmp_dash_rewrite_segments(s);

    ctx->opened = 0;

    if (ctx->nfrags == hacf->winfrags) {
        ctx->frag++;
    } else {
        ctx->nfrags++;
    }

    ngx_rtmp_dash_write_playlist(s);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_dash_open_fragments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t    *ctx;
    ngx_rtmp_dash_frag_t   *f;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    if (ctx->opened) {
        return NGX_OK;
    }

    f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);
    f->id = (ctx->frag+ctx->nfrags);

    ngx_memzero(&ctx->video_file, sizeof(ctx->video_file));
    ngx_memzero(&ctx->audio_file, sizeof(ctx->audio_file));

    ctx->video_file.log = s->connection->log;
    ctx->audio_file.log = s->connection->log;

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "%uL.m4v", f->id) = 0;
    *ngx_sprintf(ctx->video_fragment.data + ctx->stream.len, "%uL.m4v", 
                 f->id) = 0;

    ngx_str_set(&ctx->video_file.name, "dash-v");
    ctx->video_file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (ctx->video_file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating video fragment file");
        return NGX_ERROR;
    }

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "%uL.m4a", f->id) = 0;
    *ngx_sprintf(ctx->audio_fragment.data + ctx->stream.len, "%uL.m4a", 
                 f->id) = 0;
    ngx_str_set(&ctx->audio_file.name, "dash-a");
    ctx->audio_file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                                      NGX_FILE_TRUNCATE, 
                                      NGX_FILE_DEFAULT_ACCESS);

    if (ctx->audio_file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating audio fragment file");
        return NGX_ERROR;
    }

    ctx->video_sample_count = 0;
    f->video_earliest_pres_time = 0;
    ctx->video_mdat_size = 0; 

    ctx->audio_sample_count = 0;
    f->audio_earliest_pres_time = 0;
    ctx->audio_mdat_size = 0; 

    ctx->opened = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_dash_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_dash_app_conf_t       *hacf;
    ngx_rtmp_dash_ctx_t            *ctx;
    u_char                         *p;
    size_t                          len;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    if (hacf == NULL || !hacf->dash || hacf->path.len == 0) {
        goto next;
    }

    if (s->auto_pushed) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "dash: publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_dash_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_dash_module);

    }

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->connection->pool,
                                 sizeof(ngx_rtmp_dash_frag_t) *
                                 (hacf->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
        ctx->frag = 0;
        ctx->nfrags = 0;
    }

    if (ngx_strstr(v->name, "..")) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "dash: bad stream name: '%s'", v->name);
        return NGX_ERROR;
    }

    ctx->name.len = ngx_strlen(v->name);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len + 1);
    
    if (ctx->name.data == NULL) {
        return NGX_ERROR;
    }

    *ngx_cpymem(ctx->name.data, v->name, ctx->name.len) = 0;

    len = hacf->path.len + 1 + ctx->name.len + sizeof(".mpd");

    ctx->playlist.data = ngx_palloc(s->connection->pool, len);
    p = ngx_cpymem(ctx->playlist.data, hacf->path.data, hacf->path.len);

    if (p[-1] != '/') {
        *p++ = '/';
    }

    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);

    /* ctx->stream_path holds initial part of stream file path 
     * however the space for the whole stream path
     * is allocated */

    ctx->stream.len = p - ctx->playlist.data + 1;
    ctx->stream.data = ngx_palloc(s->connection->pool,
                                  ctx->stream.len + NGX_INT64_LEN +
                                  sizeof(".mp4"));

    ngx_memcpy(ctx->stream.data, ctx->playlist.data, ctx->stream.len - 1);
    ctx->stream.data[ctx->stream.len - 1] = '-';

    ctx->video_fragment.len = p - ctx->playlist.data + 1;
    ctx->video_fragment.data = ngx_palloc(s->connection->pool, 
                                  ctx->video_fragment.len + NGX_INT64_LEN +
                                  sizeof(".m4v"));
    ctx->audio_fragment.len = p - ctx->playlist.data + 1;
    ctx->audio_fragment.data = ngx_palloc(s->connection->pool, 
                                  ctx->audio_fragment.len + NGX_INT64_LEN +
                                  sizeof(".m4a"));

    ngx_memcpy(ctx->video_fragment.data, ctx->playlist.data, 
               ctx->video_fragment.len - 1);
    ctx->video_fragment.data[ctx->video_fragment.len - 1] = '-';
    ngx_memcpy(ctx->audio_fragment.data, ctx->playlist.data, 
               ctx->audio_fragment.len - 1);
    ctx->audio_fragment.data[ctx->audio_fragment.len - 1] = '-';

    /* playlist path */
    p = ngx_cpymem(p, ".mpd", sizeof(".mpd") - 1);

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
                   "dash: playlist='%V' playlist_bak='%V' stream_pattern='%V'",
                   &ctx->playlist, &ctx->playlist_bak, &ctx->stream);

    /* start time for mpd */
    ctx->start_time.data = ngx_palloc(s->connection->pool,
                                  ngx_cached_http_log_iso8601.len);
    ngx_memcpy(ctx->start_time.data, ngx_cached_http_log_iso8601.data,
                                 ngx_cached_http_log_iso8601.len);
    ctx->start_time.len = ngx_cached_http_log_iso8601.len;

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_dash_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_dash_app_conf_t       *hacf;
    ngx_rtmp_dash_ctx_t            *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (hacf == NULL || !hacf->dash || ctx == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "dash: delete stream");

    ngx_rtmp_dash_close_fragments(s);

next:
    return next_close_stream(s, v);
}


static void
ngx_rtmp_dash_update_fragments(ngx_rtmp_session_t *s, ngx_int_t boundary, 
                               uint32_t ts)
{
    ngx_rtmp_dash_ctx_t        *ctx;
    ngx_rtmp_dash_app_conf_t   *hacf;
    int32_t                     duration;
    ngx_rtmp_dash_frag_t       *f;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);

    duration = ctx->video ? (f->video_latest_pres_time - 
                             f->video_earliest_pres_time) :
                             (f->audio_latest_pres_time - 
                             f->audio_earliest_pres_time);

    if ((ctx->video) && ((int32_t)(hacf->fraglen - duration) > 150)) {
        boundary = 0;
    }
    if (!ctx->video && ctx->audio) {
        if ((int32_t)(hacf->fraglen - duration) > 0) {
            boundary = 0;
        }
        else {
            boundary = 1;
        }
    }

    if (ctx->nfrags == 0) {
        ngx_rtmp_dash_write_init_segments(s);
        boundary = 1;
    }

    if (boundary) {
        f->SAP = 1;
    }

    if (ctx->audio_mdat_size >= NGX_RTMP_DASH_MAX_SIZE) {
        boundary = 1;
    }
    if (ctx->video_mdat_size >= NGX_RTMP_DASH_MAX_SIZE) {
        boundary = 1;
    }

    if (boundary) { 
        ngx_rtmp_dash_close_fragments(s);
        ngx_rtmp_dash_open_fragments(s);
    }
}


static ngx_int_t
ngx_rtmp_dash_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_dash_app_conf_t       *hacf;
    ngx_rtmp_dash_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    size_t                          bsize;
    ngx_buf_t                       out;
    ngx_rtmp_dash_frag_t           *f;
    static u_char                   buffer[NGX_RTMP_DASH_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (hacf == NULL || !hacf->dash || ctx == NULL ||
        codec_ctx == NULL  || h->mlen < 2) 
    {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC ||
        codec_ctx->aac_header == NULL)
    {
        return NGX_OK;
    }

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    /* copy payload */

    ctx->audio = 1;

    for (; in && out.last < out.end; in = in->next) {
        bsize = in->buf->last - in->buf->pos;
        if (bsize < 4) {
            continue;
        }
        if (out.last + bsize > out.end) {
            bsize = out.end - out.last;
        }
        if (*in->buf->pos == 0xAF) { /* rtmp frame header */
            /* rtmp audio frame number--skip 0 */
            if (*(in->buf->pos+1) == 0x00) { 
                break;
            }
            else {
                if (bsize > 2) {
                    /* skip two bytes of audio frame header */
                    in->buf->pos += 2; 
                }
            }
        }
        if (!in->next) {
            bsize -= 2; /* chop 2 bytes off the end of the frame */
        }
        out.last = ngx_cpymem(out.last, in->buf->pos, bsize);
    }

    if (out.last-out.pos > 0) {
        ngx_rtmp_dash_update_fragments(s, 0, h->timestamp);

        f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);

        /* Set Presentation Times */
        if (ctx->audio_sample_count == 0 ) {
            f->audio_earliest_pres_time = h->timestamp;
        }
        f->audio_latest_pres_time = h->timestamp;

        ctx->audio_sample_count += 1;
        if ((ctx->audio_sample_count <= NGX_RTMP_DASH_MAX_SAMPLES)) {
            ctx->audio_sample_sizes[ctx->audio_sample_count] = 
                 ngx_rtmp_mp4_write_data(s, &ctx->audio_file, &out);
            ctx->audio_mdat_size += 
                 ctx->audio_sample_sizes[ctx->audio_sample_count];
        }
        else { 
            ctx->audio_sample_count = NGX_RTMP_DASH_MAX_SAMPLES;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_dash_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_dash_app_conf_t       *hacf;
    ngx_rtmp_dash_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    u_char                         *p;
    uint8_t                         htype, fmt, ftype;
    uint32_t                        i = 1;
    ngx_buf_t                       out;
    size_t                          bsize;
    ngx_rtmp_dash_frag_t           *f;
    static u_char                   buffer[NGX_RTMP_DASH_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || !hacf->dash || ctx == NULL || codec_ctx == NULL ||
        codec_ctx->avc_header == NULL || h->mlen < 1)
    {
        return NGX_OK;
    }

    /* Only H264 is supported */
    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
        return NGX_OK;
    }

    ctx->video = 1;

    if (in->buf->last-in->buf->pos < 2) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame */

    ngx_memcpy(&fmt, in->buf->pos, 1);
    ftype = (fmt & 0xf0) >> 4;

    /* proceed only with PICT */

    ngx_memcpy(&htype, in->buf->pos+1, 1);
    if (htype != 1) {
        return NGX_OK;
    }

    ngx_memzero(&out, sizeof(out));
    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    ngx_rtmp_dash_update_fragments(s, (ftype ==1), h->timestamp);

    f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);

    if (!ctx->opened) {
        return NGX_OK;
    }

    /* Set presentation times */
    if (ctx->video_sample_count == 0) {
        f->video_earliest_pres_time = h->timestamp;
    }
    f->video_latest_pres_time = h->timestamp;

    for (; in && out.last < out.end; in = in->next) {
        p = in->buf->pos;
        if (i == 1) {
            i = 2;
            p += 5;
        }
        bsize = in->buf->last - p;
        if (out.last + bsize > out.end) {
            bsize = out.end - out.last;
        }

        out.last = ngx_cpymem(out.last, p, bsize);
    }

    ctx->video_sample_count += 1;
    if (ctx->video_sample_count <= NGX_RTMP_DASH_MAX_SAMPLES) {
        ctx->video_sample_sizes[ctx->video_sample_count] = 
             ngx_rtmp_mp4_write_data(s, &ctx->video_file, &out);
        ctx->video_mdat_size += 
             ctx->video_sample_sizes[ctx->video_sample_count];
    }
    else { 
        ctx->video_sample_count = NGX_RTMP_DASH_MAX_SAMPLES;
    }

    return NGX_OK;
}


static void
ngx_rtmp_dash_discontinue(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);


    if (ctx != NULL && ctx->opened) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "dash: discontinue");

        ngx_close_file(ctx->video_file.fd);
        ngx_close_file(ctx->audio_file.fd);
        ctx->opened = 0;
    }
}


static ngx_int_t
ngx_rtmp_dash_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_dash_discontinue(s);

    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_dash_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_dash_discontinue(s);

    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_dash_cleanup_dir(ngx_str_t *ppath, ngx_msec_t playlen)
{
    ngx_dir_t               dir;
    time_t                  mtime, max_age;
    ngx_err_t               err;
    ngx_str_t               name, spath;
    u_char                 *p;
    ngx_int_t               nentries, nerased;
    u_char                  path[NGX_MAX_PATH + 1];

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                   "dash: cleanup path='%V' playlen=%M",
                   ppath, playlen);

    if (ngx_open_dir(ppath, &dir) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                      "dash: cleanup open dir failed '%V'", ppath);
        return NGX_ERROR;
    }

    nentries = 0;
    nerased = 0;

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (ngx_close_dir(&dir) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno,
                              "dash: cleanup " ngx_close_dir_n " \"%V\" failed",
                              ppath);
            }

            if (err == NGX_ENOMOREFILES) {
                return nentries - nerased;
            }

            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, err,
                          "dash: cleanup " ngx_read_dir_n
                          " \"%V\" failed", ppath);
            return NGX_ERROR;
        }

        name.data = ngx_de_name(&dir);
        if (name.data[0] == '.') {
            continue;
        }

        name.len = ngx_de_namelen(&dir);

        p = ngx_snprintf(path, sizeof(path) - 1, "%V/%V", ppath, &name);
        *p = 0;

        spath.data = path;
        spath.len = p - path;

        nentries++;

        if (ngx_de_info(path, &dir) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno,
                          "dash: cleanup " ngx_de_info_n " \"%V\" failed",
                          &spath);

            continue;
        }

        if (ngx_de_is_dir(&dir)) {

            if (ngx_rtmp_dash_cleanup_dir(&spath, playlen) == 0) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                               "dash: cleanup dir '%V'", &name);

                if (ngx_delete_dir(spath.data) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                                  "dash: cleanup dir error '%V'", &spath);
                } else {
                    nerased++;
                }
            }

            continue;
        }

        if (!ngx_de_is_file(&dir)) {
            continue;
        }

       if (name.len >= 4 && name.data[name.len - 4] == '.' &&
                                    name.data[name.len - 3] == 'm' &&
                                    name.data[name.len - 2] == '4' &&
                                    name.data[name.len - 1] == 'v')
        {
            max_age = playlen / 166;

        } else if (name.len >= 4 && name.data[name.len - 4] == '.' &&
                                    name.data[name.len - 3] == 'm' &&
                                    name.data[name.len - 2] == '4' &&
                                    name.data[name.len - 1] == 'a')
        {
            max_age = playlen / 166;

        } else if (name.len >= 4 && name.data[name.len - 4] == '.' &&
                                    name.data[name.len - 3] == 'm' &&
                                    name.data[name.len - 2] == 'p' &&
                                    name.data[name.len - 1] == 'd')
        {
            max_age = playlen / 166;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                           "dash: cleanup skip unknown file type '%V'", &name);
            continue;
        }

        mtime = ngx_de_mtime(&dir);
        if (mtime + max_age > ngx_cached_time->sec) {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                       "dash: cleanup '%V' mtime=%T age=%T",
                       &name, mtime, ngx_cached_time->sec - mtime);

        if (ngx_delete_file(spath.data) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                          "dash: cleanup error '%V'", &spath);
            continue;
        }

        nerased++;
    }
}


static time_t
ngx_rtmp_dash_cleanup(void *data)
{
    ngx_rtmp_dash_cleanup_t *cleanup = data;

    ngx_rtmp_dash_cleanup_dir(&cleanup->path, cleanup->playlen);

    return cleanup->playlen / 500;
}


static void *
ngx_rtmp_dash_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_dash_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_dash_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->dash = NGX_CONF_UNSET;
    conf->fraglen = NGX_CONF_UNSET_MSEC;
    conf->playlen = NGX_CONF_UNSET_MSEC;
    conf->cleanup = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_rtmp_dash_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_dash_app_conf_t    *prev = parent;
    ngx_rtmp_dash_app_conf_t    *conf = child;
    ngx_rtmp_dash_cleanup_t     *cleanup;

    ngx_conf_merge_value(conf->dash, prev->dash, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_value(conf->cleanup, prev->cleanup, 1);

    if (conf->fraglen) {
        conf->winfrags = conf->playlen / conf->fraglen;
    }

    /* schedule cleanup */

    if (conf->path.len == 0 || !conf->cleanup) {
        return NGX_CONF_OK;
    }

    if (conf->path.data[conf->path.len - 1] == '/') {
        conf->path.len--;
    }

    cleanup = ngx_pcalloc(cf->pool, sizeof(*cleanup));
    if (cleanup == NULL) {
        return NGX_CONF_ERROR;
    }

    cleanup->path = conf->path;
    cleanup->playlen = conf->playlen;

    conf->slot = ngx_pcalloc(cf->pool, sizeof(*conf->slot));
    if (conf->slot == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->slot->manager = ngx_rtmp_dash_cleanup;
    conf->slot->name = conf->path;
    conf->slot->data = cleanup;
    conf->slot->conf_file = cf->conf_file->file.name.data;
    conf->slot->line = cf->conf_file->line;

    if (ngx_add_path(cf, &conf->slot) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_dash_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_dash_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_dash_audio;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_dash_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_dash_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_dash_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_dash_stream_eof;

    return NGX_OK;
}
