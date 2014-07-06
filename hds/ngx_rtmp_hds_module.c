/*
 * Copyright (C) Stephen Basile
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>
#include <ngx_rtmp_live_module.h>
#include "dash/ngx_rtmp_mp4.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static ngx_int_t ngx_rtmp_hds_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hds_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hds_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_HDS_BUFSIZE            (1024*1024)
#define NGX_RTMP_HDS_DIR_ACCESS         0744
#define NGX_RTMP_HDS_MAX_SIZE           (20*1024*1024)


typedef struct {
    ngx_uint_t                          earliest_pres_time;
    ngx_uint_t                          latest_pres_time;
    uint32_t                            id;
} ngx_rtmp_hds_frag_t;


typedef struct {
    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           bootstrap;
    ngx_str_t                           bootstrap_bak;
    ngx_str_t                           name;
    ngx_str_t                           stream;

    unsigned                            opened:1;
    unsigned                            video:1;
    unsigned                            audio:1;

    ngx_file_t                          file;

    uint32_t                            restore_offset;

    uint32_t                            frag;
    uint32_t                            nfrags;
    ngx_rtmp_hds_frag_t                *frags;
    uint32_t                            fraglen;
    
    ngx_str_t                           fragment;

    ngx_uint_t                          meta_version;

    uint64_t                            mdat_size;

} ngx_rtmp_hds_ctx_t;


typedef struct {
    ngx_str_t                           path;
    ngx_msec_t                          playlen;
} ngx_rtmp_hds_cleanup_t;


typedef struct {
    ngx_flag_t                          hds;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          playlen;
    ngx_str_t                           path;
    ngx_uint_t                          winfrags;
    ngx_flag_t                          cleanup;
    ngx_path_t                         *slot;
    ngx_flag_t                          continuous;
} ngx_rtmp_hds_app_conf_t;


static ngx_command_t ngx_rtmp_hds_commands[] = {

    { ngx_string("hds"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, hds),
      NULL },

    { ngx_string("hds_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, fraglen),
      NULL },

    { ngx_string("hds_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, path),
      NULL },

    { ngx_string("hds_playlist_length"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, playlen),
      NULL },

    { ngx_string("hds_cleanup"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, cleanup),
      NULL },

    { ngx_string("hds_continuous"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, continuous),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hds_module_ctx = {
  NULL,                               /* preconfiguration */
  ngx_rtmp_hds_postconfiguration,    /* postconfiguration */

  NULL,                               /* create main configuration */
  NULL,                               /* init main configuration */

  NULL,                               /* create server configuration */
  NULL,                               /* merge server configuration */

  ngx_rtmp_hds_create_app_conf,      /* create location configuration */
  ngx_rtmp_hds_merge_app_conf,       /* merge location configuration */
};


ngx_module_t  ngx_rtmp_hds_module = {
  NGX_MODULE_V1,
  &ngx_rtmp_hds_module_ctx,          /* module context */
  ngx_rtmp_hds_commands,             /* module directives */
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


static ngx_rtmp_hds_frag_t *
ngx_rtmp_hds_get_frag(ngx_rtmp_session_t *s, ngx_int_t n)
{
    ngx_rtmp_hds_ctx_t         *ctx;
    ngx_rtmp_hds_app_conf_t    *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    return &ctx->frags[(ctx->frag + n) % (hacf->winfrags * 2 + 1)];
}


uint32_t
ngx_rtmp_hds_write_data(ngx_rtmp_session_t *s, ngx_file_t *file, ngx_buf_t *b)
{
    ngx_int_t       rc;
    uint32_t        size;

    if (!b || !b->last || !b->start) {
        return 0; //error
    }

    size = b->last-b->start;
    if (size < 1) {
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hds: data written: %d",
                   (int) size);

    rc = ngx_write_file(file, b->start, size, file->offset);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: writing file failed");
        return 0; //error
    }

    return size;
}


static ngx_int_t
ngx_rtmp_hds_rename_file(u_char *src, u_char *dst)
{
    /* rename file with overwrite */

#if (NGX_WIN32)
    return MoveFileEx((LPCTSTR) src, (LPCTSTR) dst, MOVEFILE_REPLACE_EXISTING);
#else
    return ngx_rename_file(src, dst);
#endif
}


ngx_uint_t
ngx_rtmp_hds_write_hint_sample(ngx_rtmp_session_t *s, ngx_buf_t *b,
                               uint32_t ts, uint8_t ftype, uint8_t htype,
                               uint32_t comp_time, size_t packet_size,
                               uint8_t type)
{
    u_char         *pos, *curpos;
    uint8_t         byte = 0;

    ngx_rtmp_mp4_field_8(b, type);

    pos = b->last;
    ngx_rtmp_mp4_field_24(b, 0); /* size placeholder */
    ngx_rtmp_mp4_field_24(b, ts); /* timestamp */
    ngx_rtmp_mp4_field_8(b, ts>>24 & 0xFF); /* timestamp */
    ngx_rtmp_mp4_field_24(b, 0); /* stream id (=0) */

    if (type == 0x90) {
        byte |= ((uint8_t)ftype << 4);
        byte |= ((uint8_t)7);

        ngx_rtmp_mp4_field_8(b, byte); /* frame type and codec (=7) */
        ngx_rtmp_mp4_field_8(b, htype); /* sequence header or nal */
        ngx_rtmp_mp4_field_24(b, comp_time); /* composition time offset */
    }

    curpos = b->last;
    b->last = pos;

    ngx_rtmp_mp4_field_24(b, ((curpos-pos)-10)+packet_size);

    b->last = curpos;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hds_write_afrt(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    u_char                         *pos, *marker, *temp;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_hds_frag_t            *f;
    uint32_t                        i, last_id = 0, dur, last_dur = 0, 
                                    last_start = 0, entry_count = 0;
    uint8_t                         discont;
   
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (b->end-b->last < (21+16*ctx->nfrags)) {
        return NGX_OK;
    }

    pos = ngx_rtmp_mp4_start_box(b, "afrt");

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 1000); /* timescale */
    ngx_rtmp_mp4_field_8(b, 0); /* quality entry count */
    /* fragment run entry count placeholder */
    marker = b->last;
    ngx_rtmp_mp4_field_32(b, 0); 

    for (i=1; i<=ctx->nfrags; i++) {
        f = ngx_rtmp_hds_get_frag(s, i);
        dur = f->latest_pres_time-f->earliest_pres_time;
        discont = 0;

        /* Discontinuities
        0: end of presentation
        1: discont in frag numbering
        2: discont in ts
        3: discont in frag numbering and ts */
        if (i != 1 && f->id != last_id+1) {
            discont += 1;
        }
        if (i != 1 && last_start+last_dur != f->earliest_pres_time) {
            discont += 2;
        }

        last_id = f->id;
        last_dur = dur;
        last_start = f->earliest_pres_time;

        if (discont > 0) {
            entry_count++;
            /* discontinuity indicator */
            ngx_rtmp_mp4_field_32(b, last_id+1); /* first fragment */
            ngx_rtmp_mp4_field_64(b, last_start+last_dur); /* timestamp */
            ngx_rtmp_mp4_field_32(b, 0); /* duration */
            ngx_rtmp_mp4_field_8(b, discont);
        }

        entry_count++;
        ngx_rtmp_mp4_field_32(b, f->id); /* first fragment */
        ngx_rtmp_mp4_field_64(b, f->earliest_pres_time); /* timestamp */
        ngx_rtmp_mp4_field_32(b, dur); /* duration */
    }

    temp = b->last;
    b->last = marker;
    ngx_rtmp_mp4_field_32(b, entry_count);
    b->last = temp;

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hds_write_asrt(ngx_rtmp_session_t *s, ngx_buf_t *b) 
{
    ngx_rtmp_hds_ctx_t             *ctx;
    u_char                         *pos;
    ngx_rtmp_hds_frag_t            *f;
   
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

    pos = ngx_rtmp_mp4_start_box(b, "asrt");

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_8(b, 0); /* quality count */
    ngx_rtmp_mp4_field_32(b, 1); /* segment run entry count */
    ngx_rtmp_mp4_field_32(b, 1); /* current segment */
    /* segment count */
    ngx_rtmp_mp4_field_32(b, f->id); 

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hds_write_abst(ngx_rtmp_session_t *s, ngx_buf_t *b) 
{
    ngx_rtmp_hds_ctx_t             *ctx;
    u_char                         *pos;
    ngx_rtmp_hds_frag_t            *f;
   
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

    pos = ngx_rtmp_mp4_start_box(b, "abst");

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, ctx->frag+ctx->nfrags); /* bootstrap version */
    ngx_rtmp_mp4_field_8(b, 0x20);
    ngx_rtmp_mp4_field_32(b, 1000); /* timescale */
    ngx_rtmp_mp4_field_64(b, f->latest_pres_time); /* current media time */
    ngx_rtmp_mp4_field_64(b, 0); /* smpte time code offset */
    b->last = ngx_cpymem(b->last, "", 1);
    ngx_rtmp_mp4_field_8(b, 0); /* server entry count */
    ngx_rtmp_mp4_field_8(b, 0); /* quality entry table */
    b->last = ngx_cpymem(b->last, "", 1); /* drm data */
    b->last = ngx_cpymem(b->last, "", 1); /* meta data */
    ngx_rtmp_mp4_field_8(b, 1); /* segment run entry count */

    ngx_rtmp_hds_write_asrt(s, b);

    ngx_rtmp_mp4_field_8(b, 1); /* fragment run entry count */

    ngx_rtmp_hds_write_afrt(s, b);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hds_write_manifest(ngx_rtmp_session_t *s)
{
    struct stat                     st;
    int                             fd;
    u_char                         *p;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *in;
    ngx_str_t                       meta, encoded_meta;
    ssize_t                         n;
    ngx_str_t                       playlist, playlist_bak;
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    /* if playlist exists and metadata unchanged, return */
    if (stat((char*)ctx->playlist.data, &st) == 0) {
        if (codec_ctx && codec_ctx->meta_version == ctx->meta_version) {
            return NGX_OK;
        }
        ctx->meta_version = codec_ctx->meta_version;
    }

    /* done playlists */

    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY, 
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: open failed: '%V'", &ctx->playlist_bak);

        return NGX_ERROR;
    }

#define NGX_RTMP_HDS_MANIFEST                                        \
    "<manifest xmlns=\"http://ns.adobe.com/f4m/1.0\">\n"\
    " <id>%V</id>\n"\
    " <mimeType></mimeType>\n"\
    " <streamType>live</streamType>\n"\
    " <duration>0</duration>\n"\
    " <bootstrapInfo profile=\"named\" url=\"%V.bootstrap\""\
    "id=\"bootstrap\"></bootstrapInfo>\n"\
    " <media streamId=\"test\" url=\"%V\" bootstrapInfoId=\"bootstrap\">\n"\
    "  <metadata>"
#define NGX_RTMP_HDS_MANIFEST_FOOT \
    "</metadata>\n"\
    " </media>\n"\
    "</manifest>\n"

    p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_HDS_MANIFEST,
                     &ctx->name, &ctx->name, &ctx->name);
    n = ngx_write_fd(fd, buffer, p - buffer);

    in = codec_ctx->received_meta;
    if (in && in->buf->pos && in->buf->last) {
        meta.data = in->buf->pos;
        meta.len = in->buf->last-in->buf->pos;
        encoded_meta.data = buffer;

        ngx_encode_base64(&encoded_meta, &meta);
        n = ngx_write_fd(fd, buffer, encoded_meta.len);
    }

    p = ngx_snprintf(buffer, sizeof(buffer), NGX_RTMP_HDS_MANIFEST_FOOT); 

    n = ngx_write_fd(fd, buffer, p - buffer);
    
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: write failed: '%V'", &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_close_file(fd);

    if (ngx_rtmp_hds_rename_file(ctx->playlist_bak.data, ctx->playlist.data)
        == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: rename failed: '%V'->'%V'", 
                      &playlist_bak, &playlist);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hds_write_bootstrap(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_hds_app_conf_t        *hacf;
    int                             rc;
    ngx_file_t                      file;
    ngx_buf_t                       b;
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);
    if (!ctx || !hacf) {
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(file));
    ngx_str_set(&file.name, "hds.bootstrap");

    file.fd = ngx_open_file(ctx->bootstrap_bak.data, NGX_FILE_RDWR,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: error creating bootstrap file");
        return NGX_ERROR;
    }

    file.log = s->connection->log;

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    ngx_rtmp_hds_write_abst(s, &b); 

    rc = ngx_write_file(&file, b.start, b.last-b.start, 0); 
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: writing bootstrap failed");
    }
    ngx_close_file(file.fd);

    if (ngx_rtmp_hds_rename_file(ctx->bootstrap_bak.data, ctx->bootstrap.data)
        == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: rename failed: '%V'->'%V'", 
                      &ctx->bootstrap_bak, &ctx->bootstrap);
        return NGX_ERROR;
    }

    return NGX_OK; 
}


static ngx_int_t
ngx_rtmp_hds_write_audio_hint(ngx_rtmp_session_t *s, uint32_t ts)
{
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    uint32_t                        written = 0;
    size_t                          size;
    ngx_buf_t                       b;
    ngx_chain_t                    *aac;
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (!ctx->opened || !codec_ctx || codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC) {
        return NGX_OK;
    }

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    aac = codec_ctx->aac_header;

    if (!aac || !aac->buf || !aac->buf->last || !aac->buf->pos) {
        return NGX_ERROR;
    }

    size = aac->buf->last-aac->buf->pos;

    if (b.last + size > b.end) {
        return NGX_ERROR;
    }

    if (size > 0) {
        ngx_rtmp_hds_write_hint_sample(s, &b, ts+ctx->restore_offset, 0, 0, 0, size, 0x08);
        b.last = ngx_cpymem(b.last, aac->buf->pos, size);

        written += ngx_rtmp_hds_write_data(s, &ctx->file, &b);
    }

    ctx->mdat_size += written;

    b.pos = b.last = b.start;
    ngx_rtmp_mp4_field_32(&b, written);
    ctx->mdat_size += ngx_rtmp_hds_write_data(s, &ctx->file, &b);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hds_write_video_hint(ngx_rtmp_session_t *s, uint32_t ts)
{
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_buf_t                       b;
    ngx_chain_t                    *in;
    uint32_t                        written = 0;
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (!ctx->opened) {
        return NGX_OK;
    }

    if (!codec_ctx || !codec_ctx->avc_header) {
        return NGX_OK;
    }

    in = codec_ctx->avc_header;

    if (!in->buf || !in->buf->pos || !in->buf->last) {
        return NGX_OK;
    }

    if (in->buf->last-in->buf->pos < 1) {
        return NGX_OK; 
    }

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    ngx_rtmp_hds_write_hint_sample(s, &b, ts+ctx->restore_offset, 1, 0, 0, 
                                   (in->buf->last-in->buf->pos), 0x09);
    if (b.end-b.last >= in->buf->last-in->buf->pos) {
        b.last = ngx_cpymem(b.last, in->buf->pos, in->buf->last-in->buf->pos);
    }
    else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: not enough memory to write avcc");
    }

    written += ngx_rtmp_hds_write_data(s, &ctx->file, &b);
    ctx->mdat_size += written;

    b.pos = b.last = b.start;
    ngx_rtmp_mp4_field_32(&b, written); 
    ctx->mdat_size += ngx_rtmp_hds_write_data(s, &ctx->file, &b);

    return NGX_OK;
}


static void
ngx_rtmp_hds_calc_ts_offset(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hds_ctx_t        *ctx;
    ngx_rtmp_hds_frag_t       *f;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (ctx->restore_offset < 1) {
        return;
    }

    f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

    if (f->latest_pres_time < ctx->restore_offset) {
        f->earliest_pres_time += ctx->restore_offset;
        f->latest_pres_time += ctx->restore_offset;
    }
}


static ngx_int_t 
ngx_rtmp_hds_close_fragments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_buf_t                       b;
    static u_char                   buffer[16];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_rtmp_hds_calc_ts_offset(s);

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    ctx->file.offset = 0;

    ngx_rtmp_mp4_write_mdat(&b, 1);

    ngx_rtmp_mp4_field_64(&b, ctx->mdat_size+16); /* mdat size */

    ngx_rtmp_hds_write_data(s, &ctx->file, &b);

    ngx_close_file(ctx->file.fd);

    ctx->opened = 0;

    ngx_rtmp_hds_write_bootstrap(s);

    ngx_rtmp_hds_write_manifest(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hds_open_fragments(ngx_rtmp_session_t *s, uint32_t ts)
{
    ngx_rtmp_hds_ctx_t         *ctx;
    ngx_buf_t                   b;
    ngx_rtmp_hds_frag_t        *f, *lastf;
    static u_char               buffer[16];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (ctx->opened) {
        return NGX_OK;
    }

    f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);
    lastf = ngx_rtmp_hds_get_frag(s, ctx->nfrags-1);

    f->id = lastf->id+1;

    ngx_memzero(&ctx->file, sizeof(ctx->file));

    ctx->file.log = s->connection->log;

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "Seg1-Frag%uL", f->id) = 0;
    *ngx_sprintf(ctx->fragment.data + ctx->stream.len, "Seg1-Frag%uL", 
                 f->id) = 0;

    ngx_str_set(&ctx->file.name, "hds");
    ctx->file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: error creating video fragment file");
        return NGX_ERROR;
    }

    f->earliest_pres_time = 0;
    ctx->opened = 1;
    ctx->mdat_size = 0;

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    ngx_rtmp_mp4_field_64(&b, 0); /* leave room for mdat */
    ngx_rtmp_mp4_field_64(&b, 0); /* leave room for flv size */

    ngx_rtmp_hds_write_data(s, &ctx->file, &b);

    if (!ctx->video && ctx->audio) {
        ngx_rtmp_hds_write_audio_hint(s, ts);
    }

    return NGX_OK;
}


static void
ngx_rtmp_hds_restore_stream(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_hds_app_conf_t        *hacf;
    ngx_file_t                      file;
    ssize_t                         ret;
    uint64_t                        earliest_pres_time;
    uint32_t                        id, duration;
    int                             i;
    u_char                         *p, *end;
    ngx_rtmp_hds_frag_t            *f;
    static u_char                   buffer[4096], path[NGX_MAX_PATH + 1];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ngx_memzero(&file, sizeof(file));

    file.log = s->connection->log;

    ngx_str_set(&file.name, "bootstrap");

    *ngx_snprintf(path, sizeof(path), "%V.bootstrap",&ctx->stream) = 0;

    file.fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                            0);

    f = NULL;

    ret = ngx_read_file(&file, buffer, sizeof(buffer), 0);
    if (ret <= 0) {
        goto done;
    }

    p = buffer;
    end = buffer + ret;

    for ( ;; ) {
        p = ngx_strlchr(p, end, 'a');

        if (p == NULL) {
            goto done;
        }
        if (ngx_strncmp(p, "afrt", 4) != 0) {
            p++;
            continue;
        }
        else {
            p += 4;
            break;
        }
    }

    if (end-p <= 13) {
        goto done;
    }

    p += 13;

    for ( ;; ) {
        earliest_pres_time = id = duration = 0;
        if (end-p < 16) {
            goto done;
        }

        for (i=3;i>=0;i--) {
            id |= ((uint32_t) *p) << (8*i);
            p++;
        }
        for (i=7;i>=0;i--) {
            earliest_pres_time |= ((uint64_t) *p) << (8*i);
            p++;
        }
        for (i=3;i>=0;i--) {
            duration |= ((uint32_t) *p) << (8*i);
            p++;
        }
        
        if (duration < 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                                  "hds: restore discontinuity found");
            if (end-p < 2) {
                goto done;
            }
            p++;
            continue;
        }

        if (id > hacf->winfrags) {
            ctx->frag = id-hacf->winfrags;
            ctx->nfrags = hacf->winfrags;
        }
        else {
            ctx->nfrags = id;
        }
 
        f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

        f->id = id;
        f->earliest_pres_time = earliest_pres_time;
        f->latest_pres_time = earliest_pres_time+duration;

        /* this +1 is to force a discontinuity to trigger */
        ctx->restore_offset = f->latest_pres_time + 1;

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                      "hds: restore id: %d, earliest_pres_time: %d, dur: %d",
                      (int) id, (int) earliest_pres_time, (int) duration);

        if (ctx->nfrags == hacf->winfrags) {
            ctx->frag++;
        } else {
            ctx->nfrags++;
        }
    }

done:
    ngx_close_file(file.fd);
}


static ngx_int_t
ngx_rtmp_hds_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hds_app_conf_t       *hacf;
    ngx_rtmp_hds_ctx_t            *ctx;
    u_char                         *p, *b;
    size_t                          len;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    if (hacf == NULL || !hacf->hds || hacf->path.len == 0) {
        goto next;
    }

    if (s->auto_pushed) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hds: publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hds_ctx_t));
        if (!ctx) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hds_module);
    }

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->connection->pool,
                                 sizeof(ngx_rtmp_hds_frag_t) *
                                 (hacf->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
        ctx->frag = 0;
        ctx->nfrags = 1;
    }

    if (ngx_strstr(v->name, "..")) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hds: bad stream name: '%s'", v->name);
        return NGX_ERROR;
    }

    ctx->name.len = ngx_strlen(v->name);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len + 1);
    
    if (ctx->name.data == NULL) {
        return NGX_ERROR;
    }

    *ngx_cpymem(ctx->name.data, v->name, ctx->name.len) = 0;

    len = hacf->path.len + 1 + ctx->name.len + sizeof(".f4m");
    ctx->playlist.data = ngx_palloc(s->connection->pool, len);

    len = hacf->path.len + 1 + ctx->name.len + sizeof(".bootstrap");
    ctx->bootstrap.data = ngx_palloc(s->connection->pool, len);

    p = ngx_cpymem(ctx->playlist.data, hacf->path.data, hacf->path.len);
    b = ngx_cpymem(ctx->bootstrap.data, hacf->path.data, hacf->path.len);

    if (p[-1] != '/') {
        *p++ = '/';
    }
    if (b[-1] != '/') {
        *b++ = '/';
    }

    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);
    b = ngx_cpymem(b, ctx->name.data, ctx->name.len);

    /* ctx->stream_path holds initial part of stream file path 
     * however the space for the whole stream path
     * is allocated */

    ctx->stream.len = p - ctx->playlist.data;
    ctx->stream.data = ngx_palloc(s->connection->pool,
                                  ctx->stream.len + NGX_INT64_LEN +
                                  NGX_INT64_LEN + sizeof("Seg-Frag"));

    ngx_memcpy(ctx->stream.data, ctx->playlist.data, ctx->stream.len);

    ctx->fragment.len = p - ctx->playlist.data ;
    ctx->fragment.data = ngx_palloc(s->connection->pool, 
                                  ctx->fragment.len + NGX_INT64_LEN +
                                  NGX_INT64_LEN + sizeof("Seg-Frag"));

    ngx_memcpy(ctx->fragment.data, ctx->playlist.data, 
               ctx->fragment.len);

    /* playlist path */
    p = ngx_cpymem(p, ".f4m", sizeof(".f4m") - 1);
    b = ngx_cpymem(b, ".bootstrap", sizeof(".bootstrap") - 1);

    ctx->playlist.len = p - ctx->playlist.data;
    ctx->bootstrap.len = b - ctx->bootstrap.data;

    *p = 0;
    *b = 0;

    /* playlist bak (new playlist) path */

    ctx->playlist_bak.data = ngx_palloc(s->connection->pool, 
                                        ctx->playlist.len + sizeof(".bak"));
    ctx->bootstrap_bak.data = ngx_palloc(s->connection->pool, 
                                        ctx->bootstrap.len + sizeof(".bak"));
    p = ngx_cpymem(ctx->playlist_bak.data, ctx->playlist.data, 
                   ctx->playlist.len);
    b = ngx_cpymem(ctx->bootstrap_bak.data, ctx->bootstrap.data, 
                   ctx->bootstrap.len);
    p = ngx_cpymem(p, ".bak", sizeof(".bak") - 1);
    b = ngx_cpymem(b, ".bak", sizeof(".bak") - 1);

    ctx->playlist_bak.len = p - ctx->playlist_bak.data;
    ctx->bootstrap_bak.len = b - ctx->bootstrap_bak.data;

    *p = 0;
    *b = 0;

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hds: playlist='%V' playlist_bak='%V' bootstrap: %V bootstrap_bak: %V stream_pattern='%V'",
                   &ctx->playlist, &ctx->playlist_bak, &ctx->bootstrap, &ctx->bootstrap_bak, &ctx->stream);

    if (hacf->continuous) {
      ngx_rtmp_hds_restore_stream(s);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_hds_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hds_app_conf_t       *hacf;
    ngx_rtmp_hds_ctx_t            *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (hacf == NULL || !hacf->hds || ctx == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hds: delete stream");

    ngx_rtmp_hds_close_fragments(s);

next:
    return next_close_stream(s, v);
}


static void
ngx_rtmp_hds_update_fragment(ngx_rtmp_session_t *s, ngx_int_t boundary, 
                               uint32_t ts)
{
    ngx_rtmp_hds_ctx_t        *ctx;
    ngx_rtmp_hds_app_conf_t   *hacf;
    uint32_t                   duration;
    ngx_rtmp_hds_frag_t       *f;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

    duration = (uint32_t)(ts - f->earliest_pres_time);

    if (duration < hacf->fraglen) {
        boundary = 0;
    }

    if ((!ctx->video && ctx->audio) && (duration >= hacf->fraglen)) {
        boundary = 1;
    }

    if (!ctx->opened) {
        boundary = 0;
        ngx_rtmp_hds_open_fragments(s, ts);
    }

    if (ctx->mdat_size >= NGX_RTMP_HDS_MAX_SIZE) {
        boundary = 1;
    }

    if (boundary) { 
        f->latest_pres_time = ts;
        ngx_rtmp_hds_close_fragments(s);

        if (ctx->nfrags == hacf->winfrags) {
            ctx->frag++;
        } else {
            ctx->nfrags++;
        }

        ngx_rtmp_hds_open_fragments(s, ts);
    }
}


static ngx_int_t
ngx_rtmp_hds_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_hds_app_conf_t        *hacf;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    size_t                          bsize;
    uint32_t                        written = 0;
    ngx_buf_t                       out, b;
    ngx_rtmp_hds_frag_t            *f;
    static u_char                   out_buffer[NGX_RTMP_HDS_BUFSIZE];
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (hacf == NULL || !hacf->hds || ctx == NULL ||
        codec_ctx == NULL  || h->mlen < 2) 
    {
        return NGX_OK;
    }

    switch (codec_ctx->audio_codec_id) {
        case NGX_RTMP_AUDIO_AAC:
        case NGX_RTMP_AUDIO_MP3:
        case NGX_RTMP_AUDIO_NELLY:
            break;
        default:
            return NGX_OK;
    }

    if (in->buf->last-in->buf->pos < 2) {
        return NGX_OK;
    }

    out.start = out_buffer;
    out.end = out_buffer + sizeof(out_buffer);
    out.pos = out.last = out.start;

    ngx_rtmp_hds_update_fragment(s, 0, h->timestamp);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ctx->audio = 1;

    /* copy payload */
    for (; in && out.last < out.end; in = in->next) {
        bsize = in->buf->last - in->buf->pos;
        if (out.last + bsize > out.end) {
            bsize = out.end - out.last;
        }

        out.last = ngx_cpymem(out.last, in->buf->pos, bsize);
    }

    if (out.last-out.pos > 0) {
        f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

        /* Set Presentation Times */
        if (f->earliest_pres_time == 0 ) {
            f->earliest_pres_time = h->timestamp;
        }
        f->latest_pres_time = h->timestamp;

        b.start = buffer;
        b.end = buffer + sizeof(buffer);
        b.pos = b.last = b.start;

        ngx_rtmp_hds_write_hint_sample(s, &b, h->timestamp+ctx->restore_offset,
                                       0, 0, 0, out.last-out.start, 0x08);

        written += ngx_rtmp_hds_write_data(s, &ctx->file, &b);
        written += ngx_rtmp_hds_write_data(s, &ctx->file, &out);
        ctx->mdat_size += written;

        b.pos = b.last = b.start;
        ngx_rtmp_mp4_field_32(&b, written); /* flv size tag */
        ctx->mdat_size += written = ngx_rtmp_hds_write_data(s, &ctx->file, &b);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hds_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_hds_app_conf_t        *hacf;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    uint8_t                         htype, fmt, ftype, comp_buf;
    uint32_t                        written = 0, comp_time = 0;
    ngx_buf_t                       out, b;
    size_t                          bsize;
    ngx_rtmp_hds_frag_t            *f;
    static u_char                   out_buffer[NGX_RTMP_HDS_BUFSIZE];
    static u_char                   buffer[NGX_RTMP_HDS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || !hacf->hds || ctx == NULL || codec_ctx == NULL) 
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

    ngx_memcpy(&htype, in->buf->pos+1, 1);

    ngx_memcpy(&comp_buf, in->buf->pos+2, 1);
    comp_time |= (comp_buf & 0xFFFFFFFF) << 16;

    ngx_memcpy(&comp_buf, in->buf->pos+3, 1);
    comp_time |= (comp_buf & 0xFFFFFFFF) << 8;

    ngx_memcpy(&comp_buf, in->buf->pos+4, 1);
    comp_time |= (comp_buf & 0xFFFFFFFF);

    out.start = out_buffer;
    out.end = out_buffer + sizeof(out_buffer);
    out.pos = out.last = out.start;

    ngx_rtmp_hds_update_fragment(s, (ftype == 1), h->timestamp);

    if (!ctx->opened) {
        return NGX_OK;
    }

    if (ftype == 1) {
        ngx_rtmp_hds_write_video_hint(s, h->timestamp);
        if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC) {
            ngx_rtmp_hds_write_audio_hint(s, h->timestamp);
        }
    }

    for (; in && out.last < out.end; in = in->next) {
        bsize = in->buf->last - in->buf->pos;
        if (out.last + bsize > out.end) {
            bsize = out.end - out.last;
        }
        out.last = ngx_cpymem(out.last, in->buf->pos, bsize);
    }

    if (out.last-out.pos > 0) {
        f = ngx_rtmp_hds_get_frag(s, ctx->nfrags);

        /* Set presentation times */
        if (f->earliest_pres_time == 0) {
            f->earliest_pres_time = h->timestamp;
        }
        f->latest_pres_time = h->timestamp;

        b.start = buffer;
        b.end = buffer + sizeof(buffer);
        b.pos = b.last = b.start;

        ngx_rtmp_hds_write_hint_sample(s, &b, h->timestamp+ctx->restore_offset,
                                       ftype, htype, comp_time, 
                                       out.last-out.start, 0x09);

        written += ngx_rtmp_hds_write_data(s, &ctx->file, &b);
        written += ngx_rtmp_hds_write_data(s, &ctx->file, &out);
        ctx->mdat_size += written;

        b.pos = b.last = b.start;
        ngx_rtmp_mp4_field_32(&b, written); /* flv size tag */
        ctx->mdat_size += written = ngx_rtmp_hds_write_data(s, &ctx->file, &b);
    }

    return NGX_OK;
}


static void
ngx_rtmp_hds_discontinue(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hds_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);


    if (ctx != NULL && ctx->opened) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hds: discontinue");

        ngx_close_file(ctx->file.fd);
        ctx->opened = 0;
    }
}


static ngx_int_t
ngx_rtmp_hds_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_hds_discontinue(s);

    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_hds_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_hds_discontinue(s);

    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_hds_cleanup_dir(ngx_str_t *ppath, ngx_msec_t playlen)
{
    ngx_dir_t               dir;
    time_t                  mtime, max_age;
    ngx_err_t               err;
    ngx_str_t               name, spath;
    u_char                 *p;
    ngx_int_t               nentries, nerased;
    u_char                  path[NGX_MAX_PATH + 1];

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                   "hds: cleanup path='%V'", ppath);

    if (ngx_open_dir(ppath, &dir) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                      "hds: cleanup open dir failed '%V'", ppath);
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
                              "hds: cleanup " ngx_close_dir_n " \"%V\" failed",
                              ppath);
            }

            if (err == NGX_ENOMOREFILES) {
                return nentries - nerased;
            }

            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, err,
                          "hds: cleanup " ngx_read_dir_n
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
                          "hds: cleanup " ngx_de_info_n " \"%V\" failed",
                          &spath);

            continue;
        }

        if (ngx_de_is_dir(&dir)) {

            if (ngx_rtmp_hds_cleanup_dir(&spath,playlen) == 0) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                               "hds: cleanup dir '%V'", &name);

                if (ngx_delete_dir(spath.data) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                                  "hds: cleanup dir error '%V'", &spath);
                } else {
                    nerased++;
                }
            }

            continue;
        }

        if (!ngx_de_is_file(&dir)) {
            continue;
        }

        if (ngx_strstr(name.data, "Frag"))
        {
            max_age = playlen / 500;

        } else if (name.len >= 4 && name.data[name.len - 4] == 't' &&
                                    name.data[name.len - 3] == 'r' &&
                                    name.data[name.len - 2] == 'a' &&
                                    name.data[name.len - 1] == 'p')
        {
            max_age = playlen / 500;

        } else if (name.len >= 4 && name.data[name.len - 4] == '.' &&
                                    name.data[name.len - 3] == 'f' &&
                                    name.data[name.len - 2] == '4' &&
                                    name.data[name.len - 1] == 'm')
        {
            max_age = playlen / 500;

        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                           "hds: cleanup skip unknown file type '%V'", &name);
            continue;
        }

        mtime = ngx_de_mtime(&dir);
        if (mtime + max_age > ngx_cached_time->sec) {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                       "hds: cleanup '%V' mtime=%T age=%T",
                       &name, mtime, ngx_cached_time->sec - mtime);

        if (ngx_delete_file(spath.data) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                          "hds: cleanup error '%V'", &spath);
            continue;
        }

        nerased++;
    }
}


static time_t
ngx_rtmp_hds_cleanup(void *data)
{
    ngx_rtmp_hds_cleanup_t *cleanup = data;

    ngx_rtmp_hds_cleanup_dir(&cleanup->path, cleanup->playlen);

    return (time_t)20; /* wait 20 ms before running again */
}


static void *
ngx_rtmp_hds_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hds_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hds_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hds = NGX_CONF_UNSET;
    conf->fraglen = NGX_CONF_UNSET_MSEC;
    conf->playlen = NGX_CONF_UNSET_MSEC;
    conf->cleanup = NGX_CONF_UNSET;
    conf->continuous = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_rtmp_hds_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hds_app_conf_t    *prev = parent;
    ngx_rtmp_hds_app_conf_t    *conf = child;
    ngx_rtmp_hds_cleanup_t     *cleanup;

    ngx_conf_merge_value(conf->hds, prev->hds, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_value(conf->cleanup, prev->cleanup, 1);
    ngx_conf_merge_value(conf->continuous, prev->continuous, 1);

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

    conf->slot->manager = ngx_rtmp_hds_cleanup;
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
ngx_rtmp_hds_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hds_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hds_audio;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hds_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hds_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_hds_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_hds_stream_eof;

    return NGX_OK;
}
