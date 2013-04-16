/*
 * Copyright (c) 2013 Roman Arutyunyan
 */


#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_rtmp_mpegts.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static char *ngx_rtmp_hls_path(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)

#define NGX_RTMP_HLS_DIR_ACCESS         0744


typedef struct {
    uint64_t                            id;
    double                              duration;
    unsigned                            active:1;
    unsigned                            discont:1; /* after */
} ngx_rtmp_hls_frag_t;


typedef struct {
    unsigned                            opened:1;

    ngx_file_t                          file;

    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           name;

    uint64_t                            frag;
    uint64_t                            frag_ts;
    ngx_uint_t                          nfrags;
    ngx_rtmp_hls_frag_t                *frags; /* circular 2 * winfrags + 1 */

    ngx_uint_t                          audio_cc;
    ngx_uint_t                          video_cc;

    uint64_t                            aframe_base;
    uint64_t                            aframe_num;
} ngx_rtmp_hls_ctx_t;


typedef struct {
    ngx_str_t                           path;
    ngx_msec_t                          playlen;
} ngx_rtmp_hls_cleanup_t;


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          muxdelay;
    ngx_msec_t                          sync;
    ngx_msec_t                          playlen;
    ngx_uint_t                          winfrags;
    ngx_flag_t                          continuous;
    ngx_flag_t                          nested;
    ngx_str_t                           path;
    ngx_path_t                         *slot;
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
      ngx_rtmp_hls_path,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
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

    { ngx_string("hls_continuous"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, continuous),
      NULL },

    { ngx_string("hls_nested"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, nested),
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
ngx_rtmp_hls_chain2buffer(ngx_buf_t *out, ngx_chain_t *in, size_t skip)
{
    size_t  size;

    for (; in; in = in->next) {
        
        size = in->buf->last - in->buf->pos;
        if (size < skip) {
            skip -= size;
            continue;
        }

        out->last = ngx_cpymem(out->last, in->buf->pos + skip,
                              ngx_min(size - skip,
                                      (size_t) (out->end - out->last)));
        skip = 0;
    }
}


static ngx_int_t
ngx_rtmp_hls_create_parent_dir(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_app_conf_t  *hacf;
    ngx_rtmp_hls_ctx_t       *ctx;
    ngx_err_t                 err;
    size_t                    len;
    static u_char             path[NGX_MAX_PATH + 1];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    if (hacf->path.len == 0) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: creating target folder: '%V'", &hacf->path);

    if (ngx_create_dir(hacf->path.data, NGX_RTMP_HLS_DIR_ACCESS) != NGX_OK) {
        err = ngx_errno;
        if (err != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, err,
                          "hls: error creating target folder: '%V'",
                          &hacf->path);
            return NGX_ERROR;
        }
    }

    if (!hacf->nested) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    len = hacf->path.len;
    if (hacf->path.data[len - 1] == '/') {
        len--;
    }

    *ngx_snprintf(path, sizeof(path) - 1, "%*s/%V", len, hacf->path.data,
                  &ctx->name) = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: creating nested folder: '%s'", path);

    if (ngx_create_dir(path, NGX_RTMP_HLS_DIR_ACCESS) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error creating nested folder: '%s'", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_rtmp_hls_frag_t *
ngx_rtmp_hls_get_frag(ngx_rtmp_session_t *s, ngx_int_t n)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_app_conf_t    *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    return &ctx->frags[(ctx->frag + n) % (hacf->winfrags * 2 + 1)];
}


static void
ngx_rtmp_hls_next_frag(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_app_conf_t    *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->nfrags == hacf->winfrags) {
        ctx->frag++;
    } else {
        ctx->nfrags++;
    }
}


static ngx_int_t
ngx_rtmp_hls_write_playlist(ngx_rtmp_session_t *s)
{
    static u_char                   buffer[1024];
    int                             fd;
    u_char                         *p;
    ngx_rtmp_hls_ctx_t             *ctx;
    ssize_t                         n;
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_int_t                       nretry;
    ngx_rtmp_hls_frag_t            *f;
    ngx_uint_t                      i, max_frag;


    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    nretry = 0;

retry:

    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY, 
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {

        if (ngx_errno == NGX_ENOENT && nretry == 0 &&
            ngx_rtmp_hls_create_parent_dir(s) == NGX_OK)
        {
            nretry++;
            goto retry;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: open failed: '%V'", &ctx->playlist_bak);

        return NGX_ERROR;
    }

    max_frag = hacf->fraglen / 1000;

    for (i = 0; i < ctx->nfrags; i++) {
        f = ngx_rtmp_hls_get_frag(s, i);
        if (f->duration > max_frag) {
            max_frag = f->duration + .5;
        }
    }

    p = ngx_snprintf(buffer, sizeof(buffer), 
                     "#EXTM3U\n"
                     "#EXT-X-VERSION:3\n"
                     "#EXT-X-MEDIA-SEQUENCE:%uL\n"
                     "#EXT-X-TARGETDURATION:%ui\n"
                     "#EXT-X-ALLOW-CACHE:NO\n\n",
                     ctx->frag, max_frag);

    n = write(fd, buffer, p - buffer);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: write failed: '%V'", &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    for (i = 0; i < ctx->nfrags; i++) {
        f = ngx_rtmp_hls_get_frag(s, i);

        p = ngx_snprintf(buffer, sizeof(buffer), 
                         "#EXTINF:%.3f,\n"
                         "%V-%uL.ts\n"
                         "%s",
                         f->duration, &ctx->name, f->id,
                         f->discont ? "#EXT-X-DISCONTINUITY\n" : "");

        ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: fragment frag=%uL, n=%ui/%ui, duration=%.3f, "
                       "discont=%i",
                       ctx->frag, i + 1, ctx->nfrags, f->duration, f->discont);

        n = write(fd, buffer, p - buffer);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "hls: write failed '%V'", &ctx->playlist_bak);
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
ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n, 
    ngx_chain_t **in)
{
    u_char  *last;
    size_t   pn;

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
ngx_rtmp_hls_append_aud(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0xf0 };

    if (out->last + sizeof(aud_nal) > out->end) {
        return NGX_ERROR;
    }

    out->last = ngx_cpymem(out->last, aud_nal, sizeof(aud_nal));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_append_sps_pps(ngx_rtmp_session_t *s, ngx_buf_t *out)
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

    /*
     * Skip bytes:
     * - flv fmt
     * - H264 CONF/PICT (0x00)
     * - 0
     * - 0
     * - 0
     * - version
     * - profile
     * - compatibility
     * - level 
     * - nal bytes
     */

    if (ngx_rtmp_hls_copy(s, NULL, &p, 10, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* number of SPS NALs */
    if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    nnals &= 0x1f; /* 5lsb */

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "h264: SPS number: %uz", nnals);

    /* SPS */
    for (n = 0; ; ++n) {
        for (; nnals; --nnals) {

            /* NAL length */
            if (ngx_rtmp_hls_copy(s, &rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_rtmp_rmemcpy(&len, &rlen, 2);

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "h264: header NAL length: %uz", (size_t) len);

            /* AnnexB prefix */
            if (out->end - out->last < 4) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "h264: too small buffer for header NAL size");
                return NGX_ERROR;
            }

            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 1;

            /* NAL body */
            if (out->end - out->last < len) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "h264: too small buffer for header NAL");
                return NGX_ERROR;
            }

            if (ngx_rtmp_hls_copy(s, out->last, &p, len, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out->last += len;
        }

        if (n == 1) {
            break;
        }

        /* number of PPS NALs */
        if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "h264: PPS number: %uz", nnals);
    }

    return NGX_OK;
}


static uint64_t
ngx_rtmp_hls_get_fragment_id(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    /*TODO: implement more methods*/

/*#define ngx_rtmp_hls_frag(hacf, f) (hacf->nfrags ? (f) % hacf->nfrags : (f))*/

    return ctx->frag + ctx->nfrags;
}

/*
static ngx_int_t
ngx_rtmp_hls_delete_fragment(ngx_rtmp_session_t *s, ngx_uint_t n)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_frag_t        *f;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    f = ngx_rtmp_hls_get_frag(s, n);

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%uL.ts", f->id) = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: delete fragment '%s'", ctx->stream.data);

    ngx_delete_file(ctx->stream.data);

    return NGX_OK;
}
*/

static ngx_int_t
ngx_rtmp_hls_close_fragment(ngx_rtmp_session_t *s, ngx_int_t discont)
{
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: close fragment n=%uL, discont=%i",
                   ctx->frag, discont);

    ngx_close_file(ctx->file.fd);

    ctx->opened = 0;
    ctx->file.fd = NGX_INVALID_FILE;

    ngx_rtmp_hls_next_frag(s);

    ngx_rtmp_hls_write_playlist(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_open_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t discont)
{
    ngx_rtmp_hls_ctx_t     *ctx;
    ngx_rtmp_hls_frag_t    *f;
    ngx_uint_t              nretry;
    uint64_t                id;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx->opened) {
        return NGX_OK;
    }

    if (ctx->nfrags && discont) {
        f = ngx_rtmp_hls_get_frag(s, ctx->nfrags - 1);
        f->discont = 1;
    }

    id = ngx_rtmp_hls_get_fragment_id(s);

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%uL.ts", id) = 0;

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: open fragment file='%s', frag=%uL, n=%uL, time=%uL, "
                   "discont=%i",
                   ctx->stream.data, ctx->frag, ctx->nfrags, ts, discont);

    ngx_memzero(&ctx->file, sizeof(ctx->file));

    ctx->file.log = s->connection->log;

    ngx_str_set(&ctx->file.name, "hls");

    nretry = 0;

retry:

    ctx->file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_WRONLY,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (ctx->file.fd == NGX_INVALID_FILE) {

        if (ngx_errno == NGX_ENOENT && nretry == 0 &&
            ngx_rtmp_hls_create_parent_dir(s) == NGX_OK)
        {
            nretry++;
            goto retry;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error creating fragment file");
        return NGX_ERROR;
    }

    if (ngx_rtmp_mpegts_write_header(&ctx->file) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error writing fragment header");
        ngx_close_file(ctx->file.fd);
        return NGX_ERROR;
    }

    ctx->opened = 1;

    f = ngx_rtmp_hls_get_frag(s, ctx->nfrags);
/*
    if (f->active) {
        ngx_rtmp_hls_delete_fragment(s, ctx->nfrags);
    }
*/
    ngx_memzero(f, sizeof(*f));

    f->active = 1;
    f->id = id;

    ctx->frag_ts = ts;

    return NGX_OK;
}


static void
ngx_rtmp_hls_restore_stream(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_file_t                      file;
    ssize_t                         ret;
    size_t                          len;
    off_t                           offset;
    u_char                         *p, *last, *end, *next, *pa;
    ngx_rtmp_hls_frag_t            *f;
    double                          duration;
    ngx_uint_t                      mag;
    static u_char                   buffer[4096];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    ngx_memzero(&file, sizeof(file));

    file.log = s->connection->log;

    ngx_str_set(&file.name, "m3u8");

    file.fd = ngx_open_file(ctx->playlist.data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                            0);
    if (file.fd == NGX_INVALID_FILE) {
        return;
    }

    offset = 0;
    ctx->nfrags = 0;
    f = NULL;
    duration = 0;

    for ( ;; ) {

        ret = ngx_read_file(&file, buffer, sizeof(buffer), offset);
        if (ret <= 0) {
            goto done;
        }

        p = buffer;
        end = buffer + ret;
        
        for ( ;; ) {
            last = ngx_strlchr(p, end, '\n');

            if (last == NULL) {
                if (p == buffer) {
                    goto done;
                }
                break;
            }

            next = last + 1;
            offset += (next - p);

            if (p != last && last[-1] == '\r') {
                last--;
            }

            len = (size_t) (last - p);


#define NGX_RTMP_MSEQ           "#EXT-X-MEDIA-SEQUENCE:"
#define NGX_RTMP_MSEQ_LEN       (sizeof(NGX_RTMP_MSEQ) - 1)


            if (ngx_memcmp(p, NGX_RTMP_MSEQ, NGX_RTMP_MSEQ_LEN) == 0) {

                ctx->frag = strtod((const char *) &p[NGX_RTMP_MSEQ_LEN], NULL);

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: restore sequence frag=%uL", ctx->frag);
            }


#define NGX_RTMP_EXTINF         "#EXTINF:"
#define NGX_RTMP_EXTINF_LEN     (sizeof(NGX_RTMP_EXTINF) - 1)


            if (ngx_memcmp(p, NGX_RTMP_EXTINF, NGX_RTMP_EXTINF_LEN) == 0) {

                duration = strtod((const char *) &p[NGX_RTMP_EXTINF_LEN], NULL);

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: restore durarion=%.3f", duration);
            }


#define NGX_RTMP_DISCONT        "#EXT-X-DISCONTINUITY"
#define NGX_RTMP_DISCONT_LEN    (sizeof(NGX_RTMP_DISCONT) - 1)


            if (ngx_memcmp(p, NGX_RTMP_DISCONT, NGX_RTMP_DISCONT_LEN) == 0) {

                if (f) {
                    f->discont = 1;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: discontinuity");
            }

            /* find '.ts\r' */

            if (p + 4 <= last &&
                last[-3] == '.' && last[-2] == 't' && last[-1] == 's')
            {
                f = ngx_rtmp_hls_get_frag(s, ctx->nfrags);

                ngx_memzero(f, sizeof(*f));

                f->duration = duration;
                f->active = 1;
                f->id = 0;

                mag = 1;
                for (pa = last - 4; pa != p; pa--) {
                    if (*pa < '0' || *pa > '9') {
                        break;
                    }
                    f->id += (*pa - '0') * mag;
                    mag *= 10;
                }

                ngx_rtmp_hls_next_frag(s);

                ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: restore fragment '%*s' id=%uL, "
                               "duration=%.3f, frag=%uL, nfrags=%ui",
                               len, p, f->id, f->duration, ctx->frag,
                               ctx->nfrags);
            }

            p = next;
        }
    }

done:
    ngx_close_file(file.fd);
}


static ngx_int_t
ngx_rtmp_hls_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    u_char                         *p;
    ngx_rtmp_hls_frag_t            *f;
    size_t                          len;

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

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    } else {
        f = ctx->frags;
        ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));
        ctx->frags = f;
    }

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->connection->pool,
                                 sizeof(ngx_rtmp_hls_frag_t) *
                                 (hacf->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_strstr(v->name, "..")) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: bad stream name: '%s'", v->name);
        return NGX_ERROR;
    }

    ctx->name.len = ngx_strlen(v->name);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len + 1);
    if (ctx->name.data == NULL) {
        return NGX_ERROR;
    }
    *ngx_cpymem(ctx->name.data, v->name, ctx->name.len) = 0;

    len = hacf->path.len + 1 + ctx->name.len + sizeof(".m3u8");
    if (hacf->nested) {
        len += ctx->name.len + 1;
    }

    ctx->playlist.data = ngx_palloc(s->connection->pool, len);
    p = ngx_cpymem(ctx->playlist.data, hacf->path.data, hacf->path.len);

    if (p[-1] != '/') {
        *p++ = '/';
    }

    if (hacf->nested) {
        p = ngx_cpymem(p, ctx->name.data, ctx->name.len);
        *p++ = '/';
    }

    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);

    /* ctx->stream_path holds initial part of stream file path 
     * however the space for the whole stream path
     * is allocated */

    ctx->stream.len = p - ctx->playlist.data;
    ctx->stream.data = ngx_palloc(s->connection->pool,
                       ctx->stream.len + 1 + NGX_INT64_LEN + sizeof(".ts"));

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

    if (hacf->continuous) {
        ngx_rtmp_hls_restore_stream(s);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_hls_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (hacf == NULL || !hacf->hls || ctx == NULL) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: delete stream");

    ngx_rtmp_hls_close_fragment(s, 1);

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_hls_parse_aac_header(ngx_rtmp_session_t *s, ngx_uint_t *objtype,
    ngx_uint_t *srindex, ngx_uint_t *chconf)
{
    ngx_rtmp_codec_ctx_t   *codec_ctx;
    ngx_chain_t            *cl;
    u_char                 *p, b0, b1;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    cl = codec_ctx->aac_header;

    p = cl->buf->pos;

    if (ngx_rtmp_hls_copy(s, NULL, &p, 2, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_hls_copy(s, &b0, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_hls_copy(s, &b1, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    *objtype = b0 >> 3;
    if (*objtype == 0 || *objtype == 0x1f) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: unsupported adts object type:%ui", *objtype);
        return NGX_ERROR;
    }

    *srindex = ((b0 << 1) & 0x0f) | ((b1 & 0x80) >> 7);
    if (*srindex == 0x0f) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: unsupported adts sample rate:%ui", *srindex);
        return NGX_ERROR;
    }

    *chconf = (b1 >> 3) & 0x0f;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: aac object_type:%ui, sample_rate_index:%ui, "
                   "channel_config:%ui", *objtype, *srindex, *chconf);

    return NGX_OK;
}


static void
ngx_rtmp_hls_update_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t boundary)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_app_conf_t    *hacf;
    ngx_int_t                   restart;
    ngx_rtmp_hls_frag_t        *f;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->opened) {
        f = ngx_rtmp_hls_get_frag(s, ctx->nfrags);
        f->duration = (ts - ctx->frag_ts) / 90000.;
        if (f->duration < hacf->fraglen / 1000.) {
            return;
        }
    }

    if (!boundary) {
        return;
    }

    restart = ctx->opened;

    ngx_rtmp_hls_close_fragment(s, 0);

    ngx_rtmp_hls_open_fragment(s, ts, !restart);
}


static ngx_int_t
ngx_rtmp_hls_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    uint64_t                        dts;
    int64_t                         ddts;
    ngx_rtmp_mpegts_frame_t         frame;
    ngx_buf_t                       out;
    u_char                         *p;
    ngx_uint_t                      objtype, srindex, chconf, size;
    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (hacf == NULL || !hacf->hls || ctx == NULL ||
        codec_ctx == NULL  || h->mlen < 2) 
    {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC ||
        codec_ctx->aac_header == NULL)
    {
        return NGX_OK;
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.dts = (uint64_t) h->timestamp * 90;
    frame.cc = ctx->audio_cc;
    frame.pid = 0x101;
    frame.sid = 0xc0;

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    p = out.last;
    out.last += 7;

    if (ngx_rtmp_hls_parse_aac_header(s, &objtype, &srindex, &chconf)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: aac header error");
        return NGX_OK;
    }

    size = h->mlen - 2 + 7;

    p[0] = 0xff;
    p[1] = 0xf1;
    p[2] = ((objtype - 1) << 6) | (srindex << 2) | ((chconf & 0x04) >> 2);
    p[3] = ((chconf & 0x03) << 6) | ((size >> 11) & 0x03);
    p[4] = (size >> 3);
    p[5] = (size << 5) | 0x1f;
    p[6] = 0xfc;

    ngx_rtmp_hls_chain2buffer(&out, in, 2);

    if (hacf->sync && codec_ctx->sample_rate) {

        /* TODO: We assume here AAC frame size is 1024
         *       Need to handle AAC frames with frame size of 960 */

        dts = ctx->aframe_base + ctx->aframe_num * 90000 * 1024 /
                                 codec_ctx->sample_rate;
        ddts = (int64_t) (dts - frame.dts);

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: sync stat ddts=%L (%.5fs)",
                       ddts, ddts / 90000.);

        if (ddts > (int64_t) hacf->sync * 90 ||
            ddts < (int64_t) hacf->sync * -90)
        {
            ctx->aframe_base = frame.dts;
            ctx->aframe_num  = 0;

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: sync breakup ddts=%L (%.5fs)",
                           ddts, ddts / 90000.);
        } else {
            frame.dts = dts;
        }

        ctx->aframe_num++;
    }

    frame.pts = frame.dts;

    /* Fragment is restarted in video handler.
     * However if video stream is missing then do it here */

    ngx_rtmp_hls_update_fragment(s, frame.dts, codec_ctx->avc_header == NULL);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: audio dts=%uL", frame.dts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->file, &frame, &out) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: audio frame failed");
    }

    ctx->audio_cc = frame.cc;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_get_nal_bytes(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t   *codec_ctx;
    ngx_chain_t            *cl;
    u_char                 *p;
    uint8_t                 nal_bytes;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    cl = codec_ctx->avc_header;

    p = cl->buf->pos;

    if (ngx_rtmp_hls_copy(s, NULL, &p, 9, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    /* NAL size length (1,2,4) */
    if (ngx_rtmp_hls_copy(s, &nal_bytes, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    nal_bytes &= 0x03; /* 2 lsb */

    ++nal_bytes;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: NAL bytes: %ui", (ngx_uint_t) nal_bytes);

    return nal_bytes;
}


static ngx_int_t
ngx_rtmp_hls_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    u_char                         *p;
    uint8_t                         fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                        len, rlen;
    ngx_buf_t                       out;
    uint32_t                        cts;
    ngx_rtmp_mpegts_frame_t         frame;
    ngx_uint_t                      nal_bytes;
    ngx_int_t                       aud_sent, sps_pps_sent, rc;
    static u_char                   buffer[NGX_RTMP_HLS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || !hacf->hls || ctx == NULL || codec_ctx == NULL ||
        codec_ctx->avc_header == NULL || h->mlen < 1)
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

    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
          (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;
    
    rc = ngx_rtmp_hls_get_nal_bytes(s);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: failed to parse NAL bytes");
        return NGX_OK;
    }

    nal_bytes = rc;
    aud_sent = 0;
    sps_pps_sent = 0;

    while (in) {
        if (ngx_rtmp_hls_copy(s, &rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_rtmp_hls_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = src_nal_type & 0x1f;

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: h264 NAL type=%ui, len=%uD",
                       (ngx_uint_t) nal_type, len);

        if (!aud_sent) {
            switch (nal_type) {
                case 1:
                case 5:
                    if (ngx_rtmp_hls_append_aud(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls: error appending AUD NAL");
                    }
                case 9:
                    aud_sent = 1;
                    break;
            }
        }

        switch (nal_type) {
            case 1:
                sps_pps_sent = 0;
                break;
            case 5:
                if (sps_pps_sent) {
                    break;
                }
                if (ngx_rtmp_hls_append_sps_pps(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: error appenging SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
        }

        /* AnnexB prefix */

        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for AnnexB prefix");
            return NGX_OK;
        }

        /* first AnnexB prefix is long (4 bytes) */

        if (out.last == out.pos) {
            *out.last++ = 0;
        }

        *out.last++ = 0;
        *out.last++ = 0;
        *out.last++ = 1;
        *out.last++ = src_nal_type;

        /* NAL body */

        if (out.end - out.last < (ngx_int_t) len) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_rtmp_hls_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.cc = ctx->video_cc;
    frame.dts = (uint64_t) h->timestamp * 90;
    frame.pts = frame.dts + cts * 90;
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = (ftype == 1);

    ngx_rtmp_hls_update_fragment(s, frame.dts, frame.key);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: video pts=%uL, dts=%uL", frame.pts, frame.dts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->file, &frame, &out) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: video frame failed");
    }

    ctx->video_cc = frame.cc;

    return NGX_OK;
}


static void
ngx_rtmp_hls_discontinue(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx == NULL || !ctx->opened) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hld: discontinue");

    ngx_close_file(ctx->file.fd);
    ctx->opened = 0;
}


static ngx_int_t
ngx_rtmp_hls_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_hls_discontinue(s);

    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_hls_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_hls_discontinue(s);

    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_hls_cleanup_dir(ngx_str_t *ppath, ngx_msec_t playlen)
{
    ngx_dir_t               dir;
    time_t                  mtime, max_age;
    ngx_err_t               err;
    ngx_str_t               name, spath;
    u_char                 *p;
    ngx_int_t               nentries, nerased;
    u_char                  path[NGX_MAX_PATH + 1];

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                   "hls: cleanup path='%V' playlen=%M",
                   ppath, playlen);

    if (ngx_open_dir(ppath, &dir) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                      "hls: cleanup open dir failed '%V'", ppath);
        return NGX_ERROR;
    }

    nentries = 0;
    nerased = 0;

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err == NGX_ENOMOREFILES) {
                return nentries - nerased;
            }

            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, err,
                          "hls: cleanup " ngx_read_dir_n
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
                          "hls: cleanup " ngx_de_info_n " \"%V\" failed",
                          &spath);

            continue;
        }

        if (ngx_de_is_dir(&dir)) {

            if (ngx_rtmp_hls_cleanup_dir(&spath, playlen) == 0) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                               "hls: cleanup dir '%V'", &name);

                if (ngx_delete_dir(spath.data) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                                  "hls: cleanup dir error '%V'", &spath);
                } else {
                    nerased++;
                }
            }

            continue;
        }

        if (!ngx_de_is_file(&dir)) {
            continue;
        }

        if (name.len >= 3 && name.data[name.len - 3] == '.' &&
                             name.data[name.len - 2] == 't' &&
                             name.data[name.len - 1] == 's')
        {
            max_age = playlen / 500;

        } else if (name.len >= 5 && name.data[name.len - 5] == '.' &&
                                    name.data[name.len - 4] == 'm' &&
                                    name.data[name.len - 3] == '3' &&
                                    name.data[name.len - 2] == 'u' &&
                                    name.data[name.len - 1] == '8')
        {
            max_age = playlen / 1000;

        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                           "hls: cleanup skip unknown file type '%V'", &name);
            continue;
        }

        mtime = ngx_de_mtime(&dir);
        if (mtime + max_age > ngx_cached_time->sec) {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                       "hls: cleanup '%V' mtime=%T age=%T",
                       &name, mtime, ngx_cached_time->sec - mtime);

        if (ngx_delete_file(spath.data) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                          "hls: cleanup error '%V'", &spath);
            continue;
        }

        nerased++;
    }
}


static time_t
ngx_rtmp_hls_cleanup(void *data)
{
    ngx_rtmp_hls_cleanup_t *cleanup = data;

    ngx_rtmp_hls_cleanup_dir(&cleanup->path, cleanup->playlen);

    return cleanup->playlen / 500;
}


static char *
ngx_rtmp_hls_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_hls_app_conf_t    *hacf = conf;

    ngx_rtmp_hls_cleanup_t     *cleanup;
    ngx_str_t                  *value;

    if (hacf->slot) {
        return "is duplicate";
    }

    value = cf->args->elts;
    hacf->path = value[1];

    if (hacf->path.data[hacf->path.len - 1] == '/') {
        hacf->path.len--;
    }

    cleanup = ngx_pcalloc(cf->pool, sizeof(*cleanup));
    if (cleanup == NULL) {
        return NGX_CONF_ERROR;
    }

    cleanup->path = hacf->path;

    hacf->slot = ngx_pcalloc(cf->pool, sizeof(*hacf->slot));
    if (hacf->slot == NULL) {
        return NGX_CONF_ERROR;
    }

    hacf->slot->manager = ngx_rtmp_hls_cleanup;
    hacf->slot->name = hacf->path;
    hacf->slot->data = cleanup;
    hacf->slot->conf_file = cf->conf_file->file.name.data;
    hacf->slot->line = cf->conf_file->line;

    if (ngx_add_path(cf, &hacf->slot) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hls_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hls_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hls = NGX_CONF_UNSET;
    conf->fraglen = NGX_CONF_UNSET;
    conf->muxdelay = NGX_CONF_UNSET;
    conf->sync = NGX_CONF_UNSET;
    conf->playlen = NGX_CONF_UNSET;
    conf->continuous = NGX_CONF_UNSET;
    conf->nested = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hls_app_conf_t    *prev = parent;
    ngx_rtmp_hls_app_conf_t    *conf = child;
    ngx_rtmp_hls_cleanup_t     *cleanup;

    ngx_conf_merge_value(conf->hls, prev->hls, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->muxdelay, prev->muxdelay, 700);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 300);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_value(conf->continuous, prev->continuous, 1);
    ngx_conf_merge_value(conf->nested, prev->nested, 0);

    if (conf->fraglen) {
        conf->winfrags = conf->playlen / conf->fraglen;
    }

    if (conf->slot) {
        cleanup = conf->slot->data;
        if (cleanup->playlen < conf->playlen) {
            cleanup->playlen = conf->playlen;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hls_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hls_audio;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hls_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hls_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_hls_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_hls_stream_eof;

    return NGX_OK;
}
