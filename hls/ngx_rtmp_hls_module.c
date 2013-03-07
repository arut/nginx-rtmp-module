/*
 * Copyright (c) 2013 Roman Arutyunyan
 */


#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_rtmp_mpegts.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_delete_stream_pt        next_delete_stream;


static ngx_int_t ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)

#define NGX_RTMP_HLS_DIR_ACCESS         0744


typedef struct {
    unsigned                            publishing:1;
    unsigned                            opened:1;

    ngx_file_t                          file;

    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           name;

    uint64_t                            frag;

    ngx_uint_t                          audio_cc;
    ngx_uint_t                          video_cc;

    int64_t                             aframe_base;
    int64_t                             aframe_num;

    uint64_t                            offset;
} ngx_rtmp_hls_ctx_t;


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          fraglen;
    ngx_msec_t                          muxdelay;
    ngx_msec_t                          sync;
    ngx_msec_t                          playlen;
    ngx_int_t                           factor;
    ngx_uint_t                          winfrags;
    ngx_uint_t                          nfrags;
    ngx_flag_t                          continuous;
    ngx_flag_t                          nodelete;
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

    { ngx_string("hls_continuous"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, continuous),
      NULL },

    { ngx_string("hls_nodelete"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, nodelete),
      NULL },

    { ngx_string("hls_playlist_factor"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, factor),
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


#define ngx_rtmp_hls_frag(hacf, f) (hacf->nfrags ? (f) % hacf->nfrags : (f))


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
ngx_rtmp_hls_update_playlist(ngx_rtmp_session_t *s)
{
    static u_char                   buffer[1024];
    int                             fd;
    u_char                         *p;
    ngx_rtmp_hls_ctx_t             *ctx;
    ssize_t                         n;
    uint64_t                        ffrag;
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
                      "hls: open failed: '%V'", &ctx->playlist_bak);

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

    ffrag = ctx->frag > hacf->winfrags ?
            ctx->frag - (uint64_t) hacf->winfrags : 1;

    p = ngx_snprintf(buffer, sizeof(buffer), 
                     "#EXTM3U\r\n"
                     "#EXT-X-MEDIA-SEQUENCE:%uL\r\n"
                     "#EXT-X-TARGETDURATION:%ui\r\n"
                     "#EXT-X-ALLOW-CACHE:NO\r\n\r\n",
                     ctx->frag, (ngx_uint_t) (hacf->fraglen / 1000));

    n = write(fd, buffer, p - buffer);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: write failed: '%V'", &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    for (; ffrag < ctx->frag; ++ffrag) {
        p = ngx_snprintf(buffer, sizeof(buffer), 
                         "#EXTINF:%i,\r\n"
                         "%V-%uL.ts\r\n", 
                         (ngx_int_t) (hacf->fraglen / 1000), &ctx->name,
                         ngx_rtmp_hls_frag(hacf, ffrag));

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


static void 
ngx_rtmp_hls_next_frag(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_app_conf_t    *hacf;
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    if (ctx == NULL || hacf == NULL) {
        return;
    }

    if (ctx->opened) {
        ngx_close_file(ctx->file.fd);
        ctx->opened = 0;
    }

    if (hacf->nfrags == 0 && ctx->frag > 2 * hacf->winfrags &&
        !hacf->nodelete)
    {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%uL.ts",
                     ngx_rtmp_hls_frag(hacf, ctx->frag - 2 * hacf->winfrags))
         = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: delete frag '%s'", ctx->stream.data);

        ngx_delete_file(ctx->stream.data);

    }

    ctx->frag++;

    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "-%uL.ts",
                 ngx_rtmp_hls_frag(hacf, ctx->frag)) = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: open frag '%s', frag=%uL",
                   ctx->stream.data, ctx->frag);

    ngx_memzero(&ctx->file, sizeof(ctx->file));

    ctx->file.log = s->connection->log;

    ngx_str_set(&ctx->file.name, "hls");

    ctx->file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_WRONLY,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error creating fragment file");
        return;
    }

    if (ngx_rtmp_mpegts_write_header(&ctx->file) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error writing fragment header");
        ngx_close_file(ctx->file.fd);
        return;
    }

    ctx->opened = 1;

    ngx_rtmp_hls_update_playlist(s);
}


#define NGX_RTMP_HLS_RESTORE_PREFIX "#EXTM3U\r\n#EXT-X-MEDIA-SEQUENCE:"


static void
ngx_rtmp_hls_restore_stream(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_file_t                      file;
    ssize_t                         ret;
    u_char                          buffer[sizeof(NGX_RTMP_HLS_RESTORE_PREFIX) -
                                           1 + NGX_INT64_LEN];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    ngx_memzero(&file, sizeof(file));

    file.log = s->connection->log;

    ngx_str_set(&file.name, "m3u8");

    file.fd = ngx_open_file(ctx->playlist.data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                            0);
    if (file.fd == NGX_INVALID_FILE) {
        return;
    }

    ret = ngx_read_file(&file, buffer, sizeof(buffer), 0);
    if (ret <= 0) {
        goto done;
    }

    if ((size_t) ret < sizeof(NGX_RTMP_HLS_RESTORE_PREFIX)) {
        goto done;
    }

    if (ngx_strncmp(buffer, NGX_RTMP_HLS_RESTORE_PREFIX,
                    sizeof(NGX_RTMP_HLS_RESTORE_PREFIX) - 1))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: failed to restore stream");
        goto done;
    }

    buffer[ret] = 0;

    ctx->frag = strtod((const char *)
                       &buffer[sizeof(NGX_RTMP_HLS_RESTORE_PREFIX) - 1], NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: restored frag=%uL", ctx->frag);

done:
    ngx_close_file(file.fd);
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

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    }

    ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));

    /*TODO: escaping does not solve the problem*/

    len = ngx_strlen(v->name);
    ctx->name.len = len + (ngx_uint_t) ngx_escape_uri(NULL, v->name, len, 
                    NGX_ESCAPE_URI_COMPONENT);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len);

    ngx_escape_uri(ctx->name.data, v->name, len, NGX_ESCAPE_URI_COMPONENT);

    ctx->playlist.data = ngx_palloc(s->connection->pool,
                                    hacf->path.len + 1 + ctx->name.len +
                                    sizeof(".m3u8"));
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

    ctx->publishing = 1;

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

    if (hacf == NULL || !hacf->hls || ctx == NULL || !ctx->publishing) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: delete");

    ctx->publishing = 0;

    if (ctx->opened) {
        ngx_close_file(ctx->file.fd);
        ctx->opened = 0;
    }

next:
    return next_delete_stream(s, v);
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

    (*objtype)--;

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
ngx_rtmp_hls_set_frag(ngx_rtmp_session_t *s, uint64_t ts)
{
    ngx_rtmp_hls_app_conf_t    *hacf;
    ngx_rtmp_hls_ctx_t         *ctx;
    uint64_t                    frag;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    frag = ts / hacf->fraglen / 90;

    if (frag == ctx->frag && ctx->opened) {
        return;
    }

    if (frag != ctx->frag + 1) {
        ctx->offset = (ctx->frag + 1) * (uint64_t) hacf->fraglen * 90 - ts;
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: time gap offset=%uL", ctx->offset);
    }

    ngx_rtmp_hls_next_frag(s);
}


static ngx_int_t
ngx_rtmp_hls_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
    ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    int64_t                         dts, ddts;
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

    frame.dts = (uint64_t) h->timestamp * 90 + ctx->offset;
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
    p[2] = (objtype << 6) | (srindex << 2) | (chconf & 0x04);
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
        ddts = dts - frame.dts;

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

    if (codec_ctx->avc_header == NULL) {
        ngx_rtmp_hls_set_frag(s, frame.dts);
    }

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
    frame.dts = (uint64_t) h->timestamp * 90 + ctx->offset;
    frame.pts = frame.dts + cts * 90;
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = (ftype == 1);

    if (frame.key) {
        ngx_rtmp_hls_set_frag(s, frame.dts);
    }

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
    conf->continuous = NGX_CONF_UNSET;
    conf->nodelete = NGX_CONF_UNSET;
    conf->factor = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hls_app_conf_t *prev = parent;
    ngx_rtmp_hls_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->hls, prev->hls, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->muxdelay, prev->muxdelay, 700);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 300);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_value(conf->continuous, prev->continuous, 1);
    ngx_conf_merge_value(conf->nodelete, prev->nodelete, 0);
    ngx_conf_merge_value(conf->factor, prev->factor, 2);

    if (conf->fraglen) {
        conf->winfrags = conf->playlen / conf->fraglen;
        conf->nfrags = conf->winfrags * conf->factor;
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

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_hls_delete_stream;

    return NGX_OK;
}
