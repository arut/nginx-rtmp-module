
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_streams.h"


static ngx_int_t ngx_rtmp_mp4_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_mp4_init(ngx_rtmp_session_t *s,  ngx_file_t *f,
       ngx_int_t aindex, ngx_int_t vindex);
static ngx_int_t ngx_rtmp_mp4_done(ngx_rtmp_session_t *s,  ngx_file_t *f);
static ngx_int_t ngx_rtmp_mp4_start(ngx_rtmp_session_t *s, ngx_file_t *f);
static ngx_int_t ngx_rtmp_mp4_seek(ngx_rtmp_session_t *s,  ngx_file_t *f,
                                   ngx_uint_t offset);
static ngx_int_t ngx_rtmp_mp4_stop(ngx_rtmp_session_t *s,  ngx_file_t *f);
static ngx_int_t ngx_rtmp_mp4_send(ngx_rtmp_session_t *s,  ngx_file_t *f,
                                   ngx_uint_t *ts);
static ngx_int_t ngx_rtmp_mp4_reset(ngx_rtmp_session_t *s);


#define NGX_RTMP_MP4_MAX_FRAMES         8


#pragma pack(push,4)


/* disable zero-sized array warning by msvc */

#if (NGX_WIN32)
#pragma warning(push)
#pragma warning(disable:4200)
#endif


typedef struct {
    uint32_t                            first_chunk;
    uint32_t                            samples_per_chunk;
    uint32_t                            sample_descrption_index;
} ngx_rtmp_mp4_chunk_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    ngx_rtmp_mp4_chunk_entry_t          entries[0];
} ngx_rtmp_mp4_chunks_t;


typedef struct {
    uint32_t                            sample_count;
    uint32_t                            sample_delta;
} ngx_rtmp_mp4_time_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    ngx_rtmp_mp4_time_entry_t           entries[0];
} ngx_rtmp_mp4_times_t;


typedef struct {
    uint32_t                            sample_count;
    uint32_t                            sample_offset;
} ngx_rtmp_mp4_delay_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    ngx_rtmp_mp4_delay_entry_t          entries[0];
} ngx_rtmp_mp4_delays_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint32_t                            entries[0];
} ngx_rtmp_mp4_keys_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            sample_size;
    uint32_t                            sample_count;
    uint32_t                            entries[0];
} ngx_rtmp_mp4_sizes_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            field_size;
    uint32_t                            sample_count;
    uint32_t                            entries[0];
} ngx_rtmp_mp4_sizes2_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint32_t                            entries[0];
} ngx_rtmp_mp4_offsets_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint64_t                            entries[0];
} ngx_rtmp_mp4_offsets64_t;


#if (NGX_WIN32)
#pragma warning(pop)
#endif


#pragma pack(pop)


typedef struct {
    uint32_t                            timestamp;
    uint32_t                            last_timestamp;
    off_t                               offset;
    size_t                              size;
    ngx_int_t                           key;
    uint32_t                            delay;

    unsigned                            not_first:1;
    unsigned                            valid:1;

    ngx_uint_t                          pos;

    ngx_uint_t                          key_pos;

    ngx_uint_t                          chunk;
    ngx_uint_t                          chunk_pos;
    ngx_uint_t                          chunk_count;

    ngx_uint_t                          time_pos;
    ngx_uint_t                          time_count;

    ngx_uint_t                          delay_pos;
    ngx_uint_t                          delay_count;

    ngx_uint_t                          size_pos;
} ngx_rtmp_mp4_cursor_t;


typedef struct {
    ngx_uint_t                          id;

    ngx_int_t                           type;
    ngx_int_t                           codec;
    uint32_t                            csid;
    u_char                              fhdr;
    ngx_int_t                           time_scale;
    uint64_t                            duration;

    u_char                             *header;
    size_t                              header_size;
    unsigned                            header_sent:1;

    ngx_rtmp_mp4_times_t               *times;
    ngx_rtmp_mp4_delays_t              *delays;
    ngx_rtmp_mp4_keys_t                *keys;
    ngx_rtmp_mp4_chunks_t              *chunks;
    ngx_rtmp_mp4_sizes_t               *sizes;
    ngx_rtmp_mp4_sizes2_t              *sizes2;
    ngx_rtmp_mp4_offsets_t             *offsets;
    ngx_rtmp_mp4_offsets64_t           *offsets64;
    ngx_rtmp_mp4_cursor_t               cursor;
} ngx_rtmp_mp4_track_t;


typedef struct {
    void                               *mmaped;
    size_t                              mmaped_size;
    ngx_fd_t                            extra;

    unsigned                            meta_sent:1;

    ngx_rtmp_mp4_track_t                tracks[2];
    ngx_rtmp_mp4_track_t               *track;
    ngx_uint_t                          ntracks;

    ngx_uint_t                          width;
    ngx_uint_t                          height;
    ngx_uint_t                          nchannels;
    ngx_uint_t                          sample_size;
    ngx_uint_t                          sample_rate;

    ngx_int_t                           atracks, vtracks;
    ngx_int_t                           aindex, vindex;

    uint32_t                            start_timestamp, epoch;
} ngx_rtmp_mp4_ctx_t;


#define ngx_rtmp_mp4_make_tag(a, b, c, d)  \
    ((uint32_t)d << 24 | (uint32_t)c << 16 | (uint32_t)b << 8 | (uint32_t)a)


static ngx_inline uint32_t
ngx_rtmp_mp4_to_rtmp_timestamp(ngx_rtmp_mp4_track_t *t, uint64_t ts)
{
    return (uint32_t) (ts * 1000 / t->time_scale);
}


static ngx_inline uint32_t
ngx_rtmp_mp4_from_rtmp_timestamp(ngx_rtmp_mp4_track_t *t, uint32_t ts)
{
    return (uint64_t) ts * t->time_scale / 1000;
}


#define NGX_RTMP_MP4_BUFLEN_ADDON       1000


static u_char                           ngx_rtmp_mp4_buffer[1024*1024];


#if (NGX_WIN32)
static void *
ngx_rtmp_mp4_mmap(ngx_fd_t fd, size_t size, off_t offset, ngx_fd_t *extra)
{
    void           *data;

    *extra = CreateFileMapping(fd, NULL, PAGE_READONLY,
                               (DWORD) ((uint64_t) size >> 32),
                               (DWORD) (size & 0xffffffff),
                               NULL);
    if (*extra == NULL) {
        return NULL;
    }

    data = MapViewOfFile(*extra, FILE_MAP_READ,
                         (DWORD) ((uint64_t) offset >> 32),
                         (DWORD) (offset & 0xffffffff),
                         size);

    if (data == NULL) {
        CloseHandle(*extra);
    }

    /*
     * non-NULL result means map view handle is open
     * and should be closed later
     */

    return data;
}


static ngx_int_t
ngx_rtmp_mp4_munmap(void *data, size_t size, ngx_fd_t *extra)
{
    ngx_int_t  rc;

    rc = NGX_OK;

    if (UnmapViewOfFile(data) == 0) {
        rc = NGX_ERROR;
    }

    if (CloseHandle(*extra) == 0) {
        rc = NGX_ERROR;
    }

    return rc;
}

#else

static void *
ngx_rtmp_mp4_mmap(ngx_fd_t fd, size_t size, off_t offset, ngx_fd_t *extra)
{
    void  *data;

    data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);

    /* valid address is never NULL since there's no MAP_FIXED */

    return data == MAP_FAILED ? NULL : data;
}


static ngx_int_t
ngx_rtmp_mp4_munmap(void *data, size_t size, ngx_fd_t *extra)
{
    return munmap(data, size);
}

#endif


static ngx_int_t ngx_rtmp_mp4_parse(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_trak(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_mdhd(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_hdlr(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stsd(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stsc(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stts(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_ctts(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stss(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stsz(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stz2(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_stco(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_co64(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_avc1(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_avcC(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_mp4a(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_mp4v(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_esds(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_mp3(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_nmos(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_spex(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);


typedef ngx_int_t (*ngx_rtmp_mp4_box_pt)(ngx_rtmp_session_t *s, u_char *pos,
                                         u_char *last);

typedef struct {
    uint32_t                            tag;
    ngx_rtmp_mp4_box_pt                 handler;
} ngx_rtmp_mp4_box_t;


static ngx_rtmp_mp4_box_t                       ngx_rtmp_mp4_boxes[] = {
    { ngx_rtmp_mp4_make_tag('t','r','a','k'),   ngx_rtmp_mp4_parse_trak   },
    { ngx_rtmp_mp4_make_tag('m','d','i','a'),   ngx_rtmp_mp4_parse        },
    { ngx_rtmp_mp4_make_tag('m','d','h','d'),   ngx_rtmp_mp4_parse_mdhd   },
    { ngx_rtmp_mp4_make_tag('h','d','l','r'),   ngx_rtmp_mp4_parse_hdlr   },
    { ngx_rtmp_mp4_make_tag('m','i','n','f'),   ngx_rtmp_mp4_parse        },
    { ngx_rtmp_mp4_make_tag('s','t','b','l'),   ngx_rtmp_mp4_parse        },
    { ngx_rtmp_mp4_make_tag('s','t','s','d'),   ngx_rtmp_mp4_parse_stsd   },
    { ngx_rtmp_mp4_make_tag('s','t','s','c'),   ngx_rtmp_mp4_parse_stsc   },
    { ngx_rtmp_mp4_make_tag('s','t','t','s'),   ngx_rtmp_mp4_parse_stts   },
    { ngx_rtmp_mp4_make_tag('c','t','t','s'),   ngx_rtmp_mp4_parse_ctts   },
    { ngx_rtmp_mp4_make_tag('s','t','s','s'),   ngx_rtmp_mp4_parse_stss   },
    { ngx_rtmp_mp4_make_tag('s','t','s','z'),   ngx_rtmp_mp4_parse_stsz   },
    { ngx_rtmp_mp4_make_tag('s','t','z','2'),   ngx_rtmp_mp4_parse_stz2   },
    { ngx_rtmp_mp4_make_tag('s','t','c','o'),   ngx_rtmp_mp4_parse_stco   },
    { ngx_rtmp_mp4_make_tag('c','o','6','4'),   ngx_rtmp_mp4_parse_co64   },
    { ngx_rtmp_mp4_make_tag('a','v','c','1'),   ngx_rtmp_mp4_parse_avc1   },
    { ngx_rtmp_mp4_make_tag('a','v','c','C'),   ngx_rtmp_mp4_parse_avcC   },
    { ngx_rtmp_mp4_make_tag('m','p','4','a'),   ngx_rtmp_mp4_parse_mp4a   },
    { ngx_rtmp_mp4_make_tag('m','p','4','v'),   ngx_rtmp_mp4_parse_mp4v   },
    { ngx_rtmp_mp4_make_tag('e','s','d','s'),   ngx_rtmp_mp4_parse_esds   },
    { ngx_rtmp_mp4_make_tag('.','m','p','3'),   ngx_rtmp_mp4_parse_mp3    },
    { ngx_rtmp_mp4_make_tag('n','m','o','s'),   ngx_rtmp_mp4_parse_nmos   },
    { ngx_rtmp_mp4_make_tag('s','p','e','x'),   ngx_rtmp_mp4_parse_spex   },
    { ngx_rtmp_mp4_make_tag('w','a','v','e'),   ngx_rtmp_mp4_parse        }
};


static ngx_int_t ngx_rtmp_mp4_parse_descr(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_es(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_dc(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);
static ngx_int_t ngx_rtmp_mp4_parse_ds(ngx_rtmp_session_t *s, u_char *pos,
       u_char *last);


typedef ngx_int_t (*ngx_rtmp_mp4_descriptor_pt)(ngx_rtmp_session_t *s,
                                                u_char *pos, u_char *last);

typedef struct {
    uint8_t                             tag;
    ngx_rtmp_mp4_descriptor_pt          handler;
} ngx_rtmp_mp4_descriptor_t;


static ngx_rtmp_mp4_descriptor_t        ngx_rtmp_mp4_descriptors[] = {
    { 0x03,   ngx_rtmp_mp4_parse_es   },    /* MPEG ES Descriptor */
    { 0x04,   ngx_rtmp_mp4_parse_dc   },    /* MPEG DecoderConfig Descriptor */
    { 0x05,   ngx_rtmp_mp4_parse_ds   }     /* MPEG DecoderSpec Descriptor */
};


static ngx_rtmp_module_t  ngx_rtmp_mp4_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_mp4_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_mp4_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_mp4_module_ctx,               /* module context */
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
ngx_rtmp_mp4_parse_trak(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track) {
        return NGX_OK;
    }

    ctx->track = (ctx->ntracks == sizeof(ctx->tracks) / sizeof(ctx->tracks[0]))
                 ? NULL : &ctx->tracks[ctx->ntracks];

    if (ctx->track) {
        ngx_memzero(ctx->track, sizeof(*ctx->track));
        ctx->track->id = ctx->ntracks;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: trying track %ui", ctx->ntracks);
    }

    if (ngx_rtmp_mp4_parse(s, pos, last) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->track && ctx->track->type &&
        (ctx->ntracks == 0 ||
         ctx->tracks[0].type != ctx->tracks[ctx->ntracks].type))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: adding track %ui", ctx->ntracks);

        if (ctx->track->type == NGX_RTMP_MSG_AUDIO) {
            if (ctx->atracks++ != ctx->aindex) {
                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "mp4: skipping audio track %ui!=%ui",
                               ctx->atracks - 1, ctx->aindex);
                ctx->track = NULL;
                return NGX_OK;
            }

        } else {
            if (ctx->vtracks++ != ctx->vindex) {
                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "mp4: skipping video track %i!=%i",
                               ctx->vtracks - 1, ctx->vindex);
                ctx->track = NULL;
                return NGX_OK;
            }
        }

        ++ctx->ntracks;

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: ignoring track %ui", ctx->ntracks);
    }

    ctx->track = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_mdhd(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;
    uint8_t                     version;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL) {
        return NGX_OK;
    }

    t = ctx->track;

    if (pos + 1 > last) {
        return NGX_ERROR;
    }

    version = *(uint8_t *) pos;

    switch (version) {
        case 0:
            if (pos + 20 > last) {
                return NGX_ERROR;
            }

            pos += 12;
            t->time_scale = ngx_rtmp_r32(*(uint32_t *) pos);
            pos += 4;
            t->duration = ngx_rtmp_r32(*(uint32_t *) pos);
            break;

        case 1:
            if (pos + 28 > last) {
                return NGX_ERROR;
            }

            pos += 20;
            t->time_scale = ngx_rtmp_r32(*(uint32_t *) pos);
            pos += 4;
            t->duration = ngx_rtmp_r64(*(uint64_t *) pos);
            break;

        default:
            return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: duration time_scale=%ui duration=%uL",
                   t->time_scale, t->duration);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_hdlr(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    uint32_t                    type;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL) {
        return NGX_OK;
    }

    if (pos + 12 > last) {
        return NGX_ERROR;
    }

    type = *(uint32_t *)(pos + 8);

    if (type == ngx_rtmp_mp4_make_tag('v','i','d','e')) {
        ctx->track->type = NGX_RTMP_MSG_VIDEO;
        ctx->track->csid = NGX_RTMP_CSID_VIDEO;

        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: video track");

    } else if (type == ngx_rtmp_mp4_make_tag('s','o','u','n')) {
        ctx->track->type = NGX_RTMP_MSG_AUDIO;
        ctx->track->csid = NGX_RTMP_CSID_AUDIO;

        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: audio track");
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: unknown track");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_video(ngx_rtmp_session_t *s, u_char *pos, u_char *last,
                         ngx_int_t codec)
{
    ngx_rtmp_mp4_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL) {
        return NGX_OK;
    }

    ctx->track->codec = codec;

    if (pos + 78 > last) {
        return NGX_ERROR;
    }

    pos += 24;

    ctx->width = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 2;

    ctx->height = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 52;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: video settings codec=%i, width=%ui, height=%ui",
                   codec, ctx->width, ctx->height);

    if (ngx_rtmp_mp4_parse(s, pos, last) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->track->fhdr = (u_char) ctx->track->codec;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_audio(ngx_rtmp_session_t *s, u_char *pos, u_char *last,
                         ngx_int_t codec)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    u_char                     *p;
    ngx_uint_t                  version;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL) {
        return NGX_OK;
    }

    ctx->track->codec = codec;

    if (pos + 28 > last) {
        return NGX_ERROR;
    }

    pos += 8;

    version = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 8;

    ctx->nchannels = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 2;

    ctx->sample_size = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 6;

    ctx->sample_rate = ngx_rtmp_r16(*(uint16_t *) pos);

    pos += 4;

    p = &ctx->track->fhdr;

    *p = 0;

    if (ctx->nchannels == 2) {
        *p |= 0x01;
    }

    if (ctx->sample_size == 16) {
        *p |= 0x02;
    }

    switch (ctx->sample_rate) {
        case 5512:
            break;

        case 11025:
            *p |= 0x04;
            break;

        case 22050:
            *p |= 0x08;
            break;

        default:  /*44100 etc */
            *p |= 0x0c;
            break;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: audio settings version=%ui, codec=%i, nchannels==%ui, "
                   "sample_size=%ui, sample_rate=%ui",
                   version, codec, ctx->nchannels, ctx->sample_size,
                   ctx->sample_rate);

    switch (version) {
        case 1:
            pos += 16;
            break;

        case 2:
            pos += 36;
    }

    if (pos > last) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_mp4_parse(s, pos, last) != NGX_OK) {
        return NGX_ERROR;
    }

    *p |= (ctx->track->codec << 4);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_avc1(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_video(s, pos, last, NGX_RTMP_VIDEO_H264);
}


static ngx_int_t
ngx_rtmp_mp4_parse_mp4v(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_video(s, pos, last, NGX_RTMP_VIDEO_H264);
}


static ngx_int_t
ngx_rtmp_mp4_parse_avcC(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;

    if (pos == last) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL || ctx->track->codec != NGX_RTMP_VIDEO_H264) {
        return NGX_OK;
    }

    ctx->track->header = pos;
    ctx->track->header_size = (size_t) (last - pos);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: video h264 header size=%uz",
                   ctx->track->header_size);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_mp4a(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_audio(s, pos, last, NGX_RTMP_AUDIO_MP3);
}


static ngx_int_t
ngx_rtmp_mp4_parse_ds(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t     *ctx;
    ngx_rtmp_mp4_track_t   *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->header = pos;
    t->header_size = (size_t) (last - pos);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: decoder header size=%uz", t->header_size);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_dc(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    uint8_t                 id;
    ngx_rtmp_mp4_ctx_t     *ctx;
    ngx_int_t              *pc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx->track == NULL) {
        return NGX_OK;
    }

    if (pos + 13 > last) {
        return NGX_ERROR;
    }

    id = * (uint8_t *) pos;
    pos += 13;
    pc = &ctx->track->codec;

    switch (id) {
        case 0x21:
            *pc = NGX_RTMP_VIDEO_H264;
            break;

        case 0x40:
        case 0x66:
        case 0x67:
        case 0x68:
            *pc = NGX_RTMP_AUDIO_AAC;
            break;

        case 0x69:
        case 0x6b:
            *pc = NGX_RTMP_AUDIO_MP3;
            break;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: decoder descriptor id=%i codec=%i",
                   (ngx_int_t) id, *pc);

    return ngx_rtmp_mp4_parse_descr(s, pos, last);
}


static ngx_int_t
ngx_rtmp_mp4_parse_es(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    uint16_t    id;
    uint8_t     flags;

    if (pos + 3 > last) {
        return NGX_ERROR;
    }

    id = ngx_rtmp_r16(*(uint16_t *) pos);
    pos += 2;

    flags = *(uint8_t *) pos;
    ++pos;

    if (flags & 0x80) { /* streamDependenceFlag */
        pos += 2;
    }

    if (flags & 0x40) { /* URL_FLag */
        return NGX_OK;
    }

    if (flags & 0x20) { /* OCRstreamFlag */
        pos += 2;
    }

    if (pos > last) {
        return NGX_ERROR;
    }

    (void) id;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: es descriptor es id=%i flags=%i",
                   (ngx_int_t) id, (ngx_int_t) flags);

    return ngx_rtmp_mp4_parse_descr(s, pos, last);
}


static ngx_int_t
ngx_rtmp_mp4_parse_descr(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    uint8_t                     tag, v;
    uint32_t                    size;
    ngx_uint_t                  n, ndesc;
    ngx_rtmp_mp4_descriptor_t   *ds;

    ndesc = sizeof(ngx_rtmp_mp4_descriptors)
          / sizeof(ngx_rtmp_mp4_descriptors[0]);

    while (pos < last) {
        tag = *(uint8_t *) pos++;

        for (size = 0, n = 0; n < 4; ++n) {
            if (pos == last) {
                return NGX_ERROR;
            }

            v = *(uint8_t *) pos++;

            size = (size << 7) | (v & 0x7f);

            if (!(v & 0x80)) {
                break;
            }
        }

        if (pos + size > last) {
            return NGX_ERROR;
        }

        ds = ngx_rtmp_mp4_descriptors;;

        for (n = 0; n < ndesc; ++n, ++ds) {
            if (tag == ds->tag) {
                break;
            }
        }

        if (n == ndesc) {
            ds = NULL;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: descriptor%s tag=%i size=%uD",
                ds ? "" : " unhandled", (ngx_int_t) tag, size);

        if (ds && ds->handler(s, pos, pos + size) != NGX_OK) {
            return NGX_ERROR;
        }

        pos += size;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_esds(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    if (pos + 4 > last) {
        return NGX_ERROR;
    }

    pos += 4; /* version */

    return ngx_rtmp_mp4_parse_descr(s, pos, last);
}


static ngx_int_t
ngx_rtmp_mp4_parse_mp3(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_audio(s, pos, last, NGX_RTMP_AUDIO_MP3);
}


static ngx_int_t
ngx_rtmp_mp4_parse_nmos(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_audio(s, pos, last, NGX_RTMP_AUDIO_NELLY);
}


static ngx_int_t
ngx_rtmp_mp4_parse_spex(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    return ngx_rtmp_mp4_parse_audio(s, pos, last, NGX_RTMP_AUDIO_SPEEX);
}


static ngx_int_t
ngx_rtmp_mp4_parse_stsd(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    if (pos + 8 > last) {
        return NGX_ERROR;
    }

    pos += 8;

    ngx_rtmp_mp4_parse(s, pos, last);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stsc(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->chunks = (ngx_rtmp_mp4_chunks_t *) pos;

    if (pos + sizeof(*t->chunks) + ngx_rtmp_r32(t->chunks->entry_count) *
                                   sizeof(t->chunks->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: chunks entries=%uD",
                       ngx_rtmp_r32(t->chunks->entry_count));
        return NGX_OK;
    }

    t->chunks = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stts(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->times = (ngx_rtmp_mp4_times_t *) pos;

    if (pos + sizeof(*t->times) + ngx_rtmp_r32(t->times->entry_count) *
                                  sizeof(t->times->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: times entries=%uD",
                       ngx_rtmp_r32(t->times->entry_count));
        return NGX_OK;
    }

    t->times = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_ctts(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->delays = (ngx_rtmp_mp4_delays_t *) pos;

    if (pos + sizeof(*t->delays) + ngx_rtmp_r32(t->delays->entry_count) *
                                   sizeof(t->delays->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: delays entries=%uD",
                       ngx_rtmp_r32(t->delays->entry_count));
        return NGX_OK;
    }

    t->delays = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stss(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->keys = (ngx_rtmp_mp4_keys_t *) pos;

    if (pos + sizeof(*t->keys) + ngx_rtmp_r32(t->keys->entry_count) *
                                  sizeof(t->keys->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: keys entries=%uD",
                       ngx_rtmp_r32(t->keys->entry_count));
        return NGX_OK;
    }

    t->keys = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stsz(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->sizes = (ngx_rtmp_mp4_sizes_t *) pos;

    if (pos + sizeof(*t->sizes) <= last && t->sizes->sample_size) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: sizes size=%uD",
                       ngx_rtmp_r32(t->sizes->sample_size));
        return NGX_OK;
    }

    if (pos + sizeof(*t->sizes) + ngx_rtmp_r32(t->sizes->sample_count) *
                                  sizeof(t->sizes->entries[0])
        <= last)

    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: sizes entries=%uD",
                       ngx_rtmp_r32(t->sizes->sample_count));
        return NGX_OK;
    }

    t->sizes = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stz2(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->sizes2 = (ngx_rtmp_mp4_sizes2_t *) pos;

    if (pos + sizeof(*t->sizes) + ngx_rtmp_r32(t->sizes2->sample_count) *
                                  ngx_rtmp_r32(t->sizes2->field_size) / 8
        <= last)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: sizes2 field_size=%uD entries=%uD",
                       ngx_rtmp_r32(t->sizes2->field_size),
                       ngx_rtmp_r32(t->sizes2->sample_count));
        return NGX_OK;
    }

    t->sizes2 = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_stco(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->offsets = (ngx_rtmp_mp4_offsets_t *) pos;

    if (pos + sizeof(*t->offsets) + ngx_rtmp_r32(t->offsets->entry_count) *
                                    sizeof(t->offsets->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: offsets entries=%uD",
                       ngx_rtmp_r32(t->offsets->entry_count));
        return NGX_OK;
    }

    t->offsets = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse_co64(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    ngx_rtmp_mp4_track_t       *t;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    t = ctx->track;

    if (t == NULL) {
        return NGX_OK;
    }

    t->offsets64 = (ngx_rtmp_mp4_offsets64_t *) pos;

    if (pos + sizeof(*t->offsets64) + ngx_rtmp_r32(t->offsets64->entry_count) *
                                      sizeof(t->offsets64->entries[0])
        <= last)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: offsets64 entries=%uD",
                       ngx_rtmp_r32(t->offsets64->entry_count));
        return NGX_OK;
    }

    t->offsets64 = NULL;
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_parse(ngx_rtmp_session_t *s, u_char *pos, u_char *last)
{
    uint32_t                   *hdr, tag;
    size_t                      size, nboxes;
    ngx_uint_t                  n;
    ngx_rtmp_mp4_box_t         *b;

    while (pos != last) {
        if (pos + 8 > last) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: too small box: size=%i", last - pos);
            return NGX_ERROR;
        }

        hdr = (uint32_t *) pos;
        size = ngx_rtmp_r32(hdr[0]);
        tag  = hdr[1];

        if (pos + size > last) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "mp4: too big box '%*s': size=%uz",
                          4, &tag, size);
            return NGX_ERROR;
        }

        b = ngx_rtmp_mp4_boxes;
        nboxes = sizeof(ngx_rtmp_mp4_boxes) / sizeof(ngx_rtmp_mp4_boxes[0]);

        for (n = 0; n < nboxes && b->tag != tag; ++n, ++b);

        if (n == nboxes) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: box unhandled '%*s'", 4, &tag);
        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: box '%*s'", 4, &tag);
            b->handler(s, pos + 8, pos + size);
        }

        pos += size;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_next_time(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t      *cr;
    ngx_rtmp_mp4_time_entry_t  *te;

    if (t->times == NULL) {
        return NGX_ERROR;
    }

    cr = &t->cursor;

    if (cr->time_pos >= ngx_rtmp_r32(t->times->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui time[%ui/%uD] overflow",
                       t->id, cr->time_pos,
                       ngx_rtmp_r32(t->times->entry_count));

        return NGX_ERROR;
    }

    te = &t->times->entries[cr->time_pos];

    cr->last_timestamp = cr->timestamp;
    cr->timestamp += ngx_rtmp_r32(te->sample_delta);

    cr->not_first = 1;

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui time[%ui] [%ui/%uD][%ui/%uD]=%uD t=%uD",
                   t->id, cr->pos, cr->time_pos,
                   ngx_rtmp_r32(t->times->entry_count),
                   cr->time_count, ngx_rtmp_r32(te->sample_count),
                   ngx_rtmp_r32(te->sample_delta),
                   cr->timestamp);

    cr->time_count++;
    cr->pos++;

    if (cr->time_count >= ngx_rtmp_r32(te->sample_count)) {
        cr->time_pos++;
        cr->time_count = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_seek_time(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t,
                       uint32_t timestamp)
{
    ngx_rtmp_mp4_cursor_t      *cr;
    ngx_rtmp_mp4_time_entry_t  *te;
    uint32_t                    dt;

    if (t->times == NULL) {
        return NGX_ERROR;
    }

    cr = &t->cursor;

    te = t->times->entries;

    while (cr->time_pos < ngx_rtmp_r32(t->times->entry_count)) {
        dt = ngx_rtmp_r32(te->sample_delta) * ngx_rtmp_r32(te->sample_count);

        if (cr->timestamp + dt >= timestamp) {
            if (te->sample_delta == 0) {
                return NGX_ERROR;
            }

            cr->time_count = (timestamp - cr->timestamp) /
                             ngx_rtmp_r32(te->sample_delta);
            cr->timestamp += ngx_rtmp_r32(te->sample_delta) * cr->time_count;
            cr->pos += cr->time_count;

            break;
        }

        cr->timestamp += dt;
        cr->pos += ngx_rtmp_r32(te->sample_count);
        cr->time_pos++;
        te++;
    }

    if (cr->time_pos >= ngx_rtmp_r32(t->times->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui seek time[%ui/%uD] overflow",
                       t->id, cr->time_pos,
                       ngx_rtmp_r32(t->times->entry_count));

        return  NGX_ERROR;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui seek time[%ui] [%ui/%uD][%ui/%uD]=%uD "
                   "t=%uD",
                   t->id, cr->pos, cr->time_pos,
                   ngx_rtmp_r32(t->times->entry_count),
                   cr->time_count,
                   ngx_rtmp_r32(te->sample_count),
                   ngx_rtmp_r32(te->sample_delta),
                   cr->timestamp);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_update_offset(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;
    ngx_uint_t                      chunk;

    cr = &t->cursor;

    if (cr->chunk < 1) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui offset[%ui] underflow",
                       t->id, cr->chunk);
        return NGX_ERROR;
    }

    chunk = cr->chunk - 1;

    if (t->offsets) {
        if (chunk >= ngx_rtmp_r32(t->offsets->entry_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui offset[%ui/%uD] overflow",
                           t->id, cr->chunk,
                           ngx_rtmp_r32(t->offsets->entry_count));

            return NGX_ERROR;
        }

        cr->offset = (off_t) ngx_rtmp_r32(t->offsets->entries[chunk]);
        cr->size = 0;

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui offset[%ui/%uD]=%O",
                       t->id, cr->chunk,
                       ngx_rtmp_r32(t->offsets->entry_count),
                       cr->offset);

        return NGX_OK;
    }

    if (t->offsets64) {
        if (chunk >= ngx_rtmp_r32(t->offsets64->entry_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui offset64[%ui/%uD] overflow",
                           t->id, cr->chunk,
                           ngx_rtmp_r32(t->offsets->entry_count));

            return NGX_ERROR;
        }

        cr->offset = (off_t) ngx_rtmp_r64(t->offsets64->entries[chunk]);
        cr->size = 0;

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui offset64[%ui/%uD]=%O",
                       t->id, cr->chunk,
                       ngx_rtmp_r32(t->offsets->entry_count),
                       cr->offset);

        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_next_chunk(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;
    ngx_rtmp_mp4_chunk_entry_t     *ce, *nce;
    ngx_int_t                       new_chunk;

    if (t->chunks == NULL) {
        return NGX_OK;
    }

    cr = &t->cursor;

    if (cr->chunk_pos >= ngx_rtmp_r32(t->chunks->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui chunk[%ui/%uD] overflow",
                       t->id, cr->chunk_pos,
                       ngx_rtmp_r32(t->chunks->entry_count));

        return NGX_ERROR;
    }

    ce = &t->chunks->entries[cr->chunk_pos];

    cr->chunk_count++;

    if (cr->chunk_count >= ngx_rtmp_r32(ce->samples_per_chunk)) {
        cr->chunk_count = 0;
        cr->chunk++;

        if (cr->chunk_pos + 1 < ngx_rtmp_r32(t->chunks->entry_count)) {
            nce = ce + 1;
            if (cr->chunk >= ngx_rtmp_r32(nce->first_chunk)) {
                cr->chunk_pos++;
                ce = nce;
            }
        }

        new_chunk = 1;

    } else {
        new_chunk = 0;
    }

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui chunk[%ui/%uD][%uD..%ui][%ui/%uD]",
                   t->id, cr->chunk_pos,
                   ngx_rtmp_r32(t->chunks->entry_count),
                   ngx_rtmp_r32(ce->first_chunk),
                   cr->chunk, cr->chunk_count,
                   ngx_rtmp_r32(ce->samples_per_chunk));


    if (new_chunk) {
        return ngx_rtmp_mp4_update_offset(s, t);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_seek_chunk(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;
    ngx_rtmp_mp4_chunk_entry_t     *ce, *nce;
    ngx_uint_t                      pos, dpos, dchunk;

    cr = &t->cursor;

    if (t->chunks == NULL || t->chunks->entry_count == 0) {
        cr->chunk = 1;
        return NGX_OK;
    }

    ce = t->chunks->entries;
    pos = 0;

    while (cr->chunk_pos + 1 < ngx_rtmp_r32(t->chunks->entry_count)) {
        nce = ce + 1;

        dpos = (ngx_rtmp_r32(nce->first_chunk) -
                ngx_rtmp_r32(ce->first_chunk)) *
                ngx_rtmp_r32(ce->samples_per_chunk);

        if (pos + dpos > cr->pos) {
            break;
        }

        pos += dpos;
        ce++;
        cr->chunk_pos++;
    }

    if (ce->samples_per_chunk == 0) {
        return NGX_ERROR;
    }

    dchunk = (cr->pos - pos) / ngx_rtmp_r32(ce->samples_per_chunk);

    cr->chunk = ngx_rtmp_r32(ce->first_chunk) + dchunk;
    cr->chunk_pos = (ngx_uint_t) (ce - t->chunks->entries);
    cr->chunk_count = (ngx_uint_t) (cr->pos - pos - dchunk *
                                    ngx_rtmp_r32(ce->samples_per_chunk));

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui seek chunk[%ui/%uD][%uD..%ui][%ui/%uD]",
                   t->id, cr->chunk_pos,
                   ngx_rtmp_r32(t->chunks->entry_count),
                   ngx_rtmp_r32(ce->first_chunk),
                   cr->chunk, cr->chunk_count,
                   ngx_rtmp_r32(ce->samples_per_chunk));

    return ngx_rtmp_mp4_update_offset(s, t);
}


static ngx_int_t
ngx_rtmp_mp4_next_size(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;

    cr = &t->cursor;

    cr->offset += cr->size;

    if (t->sizes) {
        if (t->sizes->sample_size) {
            cr->size = ngx_rtmp_r32(t->sizes->sample_size);

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui size fix=%uz",
                           t->id, cr->size);

            return NGX_OK;
        }

        cr->size_pos++;

        if (cr->size_pos >= ngx_rtmp_r32(t->sizes->sample_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui size[%ui/%uD] overflow",
                           t->id, cr->size_pos,
                           ngx_rtmp_r32(t->sizes->sample_count));

            return NGX_ERROR;
        }

        cr->size = ngx_rtmp_r32(t->sizes->entries[cr->size_pos]);

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui size[%ui/%uD]=%uz",
                       t->id, cr->size_pos,
                       ngx_rtmp_r32(t->sizes->sample_count),
                       cr->size);

        return NGX_OK;
    }

    if (t->sizes2) {
        if (cr->size_pos >= ngx_rtmp_r32(t->sizes2->sample_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui size[%ui/%uD] overflow",
                           t->id, cr->size_pos,
                           ngx_rtmp_r32(t->sizes2->sample_count));

            return NGX_ERROR;
        }

        /*TODO*/

        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_seek_size(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t      *cr;
    ngx_uint_t                  pos;

    cr = &t->cursor;

    if (cr->chunk_count > cr->pos) {
        return NGX_ERROR;
    }

    if (t->sizes) {
        if (t->sizes->sample_size) {
            cr->size = ngx_rtmp_r32(t->sizes->sample_size);

            cr->offset += cr->size * cr->chunk_count;

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui seek size fix=%uz",
                           t->id, cr->size);

            return NGX_OK;
        }

        if (cr->pos >= ngx_rtmp_r32(t->sizes->sample_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui seek size[%ui/%uD] overflow",
                           t->id, cr->pos,
                           ngx_rtmp_r32(t->sizes->sample_count));

            return NGX_ERROR;
        }

        for (pos = 1; pos <= cr->chunk_count; ++pos) {
            cr->offset += ngx_rtmp_r32(t->sizes->entries[cr->pos - pos]);
        }

        cr->size_pos = cr->pos;
        cr->size = ngx_rtmp_r32(t->sizes->entries[cr->size_pos]);

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui seek size[%ui/%uD]=%uz",
                       t->id, cr->size_pos,
                       ngx_rtmp_r32(t->sizes->sample_count),
                       cr->size);

        return NGX_OK;
    }

    if (t->sizes2) {
        if (cr->size_pos >= ngx_rtmp_r32(t->sizes2->sample_count)) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui seek size2[%ui/%uD] overflow",
                           t->id, cr->size_pos,
                           ngx_rtmp_r32(t->sizes->sample_count));

            return NGX_ERROR;
        }

        cr->size_pos = cr->pos;

        /* TODO */
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_mp4_next_key(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;
    uint32_t                       *ke;

    cr = &t->cursor;

    if (t->keys == NULL) {
        return NGX_OK;
    }

    if (cr->key) {
        cr->key_pos++;
    }

    if (cr->key_pos >= ngx_rtmp_r32(t->keys->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: track#%ui key[%ui/%uD] overflow",
                t->id, cr->key_pos,
                ngx_rtmp_r32(t->keys->entry_count));

        cr->key = 0;

        return NGX_OK;
    }

    ke = &t->keys->entries[cr->key_pos];
    cr->key = (cr->pos + 1 == ngx_rtmp_r32(*ke));

    ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui key[%ui/%uD][%ui/%uD]=%s",
                   t->id, cr->key_pos,
                   ngx_rtmp_r32(t->keys->entry_count),
                   cr->pos, ngx_rtmp_r32(*ke),
                   cr->key ? "match" : "miss");

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_seek_key(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t      *cr;
    uint32_t                   *ke;
    ngx_int_t                   dpos;

    cr = &t->cursor;

    if (t->keys == NULL) {
        return NGX_OK;
    }

    while (cr->key_pos < ngx_rtmp_r32(t->keys->entry_count)) {
        if (ngx_rtmp_r32(t->keys->entries[cr->key_pos]) > cr->pos) {
            break;
        }

        cr->key_pos++;
    }

    if (cr->key_pos >= ngx_rtmp_r32(t->keys->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: track#%ui seek key[%ui/%uD] overflow",
                t->id, cr->key_pos,
                ngx_rtmp_r32(t->keys->entry_count));
        return NGX_OK;
    }

    ke = &t->keys->entries[cr->key_pos];
    /*cr->key = (cr->pos + 1 == ngx_rtmp_r32(*ke));*/

    /* distance to the next keyframe */
    dpos = ngx_rtmp_r32(*ke) - cr->pos - 1;
    cr->key = 1;

    /* TODO: range version needed */
    for (; dpos > 0; --dpos) {
        ngx_rtmp_mp4_next_time(s, t);
    }

/*    cr->key = (cr->pos + 1 == ngx_rtmp_r32(*ke));*/

    ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui seek key[%ui/%uD][%ui/%uD]=%s",
                   t->id, cr->key_pos,
                   ngx_rtmp_r32(t->keys->entry_count),
                   cr->pos, ngx_rtmp_r32(*ke),
                   cr->key ? "match" : "miss");

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_next_delay(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t          *cr;
    ngx_rtmp_mp4_delay_entry_t     *de;

    cr = &t->cursor;

    if (t->delays == NULL) {
        return NGX_OK;
    }

    if (cr->delay_pos >= ngx_rtmp_r32(t->delays->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: track#%ui delay[%ui/%uD] overflow",
                t->id, cr->delay_pos,
                ngx_rtmp_r32(t->delays->entry_count));

        return NGX_OK;
    }

    cr->delay_count++;
    de = &t->delays->entries[cr->delay_pos];

    if (cr->delay_count >= ngx_rtmp_r32(de->sample_count)) {
        cr->delay_pos++;
        de++;
        cr->delay_count = 0;
    }

    if (cr->delay_pos >= ngx_rtmp_r32(t->delays->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: track#%ui delay[%ui/%uD] overflow",
                t->id, cr->delay_pos,
                ngx_rtmp_r32(t->delays->entry_count));

        return NGX_OK;
    }

    cr->delay = ngx_rtmp_r32(de->sample_offset);

    ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui delay[%ui/%uD][%ui/%uD]=%ui",
                   t->id, cr->delay_pos,
                   ngx_rtmp_r32(t->delays->entry_count),
                   cr->delay_count,
                   ngx_rtmp_r32(de->sample_count), cr->delay);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_seek_delay(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    ngx_rtmp_mp4_cursor_t      *cr;
    ngx_rtmp_mp4_delay_entry_t *de;
    uint32_t                    pos, dpos;

    cr = &t->cursor;

    if (t->delays == NULL) {
        return NGX_OK;
    }

    pos = 0;
    de = t->delays->entries;

    while (cr->delay_pos < ngx_rtmp_r32(t->delays->entry_count)) {
        dpos = ngx_rtmp_r32(de->sample_count);

        if (pos + dpos > cr->pos) {
            cr->delay_count = cr->pos - pos;
            cr->delay = ngx_rtmp_r32(de->sample_offset);
            break;
        }

        cr->delay_pos++;
        pos += dpos;
        de++;
    }

    if (cr->delay_pos >= ngx_rtmp_r32(t->delays->entry_count)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "mp4: track#%ui seek delay[%ui/%uD] overflow",
                t->id, cr->delay_pos,
                ngx_rtmp_r32(t->delays->entry_count));

        return NGX_OK;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: track#%ui seek delay[%ui/%uD][%ui/%uD]=%ui",
                   t->id, cr->delay_pos,
                   ngx_rtmp_r32(t->delays->entry_count),
                   cr->delay_count,
                   ngx_rtmp_r32(de->sample_count), cr->delay);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_next(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t)
{
    if (ngx_rtmp_mp4_next_time(s, t)  != NGX_OK ||
        ngx_rtmp_mp4_next_key(s, t)   != NGX_OK ||
        ngx_rtmp_mp4_next_chunk(s, t) != NGX_OK ||
        ngx_rtmp_mp4_next_size(s, t)  != NGX_OK ||
        ngx_rtmp_mp4_next_delay(s, t) != NGX_OK)
    {
        t->cursor.valid = 0;
        return NGX_ERROR;
    }

    t->cursor.valid = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_send_meta(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mp4_ctx_t             *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_int_t                       rc;
    ngx_uint_t                      n;
    ngx_rtmp_header_t               h;
    ngx_chain_t                    *out;
    ngx_rtmp_mp4_track_t           *t;
    double                          d;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      video_codec_id;
        double                      audio_codec_id;
        double                      audio_sample_rate;
    }                               v;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayWidth"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayHeight"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videocodecid"),
          &v.video_codec_id, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiocodecid"),
          &v.audio_codec_id, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiosamplerate"),
          &v.audio_sample_rate, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onMetaData", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_memzero(&v, sizeof(v));

    v.width  = ctx->width;
    v.height = ctx->height;
    v.audio_sample_rate = ctx->sample_rate;

    t = &ctx->tracks[0];
    for (n = 0; n < ctx->ntracks; ++n, ++t) {
        d = ngx_rtmp_mp4_to_rtmp_timestamp(t, t->duration) / 1000.;

        if (v.duration < d) {
            v.duration = d;
        }

        switch (t->type) {
            case NGX_RTMP_MSG_AUDIO:
                v.audio_codec_id = t->codec;
                break;
            case NGX_RTMP_MSG_VIDEO:
                v.video_codec_id = t->codec;
                break;
        }
    }

    out = NULL;
    rc = ngx_rtmp_append_amf(s, &out, NULL, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0]));
    if (rc != NGX_OK || out == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&h, sizeof(h));

    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;
    h.type = NGX_RTMP_MSG_AMF_META;

    ngx_rtmp_prepare_message(s, &h, NULL, out);
    rc = ngx_rtmp_send_message(s, out, 0);
    ngx_rtmp_free_shared_chain(cscf, out);

    return rc;
}


static ngx_int_t
ngx_rtmp_mp4_seek_track(ngx_rtmp_session_t *s, ngx_rtmp_mp4_track_t *t,
                        ngx_int_t timestamp)
{
    ngx_rtmp_mp4_cursor_t          *cr;

    cr = &t->cursor;
    ngx_memzero(cr, sizeof(*cr));

    if (ngx_rtmp_mp4_seek_time(s, t, ngx_rtmp_mp4_from_rtmp_timestamp(
                          t, timestamp)) != NGX_OK ||
        ngx_rtmp_mp4_seek_key(s, t)   != NGX_OK ||
        ngx_rtmp_mp4_seek_chunk(s, t) != NGX_OK ||
        ngx_rtmp_mp4_seek_size(s, t)  != NGX_OK ||
        ngx_rtmp_mp4_seek_delay(s, t) != NGX_OK)
    {
        return NGX_ERROR;
    }

    cr->valid = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_send(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_uint_t *ts)
{
    ngx_rtmp_mp4_ctx_t             *ctx;
    ngx_buf_t                       in_buf;
    ngx_rtmp_header_t               h, lh;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_chain_t                    *out, in;
    ngx_rtmp_mp4_track_t           *t, *cur_t;
    ngx_rtmp_mp4_cursor_t          *cr, *cur_cr;
    uint32_t                        buflen, end_timestamp,
                                    timestamp, last_timestamp, rdelay,
                                    cur_timestamp;
    ssize_t                         ret;
    u_char                          fhdr[5];
    size_t                          fhdr_size;
    ngx_int_t                       rc;
    ngx_uint_t                      n, counter;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (!ctx->meta_sent) {
        rc = ngx_rtmp_mp4_send_meta(s);

        if (rc == NGX_OK) {
            ctx->meta_sent = 1;
        }

        return rc;
    }

    buflen = s->buflen + NGX_RTMP_MP4_BUFLEN_ADDON;

    counter = 0;
    last_timestamp = 0;
    end_timestamp = ctx->start_timestamp +
                    (ngx_current_msec - ctx->epoch) + buflen;

    for ( ;; ) {
        counter++;
        if (counter > NGX_RTMP_MP4_MAX_FRAMES) {
            return NGX_OK;
        }

        timestamp = 0;
        t = NULL;

        for (n = 0; n < ctx->ntracks; n++) {
            cur_t = &ctx->tracks[n];
            cur_cr = &cur_t->cursor;

            if (!cur_cr->valid) {
                continue;
            }

            cur_timestamp = ngx_rtmp_mp4_to_rtmp_timestamp(cur_t,
                                                           cur_cr->timestamp);

            if (t == NULL || cur_timestamp < timestamp) {
                timestamp = cur_timestamp;
                t = cur_t;
            }
        }

        if (t == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "mp4: no track");
            return NGX_DONE;
        }

        if (timestamp > end_timestamp) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "mp4: track#%ui ahead %uD > %uD",
                    t->id, timestamp, end_timestamp);

            if (ts) {
                *ts = last_timestamp;
            }

            return (uint32_t) (timestamp - end_timestamp);
        }

        cr = &t->cursor;

        last_timestamp = ngx_rtmp_mp4_to_rtmp_timestamp(t, cr->last_timestamp);

        ngx_memzero(&h, sizeof(h));

        h.msid = NGX_RTMP_MSID;
        h.type = (uint8_t) t->type;
        h.csid = t->csid;

        lh = h;

        h.timestamp  = timestamp;
        lh.timestamp = last_timestamp;

        ngx_memzero(&in, sizeof(in));
        ngx_memzero(&in_buf, sizeof(in_buf));

        if (t->header && !t->header_sent) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: track#%ui sending header of size=%uz",
                           t->id, t->header_size);

            fhdr[0] = t->fhdr;
            fhdr[1] = 0;

            if (t->type == NGX_RTMP_MSG_VIDEO) {
                fhdr[0] |= 0x10;
                fhdr[2] = fhdr[3] = fhdr[4] = 0;
                fhdr_size = 5;
            } else {
                fhdr_size = 2;
            }

            in.buf = &in_buf;
            in_buf.pos  = fhdr;
            in_buf.last = fhdr + fhdr_size;

            out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);

            in.buf = &in_buf;
            in_buf.pos  = t->header;
            in_buf.last = t->header + t->header_size;

            ngx_rtmp_append_shared_bufs(cscf, out, &in);

            ngx_rtmp_prepare_message(s, &h, NULL, out);
            rc = ngx_rtmp_send_message(s, out, 0);
            ngx_rtmp_free_shared_chain(cscf, out);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            t->header_sent = 1;
        }

        ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui read frame offset=%O, size=%uz, "
                       "timestamp=%uD, last_timestamp=%uD",
                       t->id, cr->offset, cr->size, timestamp,
                       last_timestamp);

        ngx_rtmp_mp4_buffer[0] = t->fhdr;
        fhdr_size = 1;

        if (t->type == NGX_RTMP_MSG_VIDEO) {
            if (cr->key) {
                ngx_rtmp_mp4_buffer[0] |= 0x10;
            } else if (cr->delay) {
                ngx_rtmp_mp4_buffer[0] |= 0x20;
            } else {
                ngx_rtmp_mp4_buffer[0] |= 0x30;
            }

            if (t->header) {
                fhdr_size = 5;

                rdelay = ngx_rtmp_mp4_to_rtmp_timestamp(t, cr->delay);

                ngx_rtmp_mp4_buffer[1] = 1;
                ngx_rtmp_mp4_buffer[2] = (rdelay >> 16) & 0xff;
                ngx_rtmp_mp4_buffer[3] = (rdelay >> 8)  & 0xff;
                ngx_rtmp_mp4_buffer[4] = rdelay & 0xff;
            }

        } else { /* NGX_RTMP_MSG_AUDIO */
            if (t->header) {
                fhdr_size = 2;
                ngx_rtmp_mp4_buffer[1] = 1;
            }
        }

        if (cr->size + fhdr_size > sizeof(ngx_rtmp_mp4_buffer)) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "mp4: track#%ui too big frame: %D>%uz",
                          t->id, cr->size, sizeof(ngx_rtmp_mp4_buffer));
            goto next;
        }

        ret = ngx_read_file(f, ngx_rtmp_mp4_buffer + fhdr_size,
                            cr->size, cr->offset);

        if (ret != (ssize_t) cr->size) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "mp4: track#%ui could not read frame", t->id);
            goto next;
        }

        in.buf = &in_buf;
        in_buf.pos  = ngx_rtmp_mp4_buffer;
        in_buf.last = ngx_rtmp_mp4_buffer + cr->size + fhdr_size;

        out = ngx_rtmp_append_shared_bufs(cscf, NULL, &in);

        ngx_rtmp_prepare_message(s, &h, cr->not_first ? &lh : NULL, out);
        rc = ngx_rtmp_send_message(s, out, 0);
        ngx_rtmp_free_shared_chain(cscf, out);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        s->current_time = timestamp;

next:
        if (ngx_rtmp_mp4_next(s, t) != NGX_OK) {
            return NGX_DONE;
        }
    }
}


static ngx_int_t
ngx_rtmp_mp4_init(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_int_t aindex,
                  ngx_int_t vindex)
{
    ngx_rtmp_mp4_ctx_t         *ctx;
    uint32_t                    hdr[2];
    ssize_t                     n;
    size_t                      offset, page_offset, size, shift;
    uint64_t                    extended_size;
    ngx_file_info_t             fi;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_mp4_ctx_t));

        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_mp4_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->aindex = aindex;
    ctx->vindex = vindex;

    offset = 0;
    size   = 0;

    for ( ;; ) {
        n = ngx_read_file(f, (u_char *) &hdr, sizeof(hdr), offset);

        if (n != sizeof(hdr)) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "mp4: error reading file at offset=%uz "
                          "while searching for moov box", offset);
            return NGX_ERROR;
        }

        size = (size_t) ngx_rtmp_r32(hdr[0]);
        shift = sizeof(hdr);

        if (size == 1) {
            n = ngx_read_file(f, (u_char *) &extended_size,
                              sizeof(extended_size), offset + sizeof(hdr));

            if (n != sizeof(extended_size)) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                              "mp4: error reading file at offset=%uz "
                              "while searching for moov box", offset + 8);
                return NGX_ERROR;
            }

            size = (size_t) ngx_rtmp_r64(extended_size);
            shift += sizeof(extended_size);

        } else if (size == 0) {
            if (ngx_fd_info(f->fd, &fi) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                              "mp4: " ngx_fd_info_n " failed");
                return NGX_ERROR;
            }
            size = ngx_file_size(&fi) - offset;
        }

        if (hdr[1] == ngx_rtmp_mp4_make_tag('m','o','o','v')) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "mp4: found moov box");
            break;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: skipping box '%*s'", 4, hdr + 1);

        offset += size;
    }

    if (size < shift) {
        return NGX_ERROR;
    }

    size   -= shift;
    offset += shift;

    page_offset = offset & (ngx_pagesize - 1);
    ctx->mmaped_size = page_offset + size;

    ctx->mmaped = ngx_rtmp_mp4_mmap(f->fd, ctx->mmaped_size,
                                    offset - page_offset, &ctx->extra);
    if (ctx->mmaped == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "mp4: mmap failed at offset=%ui, size=%uz",
                      offset, size);
        return NGX_ERROR;
    }

    return ngx_rtmp_mp4_parse(s, (u_char *) ctx->mmaped + page_offset,
                                 (u_char *) ctx->mmaped + page_offset + size);
}


static ngx_int_t
ngx_rtmp_mp4_done(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_mp4_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL || ctx->mmaped == NULL) {
        return NGX_OK;
    }

    if (ngx_rtmp_mp4_munmap(ctx->mmaped, ctx->mmaped_size, &ctx->extra)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "mp4: munmap failed");
        return NGX_ERROR;
    }

    ctx->mmaped = NULL;
    ctx->mmaped_size = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_seek(ngx_rtmp_session_t *s, ngx_file_t *f, ngx_uint_t timestamp)
{
    ngx_rtmp_mp4_ctx_t     *ctx;
    ngx_rtmp_mp4_track_t   *t;
    ngx_uint_t              n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: seek timestamp=%ui", timestamp);

    for (n = 0; n < ctx->ntracks; ++n) {
        t = &ctx->tracks[n];

        if (t->type != NGX_RTMP_MSG_VIDEO) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui seek video", n);

        ngx_rtmp_mp4_seek_track(s, t, timestamp);

        timestamp = ngx_rtmp_mp4_to_rtmp_timestamp(t, t->cursor.timestamp);

        break;
    }

    for (n = 0; n < ctx->ntracks; ++n) {
        t = &ctx->tracks[n];

        if (t->type == NGX_RTMP_MSG_VIDEO) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "mp4: track#%ui seek", n);

        ngx_rtmp_mp4_seek_track(s, &ctx->tracks[n], timestamp);
    }

    ctx->start_timestamp = timestamp;
    ctx->epoch = ngx_current_msec;

    return ngx_rtmp_mp4_reset(s);
}


static ngx_int_t
ngx_rtmp_mp4_start(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_mp4_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: start timestamp=%uD", ctx->start_timestamp);

    ctx->epoch = ngx_current_msec;

    return NGX_OK;/*ngx_rtmp_mp4_reset(s);*/
}


static ngx_int_t
ngx_rtmp_mp4_reset(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mp4_ctx_t     *ctx;
    ngx_rtmp_mp4_cursor_t  *cr;
    ngx_rtmp_mp4_track_t   *t;
    ngx_uint_t              n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    t = &ctx->tracks[0];
    for (n = 0; n < ctx->ntracks; ++n, ++t) {
        cr = &t->cursor;
        cr->not_first = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_stop(ngx_rtmp_session_t *s, ngx_file_t *f)
{
    ngx_rtmp_mp4_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mp4_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->start_timestamp += (ngx_current_msec - ctx->epoch);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "mp4: stop timestamp=%uD", ctx->start_timestamp);

    return NGX_OK;/*ngx_rtmp_mp4_reset(s);*/
}


static ngx_int_t
ngx_rtmp_mp4_postconfiguration(ngx_conf_t *cf)
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

    ngx_str_set(&fmt->name, "mp4-format");

    ngx_str_set(&fmt->pfx, "mp4:");
    ngx_str_set(&fmt->sfx, ".mp4");

    fmt->init  = ngx_rtmp_mp4_init;
    fmt->done  = ngx_rtmp_mp4_done;
    fmt->seek  = ngx_rtmp_mp4_seek;
    fmt->start = ngx_rtmp_mp4_start;
    fmt->stop  = ngx_rtmp_mp4_stop;
    fmt->send  = ngx_rtmp_mp4_send;

    return NGX_OK;
}
