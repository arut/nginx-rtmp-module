

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_mp4.h"
#include <ngx_rtmp_codec_module.h>


/*
static ngx_int_t
ngx_rtmp_mp4_field_64(ngx_buf_t *b, uint64_t n)
{
    u_char  bytes[8];

    bytes[0] = ((uint64_t) n >> 56) & 0xFF;
    bytes[1] = ((uint64_t) n >> 48) & 0xFF;
    bytes[2] = ((uint64_t) n >> 40) & 0xFF;
    bytes[3] = ((uint64_t) n >> 32) & 0xFF;
    bytes[4] = ((uint64_t) n >> 24) & 0xFF;
    bytes[5] = ((uint64_t) n >> 16) & 0xFF;
    bytes[6] = ((uint64_t) n >> 8) & 0xFF;
    bytes[7] = (uint64_t) n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}
*/

static ngx_int_t
ngx_rtmp_mp4_field_32(ngx_buf_t *b, uint32_t n)
{
    u_char  bytes[4];

    bytes[0] = ((uint32_t) n >> 24) & 0xFF;
    bytes[1] = ((uint32_t) n >> 16) & 0xFF;
    bytes[2] = ((uint32_t) n >> 8) & 0xFF;
    bytes[3] = (uint32_t) n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_24(ngx_buf_t *b, uint32_t n)
{
    u_char  bytes[3];

    bytes[0] = ((uint32_t) n >> 16) & 0xFF;
    bytes[1] = ((uint32_t) n >> 8) & 0xFF;
    bytes[2] = (uint32_t) n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_16(ngx_buf_t *b, uint16_t n)
{
    u_char  bytes[2];

    bytes[0] = ((uint32_t) n >> 8) & 0xFF;
    bytes[1] = (uint32_t) n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_8(ngx_buf_t *b, uint8_t n)
{
    u_char  bytes[1];

    bytes[0] = n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_put_descr(ngx_buf_t *b, int tag, unsigned int size)
{
    ngx_rtmp_mp4_field_8(b, (uint8_t) tag);
    ngx_rtmp_mp4_field_8(b, size & 0x7F);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_data(ngx_buf_t *b, void *data, size_t n)
{
    if (b->last + n > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, (u_char *) data, n);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_box(ngx_buf_t *b, const char box[4])
{
    if (b->last + 4 > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, (u_char *) box, 4);

    return NGX_OK;
}


static u_char *
ngx_rtmp_mp4_start_box(ngx_buf_t *b, const char box[4])
{
    u_char  *p;

    p = b->last;

    if (ngx_rtmp_mp4_field_32(b, 0) != NGX_OK) {
        return NULL;
    }

    if (ngx_rtmp_mp4_box(b, box) != NGX_OK) {
        return NULL;
    }

    return p;
}


static ngx_int_t
ngx_rtmp_mp4_update_box_size(ngx_buf_t *b, u_char *p)
{
    u_char  *curpos;

    if (p == NULL) {
        return NGX_ERROR;
    }

    curpos = b->last;

    b->last = p;

    ngx_rtmp_mp4_field_32(b, (uint32_t) (curpos - p));

    b->last = curpos;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_matrix(ngx_buf_t *buf, uint32_t a, uint32_t b, uint32_t c,
    uint32_t d, uint32_t tx, uint32_t ty)
{

/* 
 * transformation matrix
 * |a  b  u|
 * |c  d  v|
 * |tx ty w|
 */

    ngx_rtmp_mp4_field_32(buf, a << 16);  /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, b << 16);  /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, 0);        /* u in 2.30 format */
    ngx_rtmp_mp4_field_32(buf, c << 16);  /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, d << 16);  /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, 0);        /* v in 2.30 format */
    ngx_rtmp_mp4_field_32(buf, tx << 16); /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, ty << 16); /* 16.16 format */
    ngx_rtmp_mp4_field_32(buf, 1 << 30);  /* w in 2.30 format */

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_ftyp(ngx_buf_t *b, int type, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    switch (type) {

    case NGX_RTMP_MP4_FILETYPE_INIT:

        pos = ngx_rtmp_mp4_start_box(b, "ftyp");

        ngx_rtmp_mp4_box(b, "iso5");
        ngx_rtmp_mp4_field_32(b, 1);

        if (metadata != NULL && metadata->video == 1) {
            ngx_rtmp_mp4_box(b, "avc1");
        }

        ngx_rtmp_mp4_box(b, "iso5");
        ngx_rtmp_mp4_box(b, "dash");

        break;
    
    default: /* NGX_RTMP_MP4_FILETYPE_SEG */

        pos = ngx_rtmp_mp4_start_box(b, "styp");

        ngx_rtmp_mp4_box(b, "msdh");
        ngx_rtmp_mp4_field_32(b, 0);
        ngx_rtmp_mp4_box(b, "msdh");
        ngx_rtmp_mp4_box(b, "msix");

        break;
    }

    ngx_rtmp_mp4_update_box_size(b, pos);
    
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mvhd(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mvhd");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0x00000000); /* creation time */
    ngx_rtmp_mp4_field_32(b, 0); /* modification time */
    ngx_rtmp_mp4_field_32(b, 1000); /* timescale */
    ngx_rtmp_mp4_field_32(b, 0); /* duration */
    ngx_rtmp_mp4_field_32(b, 0x00010000); /* playback rate */
    ngx_rtmp_mp4_field_16(b, 0x0100); /* volume rate */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */

    ngx_rtmp_mp4_write_matrix(b, 1, 0, 0, 1, 0, 0);

    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */

    ngx_rtmp_mp4_field_32(b, 1); /* track id */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_tkhd(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "tkhd");

    ngx_rtmp_mp4_field_8(b, 0); /* version */
    ngx_rtmp_mp4_field_24(b, 0x0000000F); /* flags */
    ngx_rtmp_mp4_field_32(b, 0); /* creation time */
    ngx_rtmp_mp4_field_32(b, 0); /* modification time */
    ngx_rtmp_mp4_field_32(b, 1); /* track id */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* duration */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    /* 2 16s, layer and alternate group */
    ngx_rtmp_mp4_field_32(b, metadata->audio == 1 ? 0x00000001 : 0); 
    ngx_rtmp_mp4_field_16(b, metadata->audio == 1 ? 0x0100 : 0);
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */

    ngx_rtmp_mp4_write_matrix(b, 1, 0, 0, 1, 0, 0);

    if (metadata->video == 1) {
        ngx_rtmp_mp4_field_32(b, metadata->width << 16); /* width */
        ngx_rtmp_mp4_field_32(b, metadata->height << 16); /* height */
    }
    else {
        ngx_rtmp_mp4_field_32(b, 0); /* not relevant for audio */
        ngx_rtmp_mp4_field_32(b, 0); /* not relevant for audio */
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mdhd(ngx_buf_t *b) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mdhd");

    /* version */
    ngx_rtmp_mp4_field_32(b, 0);

    /* creation time */
    ngx_rtmp_mp4_field_32(b, 0);

    /* modification time */
    ngx_rtmp_mp4_field_32(b, 0);

    /* time scale*/
    ngx_rtmp_mp4_field_32(b, 1000); 

    /* duration */
    ngx_rtmp_mp4_field_32(b, 0);

    /* lanuguage */
    ngx_rtmp_mp4_field_16(b, 0x15C7);

    /* reserved */
    ngx_rtmp_mp4_field_16(b, 0);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_hdlr(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "hdlr");

    /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0);

    /* pre defined */
    ngx_rtmp_mp4_field_32(b, 0);

    if (metadata->video == 1) {
        ngx_rtmp_mp4_box(b, "vide");
    } else {
        ngx_rtmp_mp4_box(b, "soun");
    }

    /* reserved */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);

    if (metadata->video == 1) {
        /* video handler string, NULL-terminated */
        ngx_rtmp_mp4_data(b, "VideoHandler", sizeof("VideoHandler"));
    }
    else {
        /* sound handler string, NULL-terminated */
        ngx_rtmp_mp4_data(b, "SoundHandler", sizeof("SoundHandler")); 
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_vmhd(ngx_buf_t *b) 
{
    /* size is always 20, apparently */
    ngx_rtmp_mp4_field_32(b, 20);

    ngx_rtmp_mp4_box(b, "vmhd");

    /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0x01);

    /* reserved (graphics mode=copy) */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_smhd(ngx_buf_t *b) 
{
    /* size is always 16, apparently */
    ngx_rtmp_mp4_field_32(b, 16);

    ngx_rtmp_mp4_box(b, "smhd");

    /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0);

    /* reserved (balance normally=0) */
    ngx_rtmp_mp4_field_16(b, 0);
    ngx_rtmp_mp4_field_16(b, 0);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_dref(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "dref");

    /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0);

    /* entry count */
    ngx_rtmp_mp4_field_32(b, 1);

    /* url size */
    ngx_rtmp_mp4_field_32(b, 0xc);

    ngx_rtmp_mp4_box(b, "url ");

    /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0x00000001);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_dinf(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "dinf");

    ngx_rtmp_mp4_write_dref(b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_avcc(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                        ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char                *pos, *p;
    ngx_chain_t           *in;
    ngx_rtmp_codec_ctx_t  *codec_ctx;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    in = codec_ctx->avc_header;
    if (in == NULL) {
        return NGX_ERROR;
    }

    pos = ngx_rtmp_mp4_start_box(b, "avcC");

    /* assume config fits one chunk (highly probable) */

    /* check for start code */
    for (p = in->buf->pos; p <= in->buf->last; p++) {
        if (*p == 0x01) {
            break;
        }
    }

    if (in->buf->last - p > 0) {
        ngx_rtmp_mp4_data(b, p, (size_t) (in->buf->last - p));
    } else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: invalid avcc received");
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_video(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "avc1");

    /* reserved */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_16(b, 0);

    /* data reference index */
    ngx_rtmp_mp4_field_16(b, 1);

    /* codec stream version & revision */
    ngx_rtmp_mp4_field_16(b, 0);
    ngx_rtmp_mp4_field_16(b, 0);

    /* reserved */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);

    /* width & height */
    ngx_rtmp_mp4_field_16(b, (uint16_t) metadata->width);
    ngx_rtmp_mp4_field_16(b, (uint16_t) metadata->height);

    /* horizontal & vertical resolutions 72 dpi */
    ngx_rtmp_mp4_field_32(b, 0x00480000);
    ngx_rtmp_mp4_field_32(b, 0x00480000);

    /* data size */
    ngx_rtmp_mp4_field_32(b, 0);

    /* frame count */
    ngx_rtmp_mp4_field_16(b, 1);

    /* compressor name */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);

    /* reserved */
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_32(b, 0);
    ngx_rtmp_mp4_field_16(b, 0x18);
    ngx_rtmp_mp4_field_16(b, 0xffff);

    ngx_rtmp_mp4_write_avcc(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_esds(ngx_rtmp_session_t *s, ngx_buf_t *b,
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    int                    decoder_info;
    int                    aac_header_offset;
    u_char                *pos;
    ngx_chain_t           *aac;
    ngx_rtmp_codec_ctx_t  *codec_ctx;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    aac = codec_ctx->aac_header;
    if (aac == NULL) {
        decoder_info = 0;
        aac_header_offset = 0;
    } else {
        decoder_info = (aac->buf->last-aac->buf->pos);
        aac_header_offset = 2;
    }

    pos = ngx_rtmp_mp4_start_box(b, "esds");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    /* length of the rest of the box */
    ngx_rtmp_mp4_put_descr(b, 0x03, 21+decoder_info); 
    ngx_rtmp_mp4_field_16(b, 1); /* track id */ 
    ngx_rtmp_mp4_field_8(b, 0x00); /* flags */
    /* length of the rest of the box */
    ngx_rtmp_mp4_put_descr(b, 0x04, 13+decoder_info); 
    ngx_rtmp_mp4_field_8(b, metadata->audio_codec == NGX_RTMP_AUDIO_AAC ? 0x40 :
                            0x6B); /* codec id */
    ngx_rtmp_mp4_field_8(b, 0x15); /* audio stream */
    ngx_rtmp_mp4_field_24(b, 0); /* buffersize? */
    /* Next two fields are bitrate. */
    ngx_rtmp_mp4_field_32(b, 0x0001F151); 
    ngx_rtmp_mp4_field_32(b, 0x0001F14D); 

    if (aac) {
        ngx_rtmp_mp4_put_descr(b, 0x05, decoder_info);
        ngx_rtmp_mp4_data(b, aac->buf->pos + aac_header_offset,
                          (size_t) decoder_info);
    }

    ngx_rtmp_mp4_put_descr(b, 0x06, 1);
    ngx_rtmp_mp4_field_8(b, 0x02);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_audio(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mp4a");

    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 1); /* Data-reference index, XXX  == 1 */
    ngx_rtmp_mp4_field_16(b, 0); /* Version */
    ngx_rtmp_mp4_field_16(b, 0); /* Revision level */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 2); /* something mp4 specific */
    ngx_rtmp_mp4_field_16(b, 16); /* something mp4 specific */
    ngx_rtmp_mp4_field_16(b, 0); /* something mp4 specific */
    ngx_rtmp_mp4_field_16(b, 0); /* packet size (=0) */
    ngx_rtmp_mp4_field_16(b, (uint16_t) metadata->sample_rate);
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */

    ngx_rtmp_mp4_write_esds(s, b, metadata);

    ngx_rtmp_mp4_field_32(b, 8); /* size */
    ngx_rtmp_mp4_field_32(b, 0); /* null tag */

    ngx_rtmp_mp4_update_box_size(b, pos);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stsd(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stsd");

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 1); /* entry count */

    if (metadata->video == 1) {
        ngx_rtmp_mp4_write_video(s,b,metadata);
    }
    else {
        ngx_rtmp_mp4_write_audio(s,b,metadata);
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stts(ngx_buf_t *b) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stts");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stsc(ngx_buf_t *b) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stsc");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stsz(ngx_buf_t *b) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stsz");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */
    ngx_rtmp_mp4_field_32(b, 0); /* moar zeros */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stco(ngx_buf_t *b) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stco");

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stbl(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "stbl");

    ngx_rtmp_mp4_write_stsd(s, b, metadata);
    ngx_rtmp_mp4_write_stts(b);
    ngx_rtmp_mp4_write_stsc(b);
    ngx_rtmp_mp4_write_stsz(b);
    ngx_rtmp_mp4_write_stco(b);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_minf(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "minf");

    if (metadata->video == 1) {
        ngx_rtmp_mp4_write_vmhd(b);
    }
    else {
        ngx_rtmp_mp4_write_smhd(b);
    }

    ngx_rtmp_mp4_write_dinf(b, metadata);
    ngx_rtmp_mp4_write_stbl(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mdia(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mdia");

    ngx_rtmp_mp4_write_mdhd(b);
    ngx_rtmp_mp4_write_hdlr(b, metadata);
    ngx_rtmp_mp4_write_minf(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_mp4_write_trak(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "trak");

    ngx_rtmp_mp4_write_tkhd(b, metadata);
    ngx_rtmp_mp4_write_mdia(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mvex(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mvex");

    /* just write the trex and mehd in here too */
#if 0
    ngx_rtmp_mp4_field_32(b, 16);

    b->last = ngx_cpymem(b->last, "mehd", sizeof("mehd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 0x000D8D2A); /* frag duration */
#endif

    ngx_rtmp_mp4_field_32(b, 0x20);

    ngx_rtmp_mp4_box(b, "trex");

    /* version & flags */
    ngx_rtmp_mp4_field_32(b, 0);

    /* track id */
    ngx_rtmp_mp4_field_32(b, 1);

    /* default sample description index */
    ngx_rtmp_mp4_field_32(b, 1);

    /* default sample duration */
    ngx_rtmp_mp4_field_32(b, 0);

    /* default sample size, 1024 for AAC */
    ngx_rtmp_mp4_field_32(b, 1024);

    /* default sample flags, key on */
    ngx_rtmp_mp4_field_32(b, 0);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_moov(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                        ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "moov");

    ngx_rtmp_mp4_write_mvhd(b, metadata);
    ngx_rtmp_mp4_write_mvex(b, metadata);
    ngx_rtmp_mp4_write_trak(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_tfhd(ngx_buf_t *b)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "tfhd");

    /* version & flags */
    ngx_rtmp_mp4_field_32(b, 0x00020000); 

    /* track id */
    ngx_rtmp_mp4_field_32(b, 1);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_tfdt(ngx_buf_t *b, uint32_t earliest_pres_time)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "tfdt");

    /* version == 1 aka 64 bit integer */
    ngx_rtmp_mp4_field_32(b, 0x00000000);
    ngx_rtmp_mp4_field_32(b, earliest_pres_time);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_trun(ngx_buf_t *b, uint32_t sample_count, 
    ngx_rtmp_mp4_sample_t *samples, ngx_uint_t sample_mask, u_char *moof_pos)
{
    u_char    *pos;
    uint32_t   i, offset, nitems, flags;

    pos = ngx_rtmp_mp4_start_box(b, "trun");

    nitems = 0;
    
    /* data offset present */
    flags = 0x01;

    if (sample_mask & NGX_RTMP_MP4_SAMPLE_DURATION) {
        nitems++;
        flags |= 0x000100;
    }

    if (sample_mask & NGX_RTMP_MP4_SAMPLE_SIZE) {
        nitems++;
        flags |= 0x000200;
    }

    if (sample_mask & NGX_RTMP_MP4_SAMPLE_KEY) {
        nitems++;
        flags |= 0x000400;
    }

    if (sample_mask & NGX_RTMP_MP4_SAMPLE_DELAY) {
        nitems++;
        flags |= 0x000800;
    }
    
    offset = (pos - moof_pos) + 20 + (sample_count * nitems * 4) + 8;  

    ngx_rtmp_mp4_field_32(b, flags); 
    ngx_rtmp_mp4_field_32(b, sample_count);
    ngx_rtmp_mp4_field_32(b, offset);

    for (i = 0; i < sample_count; i++, samples++) {

        if (sample_mask & NGX_RTMP_MP4_SAMPLE_DURATION) {
            ngx_rtmp_mp4_field_32(b, samples->duration);
        }

        if (sample_mask & NGX_RTMP_MP4_SAMPLE_SIZE) {
            ngx_rtmp_mp4_field_32(b, samples->size);
        }

        if (sample_mask & NGX_RTMP_MP4_SAMPLE_KEY) {
            ngx_rtmp_mp4_field_32(b, samples->key ? 0x00000000 : 0x00010000);
        }

        if (sample_mask & NGX_RTMP_MP4_SAMPLE_DELAY) {
            ngx_rtmp_mp4_field_32(b, samples->delay);
        }
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_traf(ngx_buf_t *b, uint32_t earliest_pres_time, 
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples,
    ngx_uint_t sample_mask, u_char *moof_pos)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "traf");

    ngx_rtmp_mp4_write_tfhd(b);
    ngx_rtmp_mp4_write_tfdt(b, earliest_pres_time);
    ngx_rtmp_mp4_write_trun(b, sample_count, samples, sample_mask, moof_pos);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mfhd(ngx_buf_t *b, uint32_t index) 
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "mfhd");

    /* don't know what this is */
    ngx_rtmp_mp4_field_32(b, 0);

    /* fragment index. */
    ngx_rtmp_mp4_field_32(b, index);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_sidx(ngx_buf_t *b, ngx_uint_t reference_size,
    uint32_t earliest_pres_time, uint32_t latest_pres_time) 
{
    u_char    *pos;
    uint32_t   duration;

    duration = latest_pres_time - earliest_pres_time;

    pos = ngx_rtmp_mp4_start_box(b, "sidx");

    /* version */
    ngx_rtmp_mp4_field_32(b, 0);

    /* reference id */
    ngx_rtmp_mp4_field_32(b, 1);

    /* timescale */
    ngx_rtmp_mp4_field_32(b, 1000); 

    /* earliest presentation time */
    ngx_rtmp_mp4_field_32(b, earliest_pres_time);

    /* first offset */
    ngx_rtmp_mp4_field_32(b, duration); /*TODO*/

    /* reserved */
    ngx_rtmp_mp4_field_16(b, 0);

    /* reference count = 1 */
    ngx_rtmp_mp4_field_16(b, 1);

    /* 1st bit is reference type, the rest is reference size */
    ngx_rtmp_mp4_field_32(b, reference_size); 

    /* subsegment duration */
    ngx_rtmp_mp4_field_32(b, duration);

    /* first bit is startsWithSAP (=1), next 3 bits are SAP type (=001) */
    ngx_rtmp_mp4_field_8(b, 0x90); 
    
    /* SAP delta time */
    ngx_rtmp_mp4_field_24(b, 0);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_moof(ngx_buf_t *b, uint32_t earliest_pres_time, 
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples,
    ngx_uint_t sample_mask, uint32_t index)
{
    u_char  *pos;

    pos = ngx_rtmp_mp4_start_box(b, "moof");

    ngx_rtmp_mp4_write_mfhd(b, index);
    ngx_rtmp_mp4_write_traf(b, earliest_pres_time, sample_count, samples,
                            sample_mask, pos);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_uint_t 
ngx_rtmp_mp4_write_mdat(ngx_buf_t *b, ngx_uint_t size) 
{
    ngx_rtmp_mp4_field_32(b, size);

    ngx_rtmp_mp4_box(b, "mdat");

    return NGX_OK;
}
