

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_mp4.h"
#include <ngx_rtmp_codec_module.h>


/* tie resolution */
#define NGX_RTMP_MP4_TIMESCALE          1000

/* normal forward playback as defined by spec */
#define NGX_RTMP_MP4_PREFERRED_RATE     0x00010000

/* full volume as defined by spec */
#define NGX_RTMP_MP4_PREFERRED_VOLUME   0x0100


static u_char compressor_name[] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/*
static ngx_int_t
ngx_rtmp_mp4_field_64(ngx_buf_t *b, uint64_t n)
{
    u_char         bytes[8];

    bytes[0] = ((uint64_t)n >> 56) & 0xFF;
    bytes[1] = ((uint64_t)n >> 48) & 0xFF;
    bytes[2] = ((uint64_t)n >> 40) & 0xFF;
    bytes[3] = ((uint64_t)n >> 32) & 0xFF;
    bytes[4] = ((uint64_t)n >> 24) & 0xFF;
    bytes[5] = ((uint64_t)n >> 16) & 0xFF;
    bytes[6] = ((uint64_t)n >> 8) & 0xFF;
    bytes[7] = (uint64_t)n & 0xFF;

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
    u_char         bytes[4];

    bytes[0] = ((uint32_t)n >> 24) & 0xFF;
    bytes[1] = ((uint32_t)n >> 16) & 0xFF;
    bytes[2] = ((uint32_t)n >> 8) & 0xFF;
    bytes[3] = (uint32_t)n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_24(ngx_buf_t *b, uint32_t n)
{
    u_char         bytes[3];

    bytes[0] = ((uint32_t)n >> 16) & 0xFF;
    bytes[1] = ((uint32_t)n >> 8) & 0xFF;
    bytes[2] = (uint32_t)n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_16(ngx_buf_t *b, uint32_t n)
{
    u_char         bytes[2];

    bytes[0] = ((uint32_t)n >> 8) & 0xFF;
    bytes[1] = (uint32_t)n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_field_8(ngx_buf_t *b, unsigned int n)
{
    u_char         bytes[1];

    bytes[0] = n & 0xFF;

    if (b->last + sizeof(bytes) > b->end) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, bytes, sizeof(bytes));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_put_descr(ngx_buf_t *b, int tag, unsigned int size) {
    //int i = 3;

    /* initially stolen from ffmpeg, but most of it isnt necessary */

    ngx_rtmp_mp4_field_8(b, tag);
    //for (; i > 0; i--) {
    //    ngx_rtmp_mp4_field_8(b, (size >> (7 * i)) | 0x80);
    //}
    ngx_rtmp_mp4_field_8(b, size & 0x7F);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_update_box_size(ngx_buf_t *b, u_char *pos)
{
    u_char         *curpos;

    curpos = b->last;
    b->last = pos;

    ngx_rtmp_mp4_field_32(b, (curpos-pos));

    b->last = curpos;

    return NGX_OK;
}


/* transformation matrix
     |a  b  u|
     |c  d  v|
     |tx ty w| */
static ngx_int_t
ngx_rtmp_mp4_write_matrix(ngx_buf_t *buf, int16_t a, int16_t b, int16_t c,
    int16_t d, int16_t tx, int16_t ty)
{
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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    switch (type) {

    case NGX_RTMP_MP4_FILETYPE_INIT:

        b->last = ngx_cpymem(b->last, "ftypiso5", sizeof("ftypiso5") - 1);

        ngx_rtmp_mp4_field_32(b, 1);

        if (metadata != NULL && metadata->video == 1) {
            b->last = ngx_cpymem(b->last, "avc1iso5dash", 
                                 sizeof("avc1iso5dash") - 1);
        } else {
            b->last = ngx_cpymem(b->last, "iso5dash", sizeof("iso5dash") - 1);
        }

        break;
    
    case NGX_RTMP_MP4_FILETYPE_SEG:

        b->last = ngx_cpymem(b->last, "stypmsdh", sizeof("stypmsdh") - 1);

        ngx_rtmp_mp4_field_32(b, 0);

        b->last = ngx_cpymem(b->last, "msdhmsix", sizeof("msdhmsix") - 1);

        break;
    }

    ngx_rtmp_mp4_update_box_size(b, pos);
    
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mvhd(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata)
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mvhd", sizeof("mvhd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0x00000000); /* creation time */
    ngx_rtmp_mp4_field_32(b, 0); /* modification time */
    ngx_rtmp_mp4_field_32(b, NGX_RTMP_MP4_TIMESCALE); /* timescale */
    ngx_rtmp_mp4_field_32(b, 0); /* duration */
    ngx_rtmp_mp4_field_32(b, NGX_RTMP_MP4_PREFERRED_RATE); /* playback rate */
    ngx_rtmp_mp4_field_16(b, NGX_RTMP_MP4_PREFERRED_VOLUME); /* volume rate */
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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "tkhd", sizeof("tkhd")-1);

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
ngx_rtmp_mp4_write_mdhd(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mdhd", sizeof("mdhd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* creation time */
    ngx_rtmp_mp4_field_32(b, 0); /* modification time */
    /* time scale*/
    ngx_rtmp_mp4_field_32(b, metadata->audio == 1 ? metadata->sample_rate : 
                                                    NGX_RTMP_MP4_TIMESCALE); 
    ngx_rtmp_mp4_field_32(b, 0); /* duration */ 
    ngx_rtmp_mp4_field_16(b, 0x15C7); /* language */ 
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */ 

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_hdlr(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "hdlr", sizeof("hdlr")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0); /* pre defined (=0) */
    if (metadata->video == 1) {
        /* video handler */
        b->last = ngx_cpymem(b->last, "vide", sizeof("vide")-1); 
    }
    else {
        /* sound handler */
        b->last = ngx_cpymem(b->last, "soun", sizeof("soun")-1); 
    }

    ngx_rtmp_mp4_field_32(b, 0); /* reserved */ 
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */ 
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */ 

    if (metadata->video == 1) {
        /* video handler string--NULL TERMINATED */
        b->last = ngx_cpymem(b->last, "VideoHandler", sizeof("VideoHandler")); 
    }
    else {
        /* sound handler string--NULL TERMINATED */
        b->last = ngx_cpymem(b->last, "SoundHandler", sizeof("SoundHandler")); 
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_vmhd(ngx_buf_t *b) 
{
    /* size is always 0x14, apparently */
    ngx_rtmp_mp4_field_32(b, 0x14);

    b->last = ngx_cpymem(b->last, "vmhd", sizeof("vmhd")-1);

    ngx_rtmp_mp4_field_32(b, 0x01); /* version and flags */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved (graphics mode = copy) */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved (graphics mode = copy) */

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_smhd(ngx_buf_t *b) 
{
    /* size is always 16, apparently */
    ngx_rtmp_mp4_field_32(b, 16);

    b->last = ngx_cpymem(b->last, "smhd", sizeof("smhd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version and flags */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved (balance, normally = 0) */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_dref(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "dref", sizeof("dref")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 1); /* entry count */
    ngx_rtmp_mp4_field_32(b, 0xc); /* size of url */

    b->last = ngx_cpymem(b->last, "url ", sizeof("url ")-1);

    ngx_rtmp_mp4_field_32(b, 0x00000001); /* version & flags */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_dinf(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "dinf", sizeof("dinf")-1);

    ngx_rtmp_mp4_write_dref(b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_avcc(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                        ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char                         *pos, *p;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *in;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    in = codec_ctx->avc_header;
    if (in == NULL) {
        return NGX_ERROR;
    }

    pos = b->last;

    for (p=in->buf->pos;p<=in->buf->last;p++) {
        if (*p == 0x01) { /* check for start code */
            break;
        }
    }

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "avcC", sizeof("avcC")-1);

    if (in->buf->last-p > 0) {
        b->last = ngx_cpymem(b->last, p, in->buf->last-p);
    }
    else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: dash: invalid avcc received");
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_video(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                         ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "avc1", sizeof("avc1")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 1); /* data reference index */
    ngx_rtmp_mp4_field_16(b, 0); /* codec stream version */
    ngx_rtmp_mp4_field_16(b, 0); /* codec stream revision (=0) */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, metadata->width);
    ngx_rtmp_mp4_field_16(b, metadata->height);
    ngx_rtmp_mp4_field_32(b, 0x00480000); /* Horizontal resolution 72dpi */
    ngx_rtmp_mp4_field_32(b, 0x00480000); /* Vertical resolution 72dpi */
    ngx_rtmp_mp4_field_32(b, 0); /* Data size (= 0) */
    ngx_rtmp_mp4_field_16(b, 1); /* Frame count (= 1) */
    ngx_rtmp_mp4_field_8(b, 0); /* compressor name len */

    b->last = ngx_cpymem(b->last, compressor_name, sizeof(compressor_name)+1);

    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_32(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 0x18); /* reserved */
    ngx_rtmp_mp4_field_16(b, 0xffff); /* reserved */

    ngx_rtmp_mp4_write_avcc(s, b, metadata);


    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_esds(ngx_rtmp_session_t *s, ngx_buf_t *b,
                        ngx_rtmp_mp4_metadata_t *metadata) 
{

    u_char                         *pos;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *aac;
    int                             decoder_info;
    int                             aac_header_offset;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    aac = codec_ctx->aac_header;
    if (aac == NULL) {
        decoder_info = 0;
        aac_header_offset = 0;
    }
    else {
        decoder_info = (aac->buf->last-aac->buf->pos);
        aac_header_offset = 2;
    }
    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "esds", sizeof("esds")-1);

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
        b->last = ngx_cpymem(b->last, aac->buf->pos+aac_header_offset,
                             decoder_info);
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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mp4a", sizeof("mp4a")-1);

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
    ngx_rtmp_mp4_field_16(b, metadata->sample_rate); /* sample rate */
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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stsd", sizeof("stsd")-1);

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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stts", sizeof("stts")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stsc(ngx_buf_t *b) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stsc", sizeof("stsc")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stsz(ngx_buf_t *b) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stsz", sizeof("stsz")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */
    ngx_rtmp_mp4_field_32(b, 0); /* moar zeros */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stco(ngx_buf_t *b) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stco", sizeof("stco")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 0); /* entry count */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_stbl(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "stbl", sizeof("stbl")-1);

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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "minf", sizeof("minf")-1);

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
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mdia", sizeof("mdia")-1);

    ngx_rtmp_mp4_write_mdhd(b, metadata);
    ngx_rtmp_mp4_write_hdlr(b, metadata);
    ngx_rtmp_mp4_write_minf(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_mp4_write_trak(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "trak", sizeof("trak")-1);

    ngx_rtmp_mp4_write_tkhd(b, metadata);
    ngx_rtmp_mp4_write_mdia(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mvex(ngx_buf_t *b, ngx_rtmp_mp4_metadata_t *metadata)
{
    u_char         *pos;
    uint32_t        sample_dur;

    if (metadata->video == 1) {
        sample_dur = metadata->frame_rate > 0 ? NGX_RTMP_MP4_TIMESCALE / 
                     metadata->frame_rate : NGX_RTMP_MP4_TIMESCALE;
    }
    else {
        sample_dur = metadata->audio_codec == NGX_RTMP_AUDIO_AAC ? 1024 : 1152;
    }

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mvex", sizeof("mvex")-1);

    /* just write the trex and mehd in here too */
#if 0
    ngx_rtmp_mp4_field_32(b, 16);

    b->last = ngx_cpymem(b->last, "mehd", sizeof("mehd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 0x000D8D2A); /* frag duration */
#endif
    ngx_rtmp_mp4_field_32(b, 0x20);

    b->last = ngx_cpymem(b->last, "trex", sizeof("trex")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version & flags */
    ngx_rtmp_mp4_field_32(b, 1); /* track id */
    ngx_rtmp_mp4_field_32(b, 1); /* default sample description index */
    ngx_rtmp_mp4_field_32(b, sample_dur); /* default sample duration */
    ngx_rtmp_mp4_field_32(b, 0); /* default sample size */
    /* default sample flags */
    ngx_rtmp_mp4_field_32(b, metadata->audio == 1 ? 0 : 0x00010000); 

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_moov(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                        ngx_rtmp_mp4_metadata_t *metadata) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "moov", sizeof("moov")-1);

    ngx_rtmp_mp4_write_mvhd(b, metadata);
    ngx_rtmp_mp4_write_mvex(b, metadata);
    ngx_rtmp_mp4_write_trak(s, b, metadata);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_tfhd(ngx_buf_t *b, ngx_uint_t sample_rate) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "tfhd", sizeof("tfhd")-1);

    /* version & flags */
    ngx_rtmp_mp4_field_32(b, sample_rate > 0 ? 0x00020020 : 0x00020000); 
    ngx_rtmp_mp4_field_32(b, 1); /* track id */
    if (sample_rate > 0) {
        ngx_rtmp_mp4_field_32(b, 0x02000000);
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_tfdt(ngx_buf_t *b, ngx_uint_t earliest_pres_time, 
    ngx_uint_t sample_rate) 
{
    u_char         *pos;
    float           multiplier;

    if (sample_rate > 0) {
        multiplier = (float)sample_rate/(float)NGX_RTMP_MP4_TIMESCALE;
    }
    else {
        multiplier = 1;
    }

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "tfdt", sizeof("tfdt")-1);

    ngx_rtmp_mp4_field_32(b, 0x00000000); /* version == 1 aka 64 bit integer */
    /* earliest presentation time */
    ngx_rtmp_mp4_field_32(b, (uint32_t)((float)earliest_pres_time*multiplier)); 

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_trun(ngx_buf_t *b, uint32_t sample_count, 
    ngx_rtmp_mp4_sample_t *samples, u_char *moof_pos)
{
    u_char    *pos;
    uint32_t   i, offset;

    pos = b->last;

    offset = (pos - moof_pos) + 20 + (sample_count * 4 * 4) + 8;  

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "trun", sizeof("trun") - 1);

    ngx_rtmp_mp4_field_32(b, 0x00000f01); 
    ngx_rtmp_mp4_field_32(b, sample_count);
    ngx_rtmp_mp4_field_32(b, offset);

    for (i = 0; i < sample_count; i++) {
        ngx_rtmp_mp4_field_32(b, samples[i].duration); 
        ngx_rtmp_mp4_field_32(b, samples[i].size); 
        ngx_rtmp_mp4_field_32(b, samples[i].key ? 0x00000000 : 0x00010000);
        ngx_rtmp_mp4_field_32(b, samples[i].delay); 
    }

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_traf(ngx_buf_t *b, ngx_uint_t earliest_pres_time, 
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples, u_char *moof_pos,
    ngx_uint_t sample_rate)
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "traf", sizeof("traf")-1);

    ngx_rtmp_mp4_write_tfhd(b, sample_rate);
    ngx_rtmp_mp4_write_tfdt(b, earliest_pres_time, sample_rate);
    ngx_rtmp_mp4_write_trun(b, sample_count, samples, moof_pos);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mp4_write_mfhd(ngx_buf_t *b, uint32_t index) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "mfhd", sizeof("mfhd")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* don't know what this is */
    ngx_rtmp_mp4_field_32(b, index); /* fragment index. */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_sidx(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_uint_t reference_size, ngx_uint_t earliest_pres_time, 
    ngx_uint_t latest_pres_time, ngx_uint_t sample_rate) 
{
    u_char         *pos;
    uint32_t        ept, dur;

    if (sample_rate > 0) {
        ept =  (uint32_t)((float)earliest_pres_time*((float)sample_rate / 
                    (float)NGX_RTMP_MP4_TIMESCALE));
        dur =  (uint32_t)((float)(latest_pres_time-earliest_pres_time) * 
                    ((float)sample_rate/(float)NGX_RTMP_MP4_TIMESCALE));
    }
    else {
        ept = earliest_pres_time;
        dur = (latest_pres_time-earliest_pres_time);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "dash: buffered dash range start: %uL, duration: %uL",
                   ept, dur);
    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "sidx", sizeof("sidx")-1);

    ngx_rtmp_mp4_field_32(b, 0); /* version */
    ngx_rtmp_mp4_field_32(b, 1); /* reference id */
    /* timescale */
    ngx_rtmp_mp4_field_32(b, sample_rate > 0 ? sample_rate : 
                                               NGX_RTMP_MP4_TIMESCALE); 
    ngx_rtmp_mp4_field_32(b, ept); /* earliest presentation time */
    ngx_rtmp_mp4_field_32(b, 0); /* first offset */
    ngx_rtmp_mp4_field_16(b, 0); /* reserved */
    ngx_rtmp_mp4_field_16(b, 1); /* reference count (=1) */
    /* 1st bit is reference type, the rest is reference size */
    ngx_rtmp_mp4_field_32(b, reference_size); 
    ngx_rtmp_mp4_field_32(b, dur); /* subsegment duration */
    /* first bit is startsWithSAP (=1), next 3 bits are SAP type (=001) */
    ngx_rtmp_mp4_field_8(b, 0x90); 
    ngx_rtmp_mp4_field_24(b, 0); /* SAP delta time */

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_mp4_write_moof(ngx_buf_t *b, ngx_uint_t earliest_pres_time, 
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples, uint32_t index,
    ngx_uint_t sample_rate) 
{
    u_char         *pos;

    pos = b->last;

    /* box size placeholder */
    ngx_rtmp_mp4_field_32(b, 0);

    b->last = ngx_cpymem(b->last, "moof", sizeof("moof")-1);

    ngx_rtmp_mp4_write_mfhd(b, index);
    ngx_rtmp_mp4_write_traf(b, earliest_pres_time, sample_count, samples,
                            pos, sample_rate);

    ngx_rtmp_mp4_update_box_size(b, pos);

    return NGX_OK;
}


ngx_uint_t 
ngx_rtmp_mp4_write_mdat(ngx_buf_t *b, ngx_uint_t size) 
{
    ngx_rtmp_mp4_field_32(b, size);

    b->last = ngx_cpymem(b->last, "mdat", sizeof("mdat")-1);

    return NGX_OK;
}
