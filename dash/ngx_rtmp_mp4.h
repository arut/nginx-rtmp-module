

#ifndef _NGX_RTMP_MP4_H_INCLUDED_
#define _NGX_RTMP_MP4_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>


#define NGX_RTMP_MP4_SAMPLE_SIZE        0x01
#define NGX_RTMP_MP4_SAMPLE_DURATION    0x02
#define NGX_RTMP_MP4_SAMPLE_DELAY       0x04
#define NGX_RTMP_MP4_SAMPLE_KEY         0x08


typedef struct {
    uint32_t        size;
    uint32_t        duration;
    uint32_t        delay;
    uint32_t        timestamp;
    unsigned        key:1;
} ngx_rtmp_mp4_sample_t;


typedef struct {
    ngx_uint_t      width;
    ngx_uint_t      height;
    ngx_uint_t      audio;
    ngx_uint_t      video;
    ngx_uint_t      sample_rate;
    ngx_uint_t      frame_rate;
    ngx_uint_t      audio_codec;
} ngx_rtmp_mp4_metadata_t;


enum {
    NGX_RTMP_MP4_FILETYPE_INIT = 0,
    NGX_RTMP_MP4_FILETYPE_SEG
};


ngx_int_t ngx_rtmp_mp4_write_ftyp(ngx_buf_t *b, int type, 
    ngx_rtmp_mp4_metadata_t *metadata);
ngx_int_t ngx_rtmp_mp4_write_moov(ngx_rtmp_session_t *s, ngx_buf_t *b, 
    ngx_rtmp_mp4_metadata_t *metadata);
ngx_int_t ngx_rtmp_mp4_write_moof(ngx_buf_t *b, uint32_t earliest_pres_time,
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples,
    ngx_uint_t sample_mask, uint32_t index);
ngx_int_t ngx_rtmp_mp4_write_sidx(ngx_buf_t *b,
    ngx_uint_t reference_size, uint32_t earliest_pres_time, 
    uint32_t latest_pres_time);
ngx_uint_t ngx_rtmp_mp4_write_mdat(ngx_buf_t *b, ngx_uint_t size);


#endif /* _NGX_RTMP_MP4_H_INCLUDED_ */
