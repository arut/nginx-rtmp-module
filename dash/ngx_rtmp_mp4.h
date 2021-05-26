

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


typedef enum {
    NGX_RTMP_MP4_FILETYPE_INIT,
    NGX_RTMP_MP4_FILETYPE_SEG
} ngx_rtmp_mp4_file_type_t;


typedef enum {
    NGX_RTMP_MP4_VIDEO_TRACK,
    NGX_RTMP_MP4_AUDIO_TRACK
} ngx_rtmp_mp4_track_type_t;


ngx_int_t ngx_rtmp_mp4_field_64(ngx_buf_t *b, uint64_t n);
ngx_int_t ngx_rtmp_mp4_field_32(ngx_buf_t *b, uint32_t n);
ngx_int_t ngx_rtmp_mp4_field_24(ngx_buf_t *b, uint32_t n);
ngx_int_t ngx_rtmp_mp4_field_16(ngx_buf_t *b, uint16_t n);
ngx_int_t ngx_rtmp_mp4_field_8(ngx_buf_t *b, uint8_t n);
ngx_int_t ngx_rtmp_mp4_write_ftyp(ngx_buf_t *b);
ngx_int_t ngx_rtmp_mp4_write_styp(ngx_buf_t *b);
ngx_int_t ngx_rtmp_mp4_write_moov(ngx_rtmp_session_t *s, ngx_buf_t *b,
    ngx_rtmp_mp4_track_type_t ttype);
ngx_int_t ngx_rtmp_mp4_write_moof(ngx_buf_t *b, uint32_t earliest_pres_time,
    uint32_t sample_count, ngx_rtmp_mp4_sample_t *samples,
    ngx_uint_t sample_mask, uint32_t index);
ngx_int_t ngx_rtmp_mp4_write_sidx(ngx_buf_t *b,
    ngx_uint_t reference_size, uint32_t earliest_pres_time,
    uint32_t latest_pres_time);
u_char *ngx_rtmp_mp4_start_box(ngx_buf_t *b, const char box[4]);
ngx_int_t ngx_rtmp_mp4_update_box_size(ngx_buf_t *b, u_char *p);
ngx_uint_t ngx_rtmp_mp4_write_mdat(ngx_buf_t *b, ngx_uint_t size);


#endif /* _NGX_RTMP_MP4_H_INCLUDED_ */
