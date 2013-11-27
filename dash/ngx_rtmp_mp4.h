

#ifndef _NGX_RTMP_MP4_H_INCLUDED_
#define _NGX_RTMP_MP4_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>


typedef struct {
    ngx_uint_t  width;
    ngx_uint_t  height;
    ngx_uint_t  audio;
    ngx_uint_t  video;
    ngx_uint_t  sample_rate;
    ngx_uint_t  frame_rate;
    ngx_uint_t  audio_codec;
} ngx_rtmp_mp4_metadata_t;


enum {
    NGX_RTMP_MP4_FILETYPE_INIT = 0,
    NGX_RTMP_MP4_FILETYPE_SEG = 1
};


/* divide all times by this value.  this is the same resolution as RTMP so it 
is convenient */
#define NGX_RTMP_MP4_TIMESCALE  1000
/* normal forward playback as defined by spec */
#define NGX_RTMP_MP4_PREFERRED_RATE 0x00010000
/* full volume as defined by spec */
#define NGX_RTMP_MP4_PREFERRED_VOLUME 0x0100

ngx_int_t  ngx_rtmp_mp4_write_ftyp(ngx_buf_t *b, int type, 
                                   ngx_rtmp_mp4_metadata_t metadata);
ngx_int_t  ngx_rtmp_mp4_write_moov(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                                   ngx_rtmp_mp4_metadata_t metadata);
ngx_int_t  ngx_rtmp_mp4_write_moof(ngx_buf_t *b, 
                                   ngx_uint_t earliest_pres_time, 
                                   uint32_t sample_count, 
                                   uint32_t sample_sizes[128], uint32_t index,
                                   ngx_uint_t sample_rate);
ngx_int_t  ngx_rtmp_mp4_write_sidx(ngx_rtmp_session_t *s, ngx_buf_t *b, 
                                   ngx_uint_t reference_size, 
                                   ngx_uint_t earliest_pres_time, 
                                   ngx_uint_t latest_pres_time, 
                                   ngx_uint_t sample_rate);
ngx_uint_t ngx_rtmp_mp4_write_mdat(ngx_buf_t *b, ngx_uint_t size);
uint32_t   ngx_rtmp_mp4_write_data(ngx_rtmp_session_t *s, ngx_file_t *file, 
                                   ngx_buf_t *b);


#endif /* _NGX_RTMP_MP4_H_INCLUDED_ */