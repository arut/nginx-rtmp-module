
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_MPEGTS_H_INCLUDED_
#define _NGX_RTMP_MPEGTS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    uint64_t    pts;
    uint64_t    dts;
    ngx_uint_t  pid;
    ngx_uint_t  sid;
    ngx_uint_t  cc;
    unsigned    key:1;
} ngx_rtmp_mpegts_frame_t;


ngx_int_t ngx_rtmp_mpegts_write_header(ngx_file_t *file);
ngx_int_t ngx_rtmp_mpegts_write_frame(ngx_file_t *file,
          ngx_rtmp_mpegts_frame_t *f, ngx_buf_t *b);


#endif /* _NGX_RTMP_MPEGTS_H_INCLUDED_ */
