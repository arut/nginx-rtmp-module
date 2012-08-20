/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_RECORD_H_INCLUDED_
#define _NGX_RTMP_RECORD_H_INCLUDED_


#include "ngx_rtmp.h"

 
u_char * ngx_rtmp_record_make_path(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_record_open(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_record_close(ngx_rtmp_session_t *s);


#endif /* _NGX_RTMP_RECORD_H_INCLUDED_ */
