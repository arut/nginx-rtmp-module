/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h.h"
#include "ngx_rtmp_amf0.h"


#define NGX_RTMP_CTL_START(s, type)             \
    ngx_rtmp_packet_hdr_t   __h;                \
    ngx_chain_t            *__l;                \
    u_char                 *__p;                \
                                                \
    memset(&h, 0, sizeof(__h));                 \
    __h.type = type;                            \
    __h.csid = 2;                               \
    __l = ngx_rtmp_alloc_shared_buf(s);         \
    if (__l == NULL) {                          \
        return NGX_ERROR;                       \
    }                                           \
    __p = __l->buf->pos;

#define NGX_RTMP_UCTL_START(s, type, utype)     \
    NGX_RTMP_CTL_START(s, type);                \
    *(__p->last++) = (u_char)((utype) >> 8);    \
    *(__p->last++) = (u_char)(utype);

#define NGX_RTMP_CTL_OUT1(v)                    \
    *(__p->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_CTL_OUT4(v)                    \
    *(__p->last++) = ((u_char*)&v)[3];          \
    *(__p->last++) = ((u_char*)&v)[2];          \
    *(__p->last++) = ((u_char*)&v)[1];          \
    *(__p->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_CTL_END(s)                     \
    ngx_rtmp_prepare_message(&__h, __l, 0);     \
    ngx_rtmp_send_message(s, __l);              \
    return NGX_OK;

#define NGX_RTMP_AMF0_START(s, cs, ms)          \
    ngx_rtmp_packet_hdr_t   __h;                \
    ngx_rtmp_amf0_ctx_t     __act;              \
                                                \
    memset(&__act, 0, sizeof(__act));           \
    __act.arg = s;                              \
    __act.alloc = ngx_rtmp_alloc_shared_buf;    \
    __act.log = (s)->connection->log;           \
                                                \
    memset(&__h, 0, sizeof(__h));               \
    __h.type = NGX_RTMP_MSG_AMF0_CMD;           \
    __h.csid = cs;                              \
    __h.msid = ms;

#define NGX_RTMP_AMF0_END(s)                    \
    if (__act.first) {                          \
        ngx_rtmp_prepare_message(&__h,          \
                __act.first, 0);                \
        ngx_rtmp_send_message(s, __act.first);  \
    }                                           \
    return NGX_OK;


/* Protocol control messages */
ngx_int_t
ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size)
{
    NGX_RTMP_CTL_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

    NGX_RTMP_CTL_OUT4(chunk_size);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_abort(ngx_rtmp_session_t *s, uint32_t csid)
{
    NGX_RTMP_CTL_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

    NGX_RTMP_CTL_OUT4(csid);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_ack(ngx_rtmp_session_t *s, uint32_t seq)
{
    NGX_RTMP_CTL_START(s, NGX_RTMP_MSG_ACK);

    NGX_RTMP_CTL_OUT4(seq);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s, uint32_t ack_size)
{
    NGX_RTMP_CTL_START(s, NGX_RTMP_MSG_ACK_SIZE);

    NGX_RTMP_CTL_OUT4(ack_size);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s, uint32_t ack_size,
        uint8_t limit_type)
{
    NGX_RTMP_CTL_START(s, NGX_RTMP_MSG_BANDWIDTH);

    NGX_RTMP_CTL_OUT4(ack_size);
    NGX_RTMP_CTL_OUT1(limit_type);

    NGX_RTMP_CTL_END(s);
}


/* User control messages */
ngx_int_t
ngx_rtmp_send_user_stream_begin(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_STREAM_BEGIN);

    NGX_RTMP_CTL_OUT4(msid);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_stream_eof(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_STREAM_EOF);

    NGX_RTMP_CTL_OUT4(msid);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_stream_dry(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_STREAM_DRY);

    NGX_RTMP_CTL_OUT4(msid);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_set_buflen(ngx_rtmp_session_t *s, uint32_t msid, 
        uint32_t buflen_msec)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_SET_BUFLEN);

    NGX_RTMP_CTL_OUT4(msid);
    NGX_RTMP_CTL_OUT4(buflen_msec);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_recorded(ngx_rtmp_session_t *s, uint32_t msid) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_RECORDED);

    NGX_RTMP_CTL_OUT4(msid);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_ping_request(ngx_rtmp_session_t *s, uint32_t timestamp) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_PING_REQUEST);

    NGX_RTMP_CTL_OUT4(timestamp);

    NGX_RTMP_CTL_END(s);
}


ngx_int_t
ngx_rtmp_send_user_ping_response(ngx_rtmp_session_t *s, uint32_t timestamp) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_CTL, NGX_RTMP_CTL_PING_RESPONSE);

    NGX_RTMP_CTL_OUT4(timestamp);

    NGX_RTMP_CTL_END(s);
}

/* AMF0 sender */
ngx_int_t
ngx_rtmp_send_amf0(ngx_session_t *s, uint32_t csid, uint32_t msid,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts)
{
    NGX_RTMP_AMF0_START(s, csid, msid);

    if (ngx_rtmp_amf0_write(&__act, elts, nelts)) {
        return NGX_ERROR;
    }

    NGX_RTMP_AMF0_END(s);
}

