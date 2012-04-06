/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"


#define NGX_RTMP_USER_START(s, tp)              \
    ngx_rtmp_header_t         __h;              \
    ngx_chain_t              *__l;              \
    ngx_buf_t                *__b;              \
    ngx_rtmp_core_srv_conf_t *__cscf;           \
                                                \
    __cscf = ngx_rtmp_get_module_srv_conf(      \
            s, ngx_rtmp_core_module);           \
    memset(&__h, 0, sizeof(__h));               \
    __h.type = tp;                              \
    __h.csid = 2;                               \
    __l = ngx_rtmp_alloc_shared_buf(__cscf);    \
    if (__l == NULL) {                          \
        return NGX_ERROR;                       \
    }                                           \
    __b = __l->buf;     

#define NGX_RTMP_UCTL_START(s, type, utype)     \
    NGX_RTMP_USER_START(s, type);               \
    *(__b->last++) = (u_char)((utype) >> 8);    \
    *(__b->last++) = (u_char)(utype);

#define NGX_RTMP_USER_OUT1(v)                   \
    *(__b->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_USER_OUT4(v)                   \
    *(__b->last++) = ((u_char*)&v)[3];          \
    *(__b->last++) = ((u_char*)&v)[2];          \
    *(__b->last++) = ((u_char*)&v)[1];          \
    *(__b->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_USER_END(s)                    \
    ngx_rtmp_prepare_message(s, &__h, NULL, __l);  \
    return ngx_rtmp_send_message(s, __l, 0);    \


/* Protocol control messages */
ngx_int_t
ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size)
{
    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

    NGX_RTMP_USER_OUT4(chunk_size);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_abort(ngx_rtmp_session_t *s, uint32_t csid)
{
    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

    NGX_RTMP_USER_OUT4(csid);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_ack(ngx_rtmp_session_t *s, uint32_t seq)
{
    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK);

    NGX_RTMP_USER_OUT4(seq);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s, uint32_t ack_size)
{
    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK_SIZE);

    NGX_RTMP_USER_OUT4(ack_size);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s, uint32_t ack_size,
        uint8_t limit_type)
{
    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_BANDWIDTH);

    NGX_RTMP_USER_OUT4(ack_size);
    NGX_RTMP_USER_OUT1(limit_type);

    NGX_RTMP_USER_END(s);
}


/* User control messages */
ngx_int_t
ngx_rtmp_send_user_stream_begin(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_BEGIN);

    NGX_RTMP_USER_OUT4(msid);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_stream_eof(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_EOF);

    NGX_RTMP_USER_OUT4(msid);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_stream_dry(ngx_rtmp_session_t *s, uint32_t msid)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_DRY);

    NGX_RTMP_USER_OUT4(msid);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_set_buflen(ngx_rtmp_session_t *s, uint32_t msid, 
        uint32_t buflen_msec)
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_SET_BUFLEN);

    NGX_RTMP_USER_OUT4(msid);
    NGX_RTMP_USER_OUT4(buflen_msec);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_recorded(ngx_rtmp_session_t *s, uint32_t msid) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_RECORDED);

    NGX_RTMP_USER_OUT4(msid);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_ping_request(ngx_rtmp_session_t *s, uint32_t timestamp) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_PING_REQUEST);

    NGX_RTMP_USER_OUT4(timestamp);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_ping_response(ngx_rtmp_session_t *s, uint32_t timestamp) 
{
    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_PING_RESPONSE);

    NGX_RTMP_USER_OUT4(timestamp);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_user_unknown(ngx_rtmp_session_t *s, uint32_t timestamp) 
{
    static uint32_t     zero;
    static uint32_t     one = 1;
    uint32_t            val;

    NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_UNKNOWN);

    NGX_RTMP_USER_OUT4(zero);
    NGX_RTMP_USER_OUT4(one);
    val = timestamp & 0x7fffffff;
    NGX_RTMP_USER_OUT4(val);

    NGX_RTMP_USER_END(s);
}


static ngx_chain_t * 
ngx_rtmp_alloc_amf_buf(void *arg)
{
    return ngx_rtmp_alloc_shared_buf((ngx_rtmp_core_srv_conf_t *)arg);
}


/* AMF sender */
ngx_chain_t *
ngx_rtmp_create_amf_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t **last, ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_rtmp_amf_ctx_t          act;
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    memset(&act, 0, sizeof(act));
    act.arg = cscf;
    if (last) {
        act.link = *last;
    }
    act.alloc = ngx_rtmp_alloc_amf_buf;
    act.log = s->connection->log;

    if (ngx_rtmp_amf_write(&act, elts, nelts) != NGX_OK) {
        if (act.first) {
            ngx_rtmp_free_shared_bufs(cscf, act.first);
        }
        return NULL;
    }

    if (act.first) {
        ngx_rtmp_prepare_message(s, h, NULL, act.first);
    }

    if (last) {
        *last = act.link;
    }

    return act.first;
}

ngx_int_t ngx_rtmp_send_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_chain_t                *cl;
    ngx_int_t                   rc;
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    cl = ngx_rtmp_create_amf_message(s, h, NULL, elts, nelts);

    if (cl == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_rtmp_send_message(s, cl, 0);

    ngx_rtmp_free_shared_bufs(cscf, cl);

    return rc;
}

