/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"
#include "ngx_rtmp_streams.h"


#define NGX_RTMP_USER_START(s, tp)                                          \
    ngx_rtmp_header_t               __h;                                    \
    ngx_chain_t                    *__l;                                    \
    ngx_buf_t                      *__b;                                    \
    ngx_rtmp_core_srv_conf_t       *__cscf;                                 \
    ngx_int_t                       rc;                                     \
                                                                            \
    __cscf = ngx_rtmp_get_module_srv_conf(                                  \
            s, ngx_rtmp_core_module);                                       \
    memset(&__h, 0, sizeof(__h));                                           \
    __h.type = tp;                                                          \
    __h.csid = 2;                                                           \
    __l = ngx_rtmp_alloc_shared_buf(__cscf);                                \
    if (__l == NULL) {                                                      \
        return NGX_ERROR;                                                   \
    }                                                                       \
    __b = __l->buf;     

#define NGX_RTMP_UCTL_START(s, type, utype)                                 \
    NGX_RTMP_USER_START(s, type);                                           \
    *(__b->last++) = (u_char)((utype) >> 8);                                \
    *(__b->last++) = (u_char)(utype);

#define NGX_RTMP_USER_OUT1(v)                                               \
    *(__b->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_USER_OUT4(v)                                               \
    *(__b->last++) = ((u_char*)&v)[3];                                      \
    *(__b->last++) = ((u_char*)&v)[2];                                      \
    *(__b->last++) = ((u_char*)&v)[1];                                      \
    *(__b->last++) = ((u_char*)&v)[0];

#define NGX_RTMP_USER_END(s)                                                \
    ngx_rtmp_prepare_message(s, &__h, NULL, __l);                           \
    rc = ngx_rtmp_send_message(s, __l, 0);                                  \
    ngx_rtmp_free_shared_chain(__cscf, __l);                                \
    return rc;


/* Protocol control messages */
ngx_int_t
ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "send chunk_size=%uD", chunk_size);

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
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "send ack seq=%uD", seq);

    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK);

    NGX_RTMP_USER_OUT4(seq);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s, uint32_t ack_size)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "send ack_size=%uD", ack_size);

    NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK_SIZE);

    NGX_RTMP_USER_OUT4(ack_size);

    NGX_RTMP_USER_END(s);
}


ngx_int_t
ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s, uint32_t ack_size,
        uint8_t limit_type)
{
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "send bandwidth ack_size=%uD limit=%d", 
            ack_size, (int)limit_type);

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

/* NOTE: this function does not free shared bufs on error */
ngx_int_t
ngx_rtmp_append_amf(ngx_rtmp_session_t *s,
        ngx_chain_t **first, ngx_chain_t **last, 
        ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_rtmp_amf_ctx_t          act;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_int_t                   rc;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    memset(&act, 0, sizeof(act));
    act.arg = cscf;
    act.alloc = ngx_rtmp_alloc_amf_buf;
    act.log = s->connection->log;

    if (first) {
        act.first = *first;
    }

    if (last) {
        act.link = *last;
    }

    rc = ngx_rtmp_amf_write(&act, elts, nelts);

    if (first) {
        *first = act.first;
    }

    if (last) {
        *last = act.link;
    }

    return rc;
}


ngx_int_t
ngx_rtmp_send_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_chain_t                *first;
    ngx_int_t                   rc;
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    first = NULL;
    rc = ngx_rtmp_append_amf(s, &first, NULL, elts, nelts);
    if (rc != NGX_OK || first == NULL) {
        goto done;
    }

    ngx_rtmp_prepare_message(s, h, NULL, first);

    rc = ngx_rtmp_send_message(s, first, 0);

done:
    ngx_rtmp_free_shared_chain(cscf, first);

    return rc;
}


ngx_int_t
ngx_rtmp_send_status(ngx_rtmp_session_t *s, char *code, char* level, char *desc)
{
    ngx_rtmp_header_t               h;
    static double                   trans;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          NULL, 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          NULL, 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("description"),
          NULL, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          "onStatus", 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf,
          sizeof(out_inf) },
    };


    out_inf[0].data = code;
    out_inf[1].data = level;
    out_inf[2].data = desc;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_send_amf(s, &h, out_elts, 
                             sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_play_status(ngx_rtmp_session_t *s, char *code, char* level,
                          ngx_uint_t duration, ngx_uint_t bytes)
{
    ngx_rtmp_header_t               h;
    static double                   dduration;
    static double                   dbytes;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          NULL, 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("duration"),
          &dduration, 0 },

        { NGX_RTMP_AMF_NUMBER, 
          ngx_string("bytes"),
          &dbytes, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          "onPlayStatus", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf,
          sizeof(out_inf) },
    };


    out_inf[0].data = code;
    out_inf[1].data = level;

    dduration = duration;
    dbytes = bytes;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_META;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_send_amf(s, &h, out_elts, 
                             sizeof(out_elts) / sizeof(out_elts[0]));
}
