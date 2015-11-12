
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"
#include "ngx_rtmp_streams.h"


#define NGX_RTMP_USER_START(s, tp)                                          \
    ngx_rtmp_header_t               __h;                                    \
    ngx_chain_t                    *__l;                                    \
    ngx_buf_t                      *__b;                                    \
    ngx_rtmp_core_srv_conf_t       *__cscf;                                 \
                                                                            \
    __cscf = ngx_rtmp_get_module_srv_conf(                                  \
            s, ngx_rtmp_core_module);                                       \
    memset(&__h, 0, sizeof(__h));                                           \
    __h.type = tp;                                                          \
    __h.csid = 2;                                                           \
    __l = ngx_rtmp_alloc_shared_buf(__cscf);                                \
    if (__l == NULL) {                                                      \
        return NULL;                                                        \
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
    return __l;


static ngx_int_t
ngx_rtmp_send_shared_packet(ngx_rtmp_session_t *s, ngx_chain_t *cl)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_int_t                       rc;

    if (cl == NULL) {
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    rc = ngx_rtmp_send_message(s, cl, 0);

    ngx_rtmp_free_shared_chain(cscf, cl);

    return rc;
}


/* Protocol control messages */

ngx_chain_t *
ngx_rtmp_create_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "chunk_size=%uD", chunk_size);

    {
        NGX_RTMP_USER_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

        NGX_RTMP_USER_OUT4(chunk_size);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_chunk_size(s, chunk_size));
}


ngx_chain_t *
ngx_rtmp_create_abort(ngx_rtmp_session_t *s, uint32_t csid)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: abort csid=%uD", csid);

    {
        NGX_RTMP_USER_START(s, NGX_RTMP_MSG_CHUNK_SIZE);

        NGX_RTMP_USER_OUT4(csid);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_abort(ngx_rtmp_session_t *s, uint32_t csid)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_abort(s, csid));
}


ngx_chain_t *
ngx_rtmp_create_ack(ngx_rtmp_session_t *s, uint32_t seq)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: ack seq=%uD", seq);

    {
        NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK);

        NGX_RTMP_USER_OUT4(seq);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_ack(ngx_rtmp_session_t *s, uint32_t seq)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_ack(s, seq));
}


ngx_chain_t *
ngx_rtmp_create_ack_size(ngx_rtmp_session_t *s, uint32_t ack_size)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: ack_size=%uD", ack_size);

    {
        NGX_RTMP_USER_START(s, NGX_RTMP_MSG_ACK_SIZE);

        NGX_RTMP_USER_OUT4(ack_size);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s, uint32_t ack_size)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_ack_size(s, ack_size));
}


ngx_chain_t *
ngx_rtmp_create_bandwidth(ngx_rtmp_session_t *s, uint32_t ack_size,
                          uint8_t limit_type)
{
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: bandwidth ack_size=%uD limit=%d",
                   ack_size, (int)limit_type);

    {
        NGX_RTMP_USER_START(s, NGX_RTMP_MSG_BANDWIDTH);

        NGX_RTMP_USER_OUT4(ack_size);
        NGX_RTMP_USER_OUT1(limit_type);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s, uint32_t ack_size,
                        uint8_t limit_type)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_bandwidth(s, ack_size, limit_type));
}


/* User control messages */

ngx_chain_t *
ngx_rtmp_create_stream_begin(ngx_rtmp_session_t *s, uint32_t msid)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: stream_begin msid=%uD", msid);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_BEGIN);

        NGX_RTMP_USER_OUT4(msid);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_stream_begin(ngx_rtmp_session_t *s, uint32_t msid)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_stream_begin(s, msid));
}


ngx_chain_t *
ngx_rtmp_create_stream_eof(ngx_rtmp_session_t *s, uint32_t msid)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: stream_end msid=%uD", msid);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_EOF);

        NGX_RTMP_USER_OUT4(msid);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_stream_eof(ngx_rtmp_session_t *s, uint32_t msid)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_stream_eof(s, msid));
}


ngx_chain_t *
ngx_rtmp_create_stream_dry(ngx_rtmp_session_t *s, uint32_t msid)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: stream_dry msid=%uD", msid);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_STREAM_DRY);

        NGX_RTMP_USER_OUT4(msid);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_stream_dry(ngx_rtmp_session_t *s, uint32_t msid)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_stream_dry(s, msid));
}


ngx_chain_t *
ngx_rtmp_create_set_buflen(ngx_rtmp_session_t *s, uint32_t msid,
                           uint32_t buflen_msec)
{
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: set_buflen msid=%uD buflen=%uD",
                   msid, buflen_msec);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_SET_BUFLEN);

        NGX_RTMP_USER_OUT4(msid);
        NGX_RTMP_USER_OUT4(buflen_msec);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_set_buflen(ngx_rtmp_session_t *s, uint32_t msid,
        uint32_t buflen_msec)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_set_buflen(s, msid, buflen_msec));
}


ngx_chain_t *
ngx_rtmp_create_recorded(ngx_rtmp_session_t *s, uint32_t msid)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: recorded msid=%uD", msid);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_RECORDED);

        NGX_RTMP_USER_OUT4(msid);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_recorded(ngx_rtmp_session_t *s, uint32_t msid)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_recorded(s, msid));
}


ngx_chain_t *
ngx_rtmp_create_ping_request(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: ping_request timestamp=%uD", timestamp);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_PING_REQUEST);

        NGX_RTMP_USER_OUT4(timestamp);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_ping_request(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_ping_request(s, timestamp));
}


ngx_chain_t *
ngx_rtmp_create_ping_response(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: ping_response timestamp=%uD", timestamp);

    {
        NGX_RTMP_UCTL_START(s, NGX_RTMP_MSG_USER, NGX_RTMP_USER_PING_RESPONSE);

        NGX_RTMP_USER_OUT4(timestamp);

        NGX_RTMP_USER_END(s);
    }
}


ngx_int_t
ngx_rtmp_send_ping_response(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_ping_response(s, timestamp));
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


ngx_chain_t *
ngx_rtmp_create_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                    ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_chain_t                *first;
    ngx_int_t                   rc;
    ngx_rtmp_core_srv_conf_t   *cscf;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: amf nelts=%ui", nelts);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    first = NULL;

    rc = ngx_rtmp_append_amf(s, &first, NULL, elts, nelts);

    if (rc != NGX_OK && first) {
        ngx_rtmp_free_shared_chain(cscf, first);
        first = NULL;
    }

    if (first) {
        ngx_rtmp_prepare_message(s, h, NULL, first);
    }

    return first;
}


ngx_int_t
ngx_rtmp_send_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                  ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_amf(s, h, elts, nelts));
}


ngx_chain_t *
ngx_rtmp_create_status(ngx_rtmp_session_t *s, char *code, char* level,
                       char *desc)
{
    ngx_rtmp_header_t               h;
    static double                   trans;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
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

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: status code='%s' level='%s' desc='%s'",
                   code, level, desc);

    out_inf[0].data = level;
    out_inf[1].data = code;
    out_inf[2].data = desc;
    trans = 0;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_status(ngx_rtmp_session_t *s, char *code, char* level, char *desc)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_status(s, code, level, desc));
}


ngx_chain_t *
ngx_rtmp_create_play_status(ngx_rtmp_session_t *s, char *code, char* level,
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

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "create: play_status code='%s' level='%s' "
                   "duration=%ui bytes=%ui",
                   code, level, duration, bytes);

    out_inf[0].data = code;
    out_inf[1].data = level;

    dduration = duration;
    dbytes = bytes;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_META;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;
    h.timestamp = duration;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_play_status(ngx_rtmp_session_t *s, char *code, char* level,
                          ngx_uint_t duration, ngx_uint_t bytes)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_play_status(s, code, level, duration, bytes));
}


// ----------- Based on Adobe FMS 3 application.redirectConnection description --------- //

ngx_chain_t *
ngx_rtmp_create_redirect_status(ngx_rtmp_session_t *s, char *callMethod, char *desc, ngx_str_t to_url)
{
    ngx_rtmp_header_t               h;
    static double                   dtrans;
    static double                   dcode;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "create redirect status: got data");
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "create redirect status: method='%s', status code='%s' level='%s' "
                   "ex.code=%ui ex.redirect='%s'", callMethod,
                   "NetConnection.Connect.Rejected", "error", 302, to_url.data);

    static ngx_rtmp_amf_elt_t       out_inf_ex_data[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("code"),
          &dcode, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("redirect"),
          NULL, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "error", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetConnection.Connect.Rejected", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_string("ex"),
          out_inf_ex_data,
          sizeof(out_inf_ex_data) },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &dtrans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf,
          sizeof(out_inf) },
    };

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "create redirect status: set structure data");

    out_elts[0].data = callMethod;
    out_inf[2].data = desc;
    dcode = 302;
    dtrans = 0;
    out_inf_ex_data[1].data = to_url.data;

    ngx_memzero(&h, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_redirect_status(ngx_rtmp_session_t *s,
                          char *callMethod, char *desc, ngx_str_t to_url)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_redirect_status(s, callMethod, desc, to_url));
}


ngx_chain_t *
ngx_rtmp_create_close_method(ngx_rtmp_session_t *s, char *methodName)
{
    ngx_rtmp_header_t               h;
    static double                   dtrans;

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &dtrans, 0 },
    };

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "create close method: set structure data");

    out_elts[0].data = methodName;
    dtrans = 0;

    ngx_memzero(&h, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_close_method(ngx_rtmp_session_t *s, char *methodName)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_close_method(s, methodName));
}


ngx_chain_t *
ngx_rtmp_create_fcpublish(ngx_rtmp_session_t *s, char *desc)
{
    ngx_rtmp_header_t               h;
    static double                   trans;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Publish.Start", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          NULL, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onFCPublish", 0 },

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

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "create: fcpublish - set structure data");

    out_inf[2].data = desc;
//    trans = 3.0;                // magick from ffmpeg
    trans = 0;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_fcpublish(ngx_rtmp_session_t *s, char *desc)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_fcpublish(s, desc));
}


ngx_chain_t *
ngx_rtmp_create_fcunpublish(ngx_rtmp_session_t *s, char *desc)
{
    ngx_rtmp_header_t               h;
    static double                   trans;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Unpublish.Success", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          NULL, 0 },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onFCUnpublish", 0 },

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

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "create: fcunpublish - set structure data");

    out_inf[2].data = desc;
//    trans = 5.0;                // magick from ffmpeg
    trans = 0;

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, out_elts,
                               sizeof(out_elts) / sizeof(out_elts[0]));
}


ngx_int_t
ngx_rtmp_send_fcunpublish(ngx_rtmp_session_t *s, char *desc)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_fcunpublish(s, desc));
}


ngx_chain_t *
ngx_rtmp_create_sample_access(ngx_rtmp_session_t *s)
{
    ngx_rtmp_header_t               h;

    static int                      access = 1;

    static ngx_rtmp_amf_elt_t       access_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "|RtmpSampleAccess", 0 },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &access, 0 },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &access, 0 },
    };

    memset(&h, 0, sizeof(h));

    h.type = NGX_RTMP_MSG_AMF_META;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    return ngx_rtmp_create_amf(s, &h, access_elts,
                               sizeof(access_elts) / sizeof(access_elts[0]));
}


ngx_int_t
ngx_rtmp_send_sample_access(ngx_rtmp_session_t *s)
{
    return ngx_rtmp_send_shared_packet(s,
           ngx_rtmp_create_sample_access(s));
}
