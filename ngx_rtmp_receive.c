/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"
#include <string.h>


ngx_int_t 
ngx_rtmp_protocol_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_buf_t              *b;
    u_char                 *p; 
    uint32_t                val;
    uint8_t                 limit;

    b = in->buf;

    if (b->last - b->pos < 4) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "too small buffer for %d message: %d",
                (int)h->type, b->last - b->pos);
        return NGX_OK;
    }

    p = (u_char*)&val;
    p[0] = b->pos[3];
    p[1] = b->pos[2];
    p[2] = b->pos[1];
    p[3] = b->pos[0];

    switch(h->type) {
        case NGX_RTMP_MSG_CHUNK_SIZE:
            /* set chunk size =val */
            ngx_rtmp_set_chunk_size(s, val);
            break;

        case NGX_RTMP_MSG_ABORT:
            /* abort chunk stream =val */
            break;

        case NGX_RTMP_MSG_ACK:
            /* receive ack with sequence number =val */
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "receive ack seq=%uD", val);
            break;

        case NGX_RTMP_MSG_ACK_SIZE:
            /* receive window size =val */
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "receive ack_size=%uD", val);
            break;

        case NGX_RTMP_MSG_BANDWIDTH:
            if (b->last - b->pos >= 5) {
                limit = *(uint8_t*)&b->pos[4];

                (void)val;
                (void)limit;

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "receive bandwidth=%uD limit=%d", 
                    val, (int)limit);

                /* receive window size =val
                 * && limit */
            }
            break;

        default:
            return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_rtmp_user_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_buf_t              *b;
    u_char                 *p; 
    uint16_t                evt;
    uint32_t                val, arg;

    b = in->buf;

    if (b->last - b->pos < 6) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "too small buffer for user message: %d",
                b->last - b->pos);
        return NGX_OK;
    }

    p = (u_char*)&evt;
    p[0] = b->pos[1];
    p[1] = b->pos[0];

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP recv user evt %s (%d)", 
            ngx_rtmp_user_message_type(evt), (int)evt);

    p = (u_char*)&val;
    p[0] = b->pos[5];
    p[1] = b->pos[4];
    p[2] = b->pos[3];
    p[3] = b->pos[2];

    switch(evt) {
        case NGX_RTMP_USER_STREAM_BEGIN:
            /* use =val as stream id which started */
            break;

        case NGX_RTMP_USER_STREAM_EOF:
            /* use =val as stream id which is over */
            break;

        case NGX_RTMP_USER_STREAM_DRY:
            /* stream =val is dry */
            break;

        case NGX_RTMP_USER_SET_BUFLEN:
            if (b->last - b->pos >= 10) {
                p = (u_char*)&arg;
                p[0] = b->pos[9];
                p[1] = b->pos[8];
                p[2] = b->pos[7];
                p[3] = b->pos[6];

                /* use =val as stream id && arg as buflen in msec*/
                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                        "msid=%uD buflen: %uD (msec)", val, arg);

                ngx_rtmp_send_user_stream_begin(s, val);
            }
            break;

        case NGX_RTMP_USER_RECORDED:
            /* stream =val is recorded */
            break;

        case NGX_RTMP_USER_PING_REQUEST:
            ngx_rtmp_send_user_ping_response(s, val);
            break;

        case NGX_RTMP_USER_PING_RESPONSE:
            /* use =val as incoming timestamp */
            ngx_rtmp_reset_ping(s);
            break;

        default:
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "unexpected user event: %d",
                (int)evt);

            return NGX_OK;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_rtmp_amf_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_amf_ctx_t          act;
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_array_t                *ch;
    ngx_rtmp_handler_pt        *ph;
    size_t                      len, n;

    static u_char               func[128];

    static ngx_rtmp_amf_elt_t   elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,  
          func,   sizeof(func) },
    };

    /* AMF command names come with string type, but shared object names
     * come without type */
    if (h->type == NGX_RTMP_MSG_AMF_SHARED || 
        h->type == NGX_RTMP_MSG_AMF3_SHARED) 
    {
        elts[0].type |= NGX_RTMP_AMF_TYPELESS;
    } else {
        elts[0].type &= ~NGX_RTMP_AMF_TYPELESS;
    }

    if ((h->type == NGX_RTMP_MSG_AMF3_SHARED ||
         h->type == NGX_RTMP_MSG_AMF3_META ||
         h->type == NGX_RTMP_MSG_AMF3_CMD)
         && in->buf->last > in->buf->pos) 
    {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "AMF3 prefix: %ui", (ngx_int_t)*in->buf->pos);
        ++in->buf->pos;
    }

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    /* read AMF func name & transaction id */
    act.link = in;
    act.log = s->connection->log;
    memset(func, 0, sizeof(func));

    if (ngx_rtmp_amf_read(&act, elts, 
                sizeof(elts) / sizeof(elts[0])) != NGX_OK) 
    {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "AMF cmd failed");
        return NGX_ERROR;
    }

    len = ngx_strlen(func);

    ch = ngx_hash_find(&cmcf->amf_hash, 
            ngx_hash_strlow(func, func, len), func, len);

    if (ch && ch->nelts) {
        ph = ch->elts;
        for (n = 0; n < ch->nelts; ++n, ++ph) {
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "AMF func '%s' passed to handler %d/%d", 
                func, n, ch->nelts);
            switch ((*ph)(s, h, in)) {
                case NGX_ERROR:
                    return NGX_ERROR;
                case NGX_DONE:
                    return NGX_OK;
            }
        }
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "AMF cmd '%s' no handler", func);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_receive_amf(ngx_rtmp_session_t *s, ngx_chain_t *in,
        ngx_rtmp_amf_elt_t *elts, size_t nelts)
{
    ngx_rtmp_amf_ctx_t     act;

    act.link = in;
    act.log = s->connection->log;

    return ngx_rtmp_amf_read(&act, elts, nelts);
}

