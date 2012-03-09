/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp.h"
#include "ngx_rtmp_amf0.h"

ngx_int_t 
ngx_rtmp_connect(ngx_rtmp_session_t *s, ngx_chain_t *li)
{
    ngx_rtmp_packet_hdr_t   h;
    ngx_chain_t             lo, *lo_amf;
    ngx_buf_t               bo;
    u_char                  buf[6], *p;
    uint16_t                ctl_evt;
    uint32_t                msid;
    uint32_t                ack_size;
    uint8_t                 limit_type;
    ngx_rtmp_amf0_ctx_t     amf_ctx;

    static double                   trans;

    static ngx_rtmp_amf0_elt_t      inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,   0 },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,   0 },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,   0 },
    };

    static ngx_rtmp_amf0_elt_t      elts[] = {
        { NGX_RTMP_AMF0_STRING, 0,  "_result",  sizeof("_result") - 1  },
        { NGX_RTMP_AMF0_NUMBER, 0,  &trans,     sizeof(trans)       },
        { NGX_RTMP_AMF0_NULL  , 0,  NULL,       0                   },    
        { NGX_RTMP_AMF0_OBJECT, 0,  inf,        sizeof(inf)         },
    };

    /* 1) send 'Window Acknowledgement Size'
     *
     * 2) send 'Set Peer Bandwidth'
     *
     * 3*) receive 'Window Acknowledgement'
     *
     * 4) send 'User Control Message(StreamBegin)'
     * '
     * 5) AMF0 reply:
     *
     * "_ result"
     * 1
     * NULL
     * { code        : "NetConnection.Connect.Success", 
     *   level       : "status", 
     *   description : "Connection succeeded." }
     */
    memset(&h, 0, sizeof(h));
    h.timestamp = 0;
    h.csid = 2; /* standard */
    h.msid = 0;
    lo.buf = &bo;
    lo.next = NULL;

    /* send Window Acknowledgement Size*/
    h.type = NGX_RTMP_PACKET_ACK_SIZE;
    ack_size = 65536;
    p = (u_char*)&ack_size;
    buf[0] = p[3];
    buf[1] = p[2];
    buf[2] = p[1];
    buf[3] = p[0];
    bo.start = bo.pos = buf;
    bo.end = bo.last = bo.start + 4;
    ngx_rtmp_send_packet(s, &h, &lo);

    /* send Set Peer Bandwidth */
    h.type = NGX_RTMP_PACKET_BANDWIDTH;
    ack_size = 65536;
    limit_type = 1;
    p = (u_char*)&ack_size;
    buf[0] = p[3];
    buf[1] = p[2];
    buf[2] = p[1];
    buf[3] = p[0];
    buf[4] = limit_type;
    bo.start = bo.pos = buf;
    bo.end = bo.last = bo.start + 5;
    ngx_rtmp_send_packet(s, &h, &lo);

    /* send STREAM_BEGIN */

    h.type = NGX_RTMP_PACKET_CTL;

    msid = 1;
    ctl_evt = NGX_RTMP_CTL_STREAM_BEGIN;

    p = (u_char*)&ctl_evt;
    buf[0] = p[1];
    buf[1] = p[0];

    p = (u_char*)&msid;
    buf[2] = p[3];
    buf[3] = p[2];
    buf[4] = p[1];
    buf[5] = p[0];
    
    bo.start = bo.pos = buf;
    bo.end = bo.last = bo.start + sizeof(buf);

    ngx_rtmp_send_packet(s, &h, &lo);

    /* send 'connect' reply */
    h.type = NGX_RTMP_PACKET_AMF0_CMD;
    h.csid = s->csid;
    inf[0].data = "NetConnection.Connect.Success"; /* code */
    inf[0].len = strlen(inf[0].data);
    inf[1].data = "status"; /* level */
    inf[1].len = strlen(inf[1].data);
    inf[2].data = "Connection succeeded."; /* description */
    inf[2].len = strlen(inf[2].data);
    trans = 1;

    lo_amf = NULL;
    amf_ctx.link = &lo_amf;
    amf_ctx.free = &s->free;
    amf_ctx.log = s->connection->log;
    if (ngx_rtmp_amf0_write(&amf_ctx, elts, 
                sizeof(elts) / sizeof(elts[0])) != NGX_OK) 
    {
        return NGX_ERROR;
    }

    ngx_rtmp_send_packet(s, &h, lo_amf);

    return NGX_OK;
}

ngx_int_t 
ngx_rtmp_call(ngx_rtmp_session_t *s, ngx_chain_t *l)
{
    return NGX_OK;
}

ngx_int_t 
ngx_rtmp_close(ngx_rtmp_session_t *s, ngx_chain_t *l)
{
    return NGX_OK;
}

ngx_int_t 
ngx_rtmp_createstream(ngx_rtmp_session_t *s, ngx_chain_t *l)
{
    return NGX_OK;
}

