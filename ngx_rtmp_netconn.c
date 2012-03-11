/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp_amf0.h"

ngx_int_t 
ngx_rtmp_connect(ngx_rtmp_session_t *s, double in_trans, ngx_chain_t *in)
{
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

    static double                   trans;
    static char                     app[128];
    static char                     flashver[128];
    static char                     svfurl[128];

    static ngx_rtmp_amf0_elt_t      in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",          app,        sizeof(app)     },
        { NGX_RTMP_AMF0_STRING, "flashver",     flashver,   sizeof(flashver)},
        { NGX_RTMP_AMF0_STRING, "swfurl",       svfurl,     sizeof(svfurl)  },
    };

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_OBJECT, 0,  in_cmd,     sizeof(in_cmd)  },
        { NGX_RTMP_AMF0_NULL,   0,  NULL,       0               },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         NULL,   0 },
        { NGX_RTMP_AMF0_STRING, "level",        NULL,   0 },
        { NGX_RTMP_AMF0_STRING, "description",  NULL,   0 },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, 0,  "_result",  sizeof("_result") - 1   },
        { NGX_RTMP_AMF0_NUMBER, 0,  &trans,     sizeof(trans)           },
        { NGX_RTMP_AMF0_NULL  , 0,  NULL,       0                       },    
        { NGX_RTMP_AMF0_OBJECT, 0,  out_inf,    sizeof(out_inf)         },
    };

    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    trans = in_trans;
    ngx_str_set(&inf[0], "NetConnection.Connect.Success");
    ngx_str_set(&inf[1], "status");
    ngx_str_set(&inf[2], "Connection succeeded.");

    return ngx_rtmp_send_ack_size(s, 65536)
        || ngx_rtmp_send_bandwidth(s, 65536, NGX_RTMP_LIMIT_SOFT)
        || ngx_rtmp_send_user_stream_begin(s, 1)
        || ngx_rtmp_send_amf0(s, 3, 1, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_ERROR
        : NGX_OK;
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

