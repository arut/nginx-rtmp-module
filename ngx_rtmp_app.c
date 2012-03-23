/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_FMS_VERSION    "FMS/3,0,1,123"
#define NGX_RTMP_CAPABILITIES   31


ngx_int_t
ngx_rtmp_connect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_uint_t                  n;
    ngx_rtmp_core_app_conf_t  **cacfp;
    size_t                      len;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;

    static struct {
        u_char               app[1024];
        u_char               flashver[1024];
        u_char               swf_url[1024];
        u_char               tc_url[1024];
        double               acodecs;
        double               vcodecs;
        u_char               page_url[1024];
    } v;


    static ngx_rtmp_amf0_elt_t  in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",         v.app,      sizeof(v.app)      },
        { NGX_RTMP_AMF0_STRING, "flashver",    v.flashver, sizeof(v.flashver) },
        { NGX_RTMP_AMF0_STRING, "swfUrl",      v.swf_url,  sizeof(v.swf_url)  },
        { NGX_RTMP_AMF0_STRING, "tcUrl",       v.tc_url,   sizeof(v.tc_url)   },
        { NGX_RTMP_AMF0_NUMBER, "audioCodecs", &v.acodecs, sizeof(v.acodecs)  },
        { NGX_RTMP_AMF0_NUMBER, "videoCodecs", &v.vcodecs, sizeof(v.vcodecs)  },
        { NGX_RTMP_AMF0_STRING, "pageUrl",     v.page_url, sizeof(v.page_url) },
    };

    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,             &trans,     0                  },
        { NGX_RTMP_AMF0_OBJECT, NULL,          in_cmd,     sizeof(in_cmd)     },
    };

    static ngx_rtmp_amf0_elt_t  out_obj[] = {
        { NGX_RTMP_AMF0_STRING, "fmsVer",           NGX_RTMP_FMS_VERSION,   0 },
        { NGX_RTMP_AMF0_NUMBER, "capabilities",     &capabilities,          0 },
    };

    static ngx_rtmp_amf0_elt_t  out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "level",                          "status", 0 },
        { NGX_RTMP_AMF0_STRING, "code",    "NetConnection.Connect.Success", 0 },
        { NGX_RTMP_AMF0_STRING, "description",     "Connection succeeded.", 0 },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     0                         },
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_obj,    sizeof(out_obj)           },    
        { NGX_RTMP_AMF0_OBJECT, NULL,   out_inf,    sizeof(out_inf)           },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* parse input */
    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect: app='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD", 
            v.app, v.flashver, v.swf_url, v.tc_url, v.page_url,
            (uint32_t)v.acodecs, (uint32_t)v.vcodecs);

    /* fill session parameters */
    s->connected = 1;

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v.name);                                         \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v.name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->acodecs = v.acodecs;
    s->vcodecs = v.vcodecs;

    /* find application & set app_conf */
    len = ngx_strlen(v.app);

    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == len
                && !ngx_strncmp((*cacfp)->name.data, v.app, len))
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "application not found: '%s'", v.app);
        return NGX_ERROR;
    }

    /* send all replies */
    return ngx_rtmp_send_ack_size(s, cscf->ack_window)
        || ngx_rtmp_send_bandwidth(s, cscf->ack_window, NGX_RTMP_LIMIT_DYNAMIC)
        || ngx_rtmp_send_user_stream_begin(s, 0)
        || ngx_rtmp_send_chunk_size(s, cscf->chunk_size)
        || ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_ERROR
        : NGX_OK; 

    /* we need NGX_OK not NGX_DONE to make access module
     * work after connect has successfully finished */
}


ngx_int_t
ngx_rtmp_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    /* support one message stream per connection */
    static double               stream = 1; 
    static double               trans;

    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",  0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,     0                         },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,       0                         },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &stream,    sizeof(stream)            },
    };

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "createStream");

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    /* send result with standard stream */
    return ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK
        ? NGX_DONE
        : NGX_ERROR;
}


ngx_int_t 
ngx_rtmp_amf0_default(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;

    static double                   trans;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",                          0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
        { NGX_RTMP_AMF0_NULL  , NULL,   NULL,                               0 },
    };

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    memset(&sh, 0, sizeof(sh));
    sh.csid = h->csid;
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.msid = 0;

    /* send simple _result */
    return ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK
        ? NGX_DONE
        : NGX_ERROR;
}
