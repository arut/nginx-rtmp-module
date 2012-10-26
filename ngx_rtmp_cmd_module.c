/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_streams.h"


#define NGX_RTMP_FMS_VERSION        "FMS/3,0,1,123"
#define NGX_RTMP_CAPABILITIES       31


ngx_rtmp_connect_pt          ngx_rtmp_connect;
ngx_rtmp_create_stream_pt    ngx_rtmp_create_stream;
ngx_rtmp_close_stream_pt     ngx_rtmp_close_stream;
ngx_rtmp_delete_stream_pt    ngx_rtmp_delete_stream;

ngx_rtmp_publish_pt          ngx_rtmp_publish;
ngx_rtmp_fcpublish_pt        ngx_rtmp_fcpublish;
ngx_rtmp_fcunpublish_pt      ngx_rtmp_fcunpublish;

ngx_rtmp_play_pt             ngx_rtmp_play;
ngx_rtmp_fcsubscribe_pt      ngx_rtmp_fcsubscribe;
ngx_rtmp_fcunsubscribe_pt    ngx_rtmp_fcunsubscribe;

ngx_rtmp_seek_pt             ngx_rtmp_seek;
ngx_rtmp_pause_pt            ngx_rtmp_pause;


static ngx_int_t ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf);


static ngx_rtmp_module_t  ngx_rtmp_cmd_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_cmd_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_cmd_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_cmd_module_ctx,               /* module context */
    NULL,                                   /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_cmd_connect_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    size_t                      len;

    static ngx_rtmp_connect_t   v;

    static ngx_rtmp_amf_elt_t  in_cmd[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("app"),
          v.app, sizeof(v.app) },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("flashVer"),
          v.flashver, sizeof(v.flashver) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          v.swf_url, sizeof(v.swf_url) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          v.tc_url, sizeof(v.tc_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          &v.acodecs, sizeof(v.acodecs) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          &v.vcodecs, sizeof(v.vcodecs) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          v.page_url, sizeof(v.page_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &v.object_encoding, 0},
    };

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_cmd, sizeof(in_cmd) },
    };

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    len = ngx_strlen(v.app);
    if (len && v.app[len - 1] == '/') {
        v.app[len - 1] = 0;
    }

    return ngx_rtmp_connect 
        ? ngx_rtmp_connect(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_uint_t                  n;
    size_t                      len;
    ngx_rtmp_header_t           h;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;
    static double               object_encoding = 0;

    static ngx_rtmp_amf_elt_t  out_obj[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("fmsVer"),
          NGX_RTMP_FMS_VERSION, 0 },
        
        { NGX_RTMP_AMF_NUMBER,
          ngx_string("capabilities"),
          &capabilities, 0 },
    };

    static ngx_rtmp_amf_elt_t  out_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          "NetConnection.Connect.Success", 0 }, 

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Connection succeeded.", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &object_encoding, 0 }
    };

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_obj, sizeof(out_obj) },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "connect: duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "connect: app='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
            "object_encoding=%ui", 
            v->app, v->flashver, v->swf_url, v->tc_url, v->page_url,
            (uint32_t)v->acodecs, (uint32_t)v->vcodecs,
            (ngx_int_t)v->object_encoding);

    trans = v->trans;

    /* fill session parameters */
    s->connected = 1;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;


#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v->name);                                        \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v->name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->acodecs = v->acodecs;
    s->vcodecs = v->vcodecs;

    /* find application & set app_conf */
    len = ngx_strlen(v->app);

    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == len
                && !ngx_strncmp((*cacfp)->name.data, v->app, len))
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "connect: application not found: '%s'", v->app);
        return NGX_ERROR;
    }

    object_encoding = v->object_encoding;

    /* send all replies */
    return ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK
        || ngx_rtmp_send_bandwidth(s, cscf->ack_window, 
                NGX_RTMP_LIMIT_DYNAMIC) != NGX_OK
        || ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK
        || ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
        ? NGX_ERROR
        : NGX_OK; 
}


static ngx_int_t
ngx_rtmp_cmd_create_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_create_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,      
          &v.trans, sizeof(v.trans) },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_create_stream
        ? ngx_rtmp_create_stream(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_create_stream_t *v)
{
    /* support one message stream per connection */
    static double               stream; 
    static double               trans;
    ngx_rtmp_header_t           h;

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &stream, sizeof(stream) },
    };

    trans = v->trans;
    stream = NGX_RTMP_MSID;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "createStream");

    /* send result with standard stream */
    return ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK
        ? NGX_DONE
        : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_cmd_close_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_close_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "closeStream");

    return ngx_rtmp_close_stream
        ? ngx_rtmp_close_stream(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_send_user_stream_eof(s, NGX_RTMP_MSID);

    /* Whatever happens return OK
     * since we should be careful with destruction */
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_delete_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_delete_stream
        ? ngx_rtmp_delete_stream(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_close_stream_t         cv;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "deleteStream");

    /* chain close_stream */
    cv.stream = 0;
    return ngx_rtmp_close_stream
        ? ngx_rtmp_close_stream(s, &cv)
        : NGX_OK;
}


static void
ngx_rtmp_cmd_fill_args(u_char name[NGX_RTMP_MAX_NAME], 
        u_char args[NGX_RTMP_MAX_ARGS])
{
    u_char      *p;

    p = (u_char *)ngx_strchr(name, '?');
    if (p == NULL) {
        return;
    }

    *p++ = 0;
    ngx_cpystrn(args, p, NGX_RTMP_MAX_ARGS);
}


static ngx_int_t
ngx_rtmp_cmd_publish_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_publish_t       v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,      
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.type, sizeof(v.type) },
    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    return ngx_rtmp_publish
        ? ngx_rtmp_publish(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_header_t               h;

    static double                   trans;

    static ngx_rtmp_amf_elt_t      out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Publish.Start", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Publish succeeded.", 0 },
    };

    static ngx_rtmp_amf_elt_t      out_elts[] = {

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
          out_inf, sizeof(out_inf) },
    };

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "publish: name='%s' args='%s' type=%s silent=%d",
            v->name, v->args, v->type, v->silent);

    if (v->silent) {
        return NGX_OK;
    }

    /* send onStatus reply */
    memset(&h, 0, sizeof(h));
    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    if (ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_fcpublish_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_fcpublish_t     v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },
    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_fcpublish
        ? ngx_rtmp_fcpublish(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_fcpublish(ngx_rtmp_session_t *s, ngx_rtmp_fcpublish_t *v)
{
    ngx_rtmp_header_t               h;

    static double                   trans;

    static ngx_rtmp_amf_elt_t      out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Publish.Start", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "FCPublish succeeded.", 0 },
    };

    static ngx_rtmp_amf_elt_t      out_elts[] = {

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
          out_inf, sizeof(out_inf) },
    };

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "fcpublish: name='%s'", v->name);

    /* send onFCPublish reply */
    memset(&h, 0, sizeof(h));
    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    if (ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_play_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t          v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.start, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.duration, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.reset, 0 }
    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    return ngx_rtmp_play
        ? ngx_rtmp_play(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_header_t               h;

    static double                   trans;
    static int                      access = 1;

    static ngx_rtmp_amf_elt_t      out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Play.Start", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Playback started.", 0 },
    };

    static ngx_rtmp_amf_elt_t      out_elts[] = {

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
          out_inf, sizeof(out_inf) },
    };

    static ngx_rtmp_amf_elt_t      out2_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          "NetStream.Play.Start", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("description"),
          "Started playing.", 0 },
    };

    static ngx_rtmp_amf_elt_t      out2_elts[] = {

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
          out2_inf,
          sizeof(out2_inf) },
    };

    static ngx_rtmp_amf_elt_t      out3_elts[] = {

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

    static ngx_rtmp_amf_elt_t      out4_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetStream.Data.Start", 0 },
    };

    static ngx_rtmp_amf_elt_t      out4_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onStatus", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out4_inf, sizeof(out4_inf) },
    };

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "play name='%s' args='%s' start=%i duration=%i "
            "reset=%i silent=%i",
            v->name, v->args, (ngx_int_t) v->start, 
            (ngx_int_t) v->duration, (ngx_int_t) v->reset, 
            (ngx_int_t) v->silent);

    if (v->silent) {
        return NGX_OK;
    }

    /* send onStatus reply */
    memset(&h, 0, sizeof(h));
    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    /*
    if (ngx_rtmp_send_user_recorded(s, NGX_RTMP_MSID) != NGX_OK) {
        return NGX_ERROR;
    }*/

    if (ngx_rtmp_send_user_stream_begin(s, NGX_RTMP_MSID) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send sample access meta message FIXME */
    if (ngx_rtmp_send_amf(s, &h, out2_elts,
                sizeof(out2_elts) / sizeof(out2_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send data start meta message */
    h.type = NGX_RTMP_MSG_AMF_META;
    if (ngx_rtmp_send_amf(s, &h, out3_elts,
                sizeof(out3_elts) / sizeof(out3_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_rtmp_send_amf(s, &h, out4_elts,
                sizeof(out4_elts) / sizeof(out4_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_fcsubscribe_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_fcsubscribe_t   v;

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_fcsubscribe
        ? ngx_rtmp_fcsubscribe(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_fcsubscribe(ngx_rtmp_session_t *s, ngx_rtmp_fcsubscribe_t *v)
{
    ngx_rtmp_header_t               h;

    static double                   trans;

    static ngx_rtmp_amf_elt_t      out_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          "NetStream.Play.Start", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("description"),
          "Started playing.", 0 },
    };

    static ngx_rtmp_amf_elt_t      out_elts[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_null_string,
          "onFCSubscribe", 0 },

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

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "fcsubscribe: name='%s'", v->name);

    /* send onFCSubscribe reply */
    memset(&h, 0, sizeof(h));
    h.type = NGX_RTMP_MSG_AMF_CMD;
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = NGX_RTMP_MSID;

    if (ngx_rtmp_send_amf(s, &h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_pause_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_pause_t     v;

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.pause, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.position, 0 },
    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "cmd: pause pause=%i position=%i",
            (ngx_int_t)v.pause, (ngx_int_t)v.position);

    return ngx_rtmp_pause
        ? ngx_rtmp_pause(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "pause: state='%i' position=%i",
                  v->pause, (ngx_int_t) v->position);

    if (v->pause) {
        return ngx_rtmp_send_status(s, "NetStream.Pause.Notify", "status",
                                    "Paused");
    } else {
        return ngx_rtmp_send_status(s, "NetStream.Unpause.Notify", "status",
                                    "Unpaused");
    }
}


static ngx_int_t
ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "disconnect");

    return ngx_rtmp_delete_stream
        ? ngx_rtmp_delete_stream(s, NULL)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_seek_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_seek_t         v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER, 
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.offset, sizeof(v.offset) },
    };

    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_seek
        ? ngx_rtmp_seek(s, &v)
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "seek: offset=%i", (ngx_int_t) v->offset);

    return (ngx_rtmp_send_user_stream_eof(s, NGX_RTMP_MSID) != NGX_OK
        || ngx_rtmp_send_user_stream_begin(s, NGX_RTMP_MSID) != NGX_OK
        || ngx_rtmp_send_status(s, "NetStream.Seek.Notify", "status",
                                "Seeking"))
        ? NGX_ERROR
        : NGX_OK;
}


static ngx_rtmp_amf_handler_t ngx_rtmp_cmd_map[] = {

    { ngx_string("connect"),            ngx_rtmp_cmd_connect_init           },
    { ngx_string("createStream"),       ngx_rtmp_cmd_create_stream_init     },
    { ngx_string("closeStream"),        ngx_rtmp_cmd_close_stream_init      },
    { ngx_string("deleteStream"),       ngx_rtmp_cmd_delete_stream_init     },

    { ngx_string("publish"),            ngx_rtmp_cmd_publish_init           },
    { ngx_string("fcpublish"),          ngx_rtmp_cmd_fcpublish_init         },
  /*{ ngx_string("fcunpublish"),        ngx_rtmp_cmd_fcunpublish_init       },*/

    { ngx_string("play"),               ngx_rtmp_cmd_play_init              },
    { ngx_string("fcsubscribe"),        ngx_rtmp_cmd_fcsubscribe_init       },
  /*{ ngx_string("fcunsubscribe"),      ngx_rtmp_cmd_fcunsubscribe_init     },*/

    { ngx_string("seek"),               ngx_rtmp_cmd_seek_init              },
    { ngx_string("pause"),              ngx_rtmp_cmd_pause_init             },
    { ngx_string("pauseraw"),           ngx_rtmp_cmd_pause_init             },
};


static ngx_int_t
ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* redirect disconnects to deleteStream 
     * to free client modules from registering
     * disconnect callback */
    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_cmd_disconnect;

    /* register AMF callbacks */
    ncalls = sizeof(ngx_rtmp_cmd_map) / sizeof(ngx_rtmp_cmd_map[0]);
    ch = ngx_array_push_n(&cmcf->amf, ncalls);
    if (h == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_cmd_map;
    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    /* set initial handlers */
    ngx_rtmp_connect = ngx_rtmp_cmd_connect;
    ngx_rtmp_create_stream = ngx_rtmp_cmd_create_stream;
    ngx_rtmp_close_stream  = ngx_rtmp_cmd_close_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_cmd_delete_stream;

    ngx_rtmp_publish = ngx_rtmp_cmd_publish;
    ngx_rtmp_fcpublish = ngx_rtmp_cmd_fcpublish;
    /*ngx_rtmp_fcunpublish = ngx_rtmp_cmd_fcunpublish;*/

    ngx_rtmp_play = ngx_rtmp_cmd_play;
    ngx_rtmp_fcsubscribe = ngx_rtmp_cmd_fcsubscribe;
    /*ngx_rtmp_fcunsubscribe = ngx_rtmp_cmd_fcunsubsrcibe;*/

    ngx_rtmp_seek = ngx_rtmp_cmd_seek;
    ngx_rtmp_pause = ngx_rtmp_cmd_pause;

    return NGX_OK;
}
