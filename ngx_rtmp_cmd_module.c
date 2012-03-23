/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp_cmd_module.h"


#define NGX_RTMP_FMS_VERSION        "FMS/3,0,1,123"
#define NGX_RTMP_CAPABILITIES       31

#define NGX_RTMP_CMD_CSID_AMF0      5


static void * ngx_rtmp_cmd_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf);


static ngx_int_t ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_play(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_close(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_cmd_default(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_command_t  ngx_rtmp_cmd_commands[] = {

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_cmd_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_cmd_postconfiguration,         /* postconfiguration */
    ngx_rtmp_cmd_create_main_conf,          /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_cmd_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_cmd_module_ctx,               /* module context */
    ngx_rtmp_cmd_commands,                  /* module directives */
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


static void *
ngx_rtmp_cmd_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_cmd_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_cmd_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

#define NGX_RTMP_CMD_INIT_ARRAY(name)                                   \
    if (ngx_array_init(&cmcf->name, cf->pool, 1, sizeof(void *))        \
            != NGX_OK)                                                  \
    {                                                                   \
        return NULL;                                                    \
    }

    NGX_RTMP_CMD_INIT_ARRAY(connect);
    NGX_RTMP_CMD_INIT_ARRAY(publish);
    NGX_RTMP_CMD_INIT_ARRAY(play);
    NGX_RTMP_CMD_INIT_ARRAY(close);

#undef NGX_RTMP_CMD_INIT_ARRAY

    return cmcf;
}


#define NGX_RTMP_CMD_I(name)                                            \
    {                                                                   \
        /* call handlers */                                             \
        ngx_rtmp_cmd_##name##_pt    *h;                                 \
        ngx_rtmp_cmd_main_conf_t   *cmcf;                               \
        ngx_uint_t                  n;                                  \
                                                                        \
        cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_cmd_module);   \
        h = cmcf->name.elts;                                            \
        for(n = 0; n < cmcf->name.nelts; ++n, ++h) {                    \
            if ((*h)                                                   

#define NGX_RTMP_CMD_F                                                  \
                        != NGX_OK) {                                    \
                return NGX_ERROR;                                       \
            }                                                           \
        }                                                               \
    }


static ngx_rtmp_amf0_handler_t ngx_rtmp_cmd_map[] = {
    { ngx_string("connect"),            ngx_rtmp_cmd_connect          },
    { ngx_string("createStream"),       ngx_rtmp_cmd_create_stream    },
    { ngx_string("publish"),            ngx_rtmp_cmd_publish          },
    { ngx_string("play"),               ngx_rtmp_cmd_play             },
    { ngx_string("close"),              ngx_rtmp_cmd_close            },
    { ngx_string("releaseStream"),      ngx_rtmp_cmd_close            },
    { ngx_string("deleteStream"),       ngx_rtmp_cmd_close            },
    { ngx_string("closeStream"),        ngx_rtmp_cmd_close            },
    { ngx_string("FCPublish"),          ngx_rtmp_cmd_default          },
    { ngx_string("FCSubscribe"),        ngx_rtmp_cmd_default          },
};


ngx_int_t
ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_uint_t                  n;
    ngx_rtmp_core_app_conf_t  **cacfp;
    size_t                      len;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;

    static struct {
        u_char                  app[1024];
        u_char                  flashver[1024];
        u_char                  swf_url[1024];
        u_char                  tc_url[1024];
        double                  acodecs;
        double                  vcodecs;
        u_char                  page_url[1024];
    } v;


    static ngx_rtmp_amf0_elt_t  in_cmd[] = {
        { NGX_RTMP_AMF0_STRING, "app",         
                                v.app,                  sizeof(v.app)       },
        { NGX_RTMP_AMF0_STRING, "flashver",    
                                v.flashver,             sizeof(v.flashver)  },
        { NGX_RTMP_AMF0_STRING, "swfUrl",      
                                v.swf_url,              sizeof(v.swf_url)   },
        { NGX_RTMP_AMF0_STRING, "tcUrl",       
                                v.tc_url,               sizeof(v.tc_url)    },
        { NGX_RTMP_AMF0_NUMBER, "audioCodecs", 
                                &v.acodecs,             sizeof(v.acodecs)   },
        { NGX_RTMP_AMF0_NUMBER, "videoCodecs", 
                                &v.vcodecs,             sizeof(v.vcodecs)   },
        { NGX_RTMP_AMF0_STRING, "pageUrl",     
                                v.page_url,             sizeof(v.page_url)  },
    };

    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,             
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,          
                                in_cmd,                 sizeof(in_cmd)      },
    };

    static ngx_rtmp_amf0_elt_t  out_obj[] = {
        { NGX_RTMP_AMF0_STRING, "fmsVer",           
                                NGX_RTMP_FMS_VERSION,   0                   },
        { NGX_RTMP_AMF0_NUMBER, "capabilities",     
                                &capabilities,          0                   },
    };

    static ngx_rtmp_amf0_elt_t  out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "level",                          
                                "status",               0                   },
        { NGX_RTMP_AMF0_STRING, "code",    
                                "NetConnection.Connect.Success", 
                                                        0                   },
        { NGX_RTMP_AMF0_STRING, "description",     
                                "Connection succeeded.",
                                                        0                   },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,       
                                "_result",              0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out_obj,                sizeof(out_obj)     },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out_inf,                sizeof(out_inf)     },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "connect: duplicate connection");
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
                "connect: application not found: '%s'", v.app);
        return NGX_ERROR;
    }

    /* call handlers */
    NGX_RTMP_CMD_I(connect) (s) NGX_RTMP_CMD_F;

    /* send all replies */
    return ngx_rtmp_send_ack_size(s, cscf->ack_window)
        || ngx_rtmp_send_bandwidth(s, cscf->ack_window, NGX_RTMP_LIMIT_DYNAMIC)
        || ngx_rtmp_send_user_stream_begin(s, 0)
        || ngx_rtmp_send_chunk_size(s, cscf->chunk_size)
        || ngx_rtmp_send_amf0(s, h, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0]))
        ? NGX_ERROR
        : NGX_DONE; 
}


ngx_int_t
ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    /* support one message stream per connection */
    static double               stream = 1; 
    static double               trans;


    static ngx_rtmp_amf0_elt_t  in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      
                                &trans,                 sizeof(trans)       },
    };

    static ngx_rtmp_amf0_elt_t  out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "_result",              0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL  , NULL,   
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &stream,                sizeof(stream)      },
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
ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    /* call handlers */
    NGX_RTMP_CMD_I(close) (s) NGX_RTMP_CMD_F;

    return NGX_OK;
}


ngx_int_t 
ngx_rtmp_cmd_close(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_cmd_disconnect(s, h, in);

    return ngx_rtmp_cmd_default(s, h, in);
}


ngx_int_t 
ngx_rtmp_cmd_default(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;

    static double                   trans;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      
                                &trans,                 sizeof(trans)       },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "_result",              0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL,   NULL,   
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_NULL,   NULL,   
                                NULL,                   0                   },
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


static ngx_int_t
ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;
    ngx_str_t                       stream;
    ngx_int_t                       type;

    static double                   trans;

    static struct {
        u_char                      name[1024];
        u_char                      type[1024];
    } v;


    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL,   0,      
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_STRING, 0,      
                                &v.name,                sizeof(v.name)      },
        { NGX_RTMP_AMF0_STRING, 0,      
                                &v.type,                sizeof(v.type)      },
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",    
                                "NetStream.Publish.Start",
                                                        0                   },
        { NGX_RTMP_AMF0_STRING, "level",                    
                                "status",               0                   },
        { NGX_RTMP_AMF0_STRING, "description",  
                                "Publish succeeded.",   0                   },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "onStatus",             0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL  , NULL,   
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out_inf,                sizeof(out_inf)     },
    };


    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "publish: name='%s' type=%s",
            v.name, v.type);

    stream.len = ngx_strlen(v.name);
    stream.data = ngx_palloc(s->connection->pool, stream.len);
    ngx_memcpy(stream.data, v.name, stream.len);

    if (ngx_strcmp(v.type, "record") == 0) {
        type = NGX_RTMP_CMD_PUBLISH_RECORD;
    } else if(ngx_strcmp(v.type, "append") == 0) {
        type = NGX_RTMP_CMD_PUBLISH_APPEND;
    } else if (ngx_strcmp(v.type, "live") == 0) {
        type = NGX_RTMP_CMD_PUBLISH_LIVE;
    } else {
        type = 0;
    }

    /* call handlers */
    NGX_RTMP_CMD_I(publish) (s, &stream, type) NGX_RTMP_CMD_F;

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_CMD_CSID_AMF0;
    sh.msid = h->msid;

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_rtmp_cmd_play(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_header_t               sh;
    ngx_str_t                       stream;

    static double                   trans;
    static int                      bfalse;

    static struct {
        u_char                      name[1024];
        double                      start;
        double                      duration;
        int                         reset;
    } v;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL,   0,      
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_STRING, 0,      
                                &v.name,                sizeof(v.name)      },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_NUMBER, 0,      
                                &v.start,               0                   },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_NUMBER, 0,      
                                &v.duration,            0                   },
        { NGX_RTMP_AMF0_OPTIONAL
        | NGX_RTMP_AMF0_BOOLEAN,0,      
                                &v.reset,               0                   }
    };

    static ngx_rtmp_amf0_elt_t      out_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",             
                                "NetStream.Play.Reset", 0                   },
        { NGX_RTMP_AMF0_STRING, "level",        
                                "status",               0                   },
        { NGX_RTMP_AMF0_STRING, "description",  
                                "Playing and resetting.",   
                                                        0                   },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "onStatus",             0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL  , NULL,   
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out_inf,                sizeof(out_inf)     },
    };

    static ngx_rtmp_amf0_elt_t      out2_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code",         
                                "NetStream.Play.Start", 0                   },
        { NGX_RTMP_AMF0_STRING, "level",        
                                "status",               0                   },
        { NGX_RTMP_AMF0_STRING, "description",  
                                "Started playing.",     0                   },
    };

    static ngx_rtmp_amf0_elt_t      out2_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "onStatus",             0                   },
        { NGX_RTMP_AMF0_NUMBER, NULL,   
                                &trans,                 0                   },
        { NGX_RTMP_AMF0_NULL  , NULL,   
                                NULL,                   0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out2_inf,               sizeof(out2_inf)    },
    };

    static ngx_rtmp_amf0_elt_t      out3_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "|RtmpSampleAccess",    0                   },
        { NGX_RTMP_AMF0_BOOLEAN,NULL,   
                                &bfalse,                0                   },
        { NGX_RTMP_AMF0_BOOLEAN,NULL,   
                                &bfalse,                0                   },
    };

    static ngx_rtmp_amf0_elt_t      out4_inf[] = {
        { NGX_RTMP_AMF0_STRING, "code", 
                                "NetStream.Data.Start", 0                   },
    };

    static ngx_rtmp_amf0_elt_t      out4_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   
                                "onStatus",             0                   },
        { NGX_RTMP_AMF0_OBJECT, NULL,   
                                out4_inf,               sizeof(out4_inf)    },
    };


    ngx_memzero(&v, sizeof(v));

    /* parse input */
    if (ngx_rtmp_receive_amf0(s, in, in_elts, 
                sizeof(in_elts) / sizeof(in_elts[0]))) 
    {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "play: name='%s' start=%uD duration=%uD reset=%d",
            v.name, (uint32_t)v.start, (uint32_t)v.duration, v.reset);

    stream.len = ngx_strlen(v.name);
    stream.data = ngx_palloc(s->connection->pool, stream.len);
    ngx_memcpy(stream.data, v.name, stream.len);

    /* call handlers */
    NGX_RTMP_CMD_I(play) (s, &stream, v.start,
            v.duration, v.reset) NGX_RTMP_CMD_F;

    /* start stream */
    if (ngx_rtmp_send_user_stream_begin(s, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /* send onStatus reply */
    memset(&sh, 0, sizeof(sh));
    sh.type = NGX_RTMP_MSG_AMF0_CMD;
    sh.csid = NGX_RTMP_CMD_CSID_AMF0;
    sh.msid = h->msid;

    if (ngx_rtmp_send_amf0(s, &sh, out_elts,
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send sample access meta message FIXME */
    if (ngx_rtmp_send_amf0(s, &sh, out2_elts,
                sizeof(out2_elts) / sizeof(out2_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* send data start meta message */
    sh.type = NGX_RTMP_MSG_AMF0_META;
    if (ngx_rtmp_send_amf0(s, &sh, out3_elts,
                sizeof(out3_elts) / sizeof(out3_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_rtmp_send_amf0(s, &sh, out4_elts,
                sizeof(out4_elts) / sizeof(out4_elts[0])) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


#if 0
static ngx_int_t
ngx_rtmp_live_set_data_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_connection_t               *c;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_amf0_ctx_t             act;
    ngx_rtmp_header_t               sh;
    ngx_rtmp_core_srv_conf_t       *cscf;

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING,   NULL,   "@setDataFrame",                  0 },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "live: data_frame");

    /* TODO: allow sending more meta packages to change live content */

    if (ctx->data_frame) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, 
                "duplicate data_frame");
        return NGX_OK;
    }

    /* create full metadata chain for output */
    memset(&act, 0, sizeof(act));
    act.cscf = cscf;
    act.alloc = ngx_rtmp_alloc_shared_buf;
    act.log = c->log;

    if (ngx_rtmp_amf0_write(&act, out_elts, 
                sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK) 
    {
        if (act.first) {
            ngx_rtmp_free_shared_bufs(cscf, act.first);
        }
        return NGX_ERROR;
    }

    if (act.first == NULL) {
        return NGX_OK;
    }

    ctx->data_frame = act.first;

    if (ngx_rtmp_append_shared_bufs(cscf, ctx->data_frame, in) == NULL) {
        if (ctx->data_frame) {
            ngx_rtmp_free_shared_bufs(cscf, ctx->data_frame);
        }
        return NGX_ERROR;
    }

    memset(&sh, 0, sizeof(sh));
    sh.csid = NGX_RTMP_LIVE_CSID_AMF0;
    sh.msid = 1;
    sh.type = NGX_RTMP_MSG_AMF0_META;

    ngx_rtmp_prepare_message(s, &sh, NULL, ctx->data_frame);

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_live_stream_length(ngx_rtmp_session_t *s, 
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               sh;

    static double                   trans;
    static double                   length;

    static ngx_rtmp_amf0_elt_t      in_elts[] = {
        { NGX_RTMP_AMF0_NUMBER, 0,      &trans,     sizeof(trans)             },
    };

    static ngx_rtmp_amf0_elt_t      out_elts[] = {
        { NGX_RTMP_AMF0_STRING, NULL,   "_result",                          0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &trans,                             0 },
        { NGX_RTMP_AMF0_NUMBER, NULL,   &length,                            0 },
    };

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

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
#endif


static ngx_int_t
ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf0_handler_t            *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_cmd_disconnect;

    /* register AMF0 callbacks */
    ncalls = sizeof(ngx_rtmp_cmd_map) / sizeof(ngx_rtmp_cmd_map[0]);
    ch = ngx_array_push_n(&cmcf->amf0, ncalls);
    if (h == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_cmd_map;
    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    return NGX_OK;
}
