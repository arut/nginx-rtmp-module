/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_AMF_H_INCLUDED_
#define _NGX_RTMP_AMF_H_INCLUDED_

#define NGX_RTMP_AMF_NUMBER             0x00
#define NGX_RTMP_AMF_BOOLEAN            0x01
#define NGX_RTMP_AMF_STRING             0x02

#define NGX_RTMP_AMF_OBJECT             0x03
#define NGX_RTMP_AMF_NULL               0x05
#define NGX_RTMP_AMF_ARRAY_NULL         0x06
#define NGX_RTMP_AMF_MIXED_ARRAY        0x08
#define NGX_RTMP_AMF_END                0x09

#define NGX_RTMP_AMF_ARRAY              0x0a

#define NGX_RTMP_AMF_OPTIONAL           0x80

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_int_t                           type;
    ngx_str_t                           name;
    void                               *data;
    size_t                              len;
} ngx_rtmp_amf_elt_t;


struct ngx_rtmp_core_srv_conf_s;

typedef ngx_chain_t * (*ngx_rtmp_amf_alloc_pt)(struct ngx_rtmp_core_srv_conf_s
        *cscf);

typedef struct {
    ngx_chain_t                        *link, *first;
    ngx_rtmp_amf_alloc_pt               alloc;
    struct ngx_rtmp_core_srv_conf_s    *cscf;
    ngx_log_t                          *log;
} ngx_rtmp_amf_ctx_t;


/*
 *
 * Examples:

struct {
   char    name[32];
   double  trans_id;
   char    app[32];
   char    flashver[32];
   char    v1[8];
   int     locked;
} vals;

ngx_rtmp_amf_elt_t props[] = {
    { NGX_RTMP_AMF_STRING,     "app",      vals.app,        sizeof(vals.app)         },
    { NGX_RTMP_AMF_STRING,     "flashver", vals.flashver,   sizeof(vals.flashver)    }
};

ngx_rtmp_amf_elt_t list[] = {
    { NGX_RTMP_AMF_STRING,     0,          vals.v1,         sizeof(vals.v1)          },
    { NGX_RTMP_AMF_BOOLEAN,    0,         &vals.locked,     sizeof(vals.locked)      }
};

ngx_rtmp_amf_elt elts[] = {
    { NGX_RTMP_AMF_STRING,     0           vals.name,       sizeof(vals.name)        },
    { NGX_RTMP_AMF_NUMBER,     0          &vals.trans_id,   sizeof(vals.trans_id)    },
    { NGX_RTMP_AMF_OBJECT,     0,          props,           sizeof(props)            },
    { NGX_RTMP_AMF_ARRAY,      0,          list,            sizeof(list)             },
    { NGX_RTMP_AMF_NULL }
};


Reading:
-------

memset(&vals, 0, sizeof(vals));
ngx_rtmp_amf_read(l, elts, sizeof(elts));


Writing:
-------

ngx_rtmp_amf_write(l, free, elts, sizeof(elts));

*/

/* reading AMF */
ngx_int_t ngx_rtmp_amf_read(ngx_rtmp_amf_ctx_t *ctx,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);

/* writing AMF */
ngx_int_t ngx_rtmp_amf_write(ngx_rtmp_amf_ctx_t *ctx,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);


#endif /* _NGX_RTMP_AMF_H_INCLUDED_ */

