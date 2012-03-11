/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_AMF0_H_INCLUDED_
#define _NGX_RTMP_AMF0_H_INCLUDED_

#define NGX_RTMP_AMF0_NUMBER    0x00
#define NGX_RTMP_AMF0_BOOLEAN   0x01
#define NGX_RTMP_AMF0_STRING    0x02

#define NGX_RTMP_AMF0_OBJECT    0x03
#define NGX_RTMP_AMF0_NULL      0x05
#define NGX_RTMP_AMF0_ARRAY     0x08
#define NGX_RTMP_AMF0_END       0x09

#include <ngx_config.h>
#include <ngx_core.h>


/*TODO: char -> u_char */

typedef struct {
    ngx_int_t               type;
    char                   *name;
    void                   *data;
    size_t                  len;
} ngx_rtmp_amf0_elt_t;


typedef ngx_chain_t * (*ngx_rtmp_amf0_alloc_pt)

typedef struct {
    ngx_chain_t            *link, *first;
    ngx_rtmp_amf0_alloc_pt  alloc;
    void                   *arg;
    ngx_log_t              *log;
} ngx_rtmp_amf0_ctx_t;


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

ngx_rtmp_amf0_elt_t props[] = {
    { NGX_RTMP_AMF0_STRING,     "app",      vals.app,        sizeof(vals.app)         },
    { NGX_RTMP_AMF0_STRING,     "flashver", vals.flashver,   sizeof(vals.flashver)    }
};

ngx_rtmp_amf0_elt_t list[] = {
    { NGX_RTMP_AMF0_STRING,     0,          vals.v1,         sizeof(vals.v1)          },
    { NGX_RTMP_AMF0_BOOLEAN,    0,         &vals.locked,     sizeof(vals.locked)      }
};

ngx_rtmp_amf0_elt elts[] = {
    { NGX_RTMP_AMF0_STRING,     0           vals.name,       sizeof(vals.name)        },
    { NGX_RTMP_AMF0_NUMBER,     0          &vals.trans_id,   sizeof(vals.trans_id)    },
    { NGX_RTMP_AMF0_OBJECT,     0,          props,           sizeof(props)            },
    { NGX_RTMP_AMF0_ARRAY,      0,          list,            sizeof(list)             },
    { NGX_RTMP_AMF0_NULL }
};


Reading:
-------

memset(&vals, 0, sizeof(vals));
ngx_rtmp_amf0_read(l, elts, sizeof(elts));


Writing:
-------

ngx_rtmp_amf0_write(l, free, elts, sizeof(elts));

*/

/* reading AMF0 */
ngx_int_t ngx_rtmp_amf0_read(ngx_rtmp_amf0_ctx_t *ctx,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts);

/* writing AMF0 */
ngx_int_t ngx_rtmp_amf0_write(ngx_rtmp_amf0_ctx_t *ctx,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts);


#endif /* _NGX_RTMP_AMF0_H_INCLUDED_ */

