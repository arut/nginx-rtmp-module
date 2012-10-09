/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <nginx.h>
#include <ngx_http.h>

#include "ngx_rtmp.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_record_module.h"


static ngx_int_t ngx_rtmp_control_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_control_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_control_merge_loc_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_CONTROL_ALL        0xff
#define NGX_RTMP_CONTROL_RECORD     0x01


typedef struct {
    ngx_uint_t                      control;
} ngx_rtmp_control_loc_conf_t;


static ngx_conf_bitmask_t           ngx_rtmp_control_masks[] = {
    { ngx_string("all"),            NGX_RTMP_CONTROL_ALL        },
    { ngx_string("record"),         NGX_RTMP_CONTROL_RECORD     },
    { ngx_null_string,              0 }
}; 


static ngx_command_t  ngx_rtmp_control_commands[] = {

    { ngx_string("rtmp_control"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_control_loc_conf_t, control),
      ngx_rtmp_control_masks },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_control_module_ctx = {
	NULL,                               /* preconfiguration */
	ngx_rtmp_control_postconfiguration, /* postconfiguration */

	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */

	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */

	ngx_rtmp_control_create_loc_conf,   /* create location configuration */
	ngx_rtmp_control_merge_loc_conf,    /* merge location configuration */
};


ngx_module_t  ngx_rtmp_control_module = {
	NGX_MODULE_V1,
	&ngx_rtmp_control_module_ctx,       /* module context */
	ngx_rtmp_control_commands,          /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};


/* /record arguments:
 *      srv  - server index (optional)
 *      app  - application name
 *      name - stream name
 *      rec  - recorder name
 */


static ngx_int_t
ngx_rtmp_control_record(ngx_http_request_t *r, ngx_str_t *method)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t      **pcscf, *cscf;
    ngx_rtmp_core_app_conf_t      **pcacf, *cacf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_stream_t         *ls;
    ngx_rtmp_live_ctx_t            *lctx;
    ngx_rtmp_session_t             *s;
    ngx_chain_t                     cl;
    ngx_uint_t                      sn, rn, n;
    ngx_str_t                       srv, app, rec, name, path;
    ngx_str_t                       msg;
    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    size_t                          len;

    sn = 0;
    if (ngx_http_arg(r, (u_char *) "srv", sizeof("srv") - 1, &srv) == NGX_OK) {
        sn = ngx_atoi(srv.data, srv.len);
    }

    if (ngx_http_arg(r, (u_char *) "app", sizeof("app") - 1, &app) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "rtmp_control: app not specified");
        ngx_str_set(&msg, "Application not specified");
        goto error;
    }

    ngx_memzero(&rec, sizeof(rec));
    ngx_http_arg(r, (u_char *) "rec", sizeof("rec") - 1, &rec);

    ngx_memzero(&name, sizeof(name));
    ngx_http_arg(r, (u_char *) "name", sizeof("name") - 1, &name);

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        ngx_str_set(&msg, "Missing main RTMP conf");
        goto error;
    }

    /* find server */
    if (sn >= cmcf->servers.nelts) {
        ngx_str_set(&msg, "Server index out of range");
        goto error;
    }

    pcscf = cmcf->servers.elts;
    pcscf += sn;
    cscf = *pcscf;

    /* find application */
    pcacf = cscf->applications.elts;
    cacf = NULL;

    for (n = 0; n < cscf->applications.nelts; ++n, ++pcacf) {
        if ((*pcacf)->name.len == app.len &&
            ngx_strncmp((*pcacf)->name.data, app.data, app.len) == 0)
        {
            cacf = *pcacf;
            break;
        }
    }

    if (cacf == NULL) {
        ngx_str_set(&msg, "Application not found");
        goto error;
    }

    lacf = cacf->app_conf[ngx_rtmp_live_module.ctx_index];
    racf = cacf->app_conf[ngx_rtmp_record_module.ctx_index];

    /* find live stream by name */
    for (ls = lacf->streams[ngx_hash_key(name.data, name.len) % lacf->nbuckets];
         ls; ls = ls->next) 
    {
        len = ngx_strlen(ls->name);

        if (name.len == len && ngx_strncmp(name.data, ls->name, name.len)
                                == 0)
        {
            break;
        }
    }

    if (ls == NULL) {
        ngx_str_set(&msg, "Live stream not found");
        goto error;
    }

    /* find publisher context */
    for (lctx = ls->ctx; lctx; lctx = lctx->next) {
        if (lctx->flags & NGX_RTMP_LIVE_PUBLISHING) {
            break;
        }
    }

    if (lctx == NULL) {
        ngx_str_set(&msg, "No publisher");
        goto error;
    }

    s = lctx->session;

    /* find recorder */
    rn = ngx_rtmp_record_find(racf, &rec);
    if (rn == NGX_CONF_UNSET_UINT) {
        ngx_str_set(&msg, "Recorder not found");
        goto error;
    }

    ngx_memzero(&path, sizeof(path));

    if (method->len == sizeof("start") - 1 &&
        ngx_strncmp(method->data, "start", method->len) == 0)
    {
        rc = ngx_rtmp_record_open(s, rn, &path);

    } else if (method->len == sizeof("stop") - 1 &&
               ngx_strncmp(method->data, "stop", method->len) == 0)
    {
        rc = ngx_rtmp_record_close(s, rn, &path);

    } else {
        ngx_str_set(&msg, "Undefined method");
        goto error;
    }

    if (rc == NGX_ERROR) {
        ngx_str_set(&msg, "Recorder error");
        goto error;
    }

    if (rc == NGX_AGAIN) {
        /* already opened/closed */
        ngx_str_null(&path);
        r->header_only = 1;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = path.len;

    b = ngx_create_temp_buf(r->pool, path.len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    b->last = ngx_cpymem(b->pos, path.data, path.len);
    b->last_buf = 1;
    
    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    r->headers_out.status = NGX_HTTP_BAD_REQUEST;
    r->headers_out.content_length_n = msg.len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    b->start = b->pos = msg.data;
    b->end = b->last = msg.data + msg.len;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);
}


static ngx_int_t
ngx_rtmp_control_handler(ngx_http_request_t *r)
{
    ngx_rtmp_control_loc_conf_t    *llcf;
    ngx_str_t                       section, method;
    u_char                         *p;
    ngx_uint_t                      n;

    llcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_control_module);
    if (llcf->control == 0) {
        return NGX_DECLINED;
    }

    /* uri format: .../section/method?args */
    ngx_memzero(&section, sizeof(section));
    ngx_memzero(&method, sizeof(method));

    for (n = r->uri.len; n; --n) {
        p = &r->uri.data[n - 1];

        if (*p != '/') {
            continue;
        }

        if (method.data) {
            section.data = p + 1;
            section.len  = method.data - section.data - 1;
            break;
        }

        method.data = p + 1;
        method.len  = r->uri.data + r->uri.len - method.data;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
                   "rtmp_control: section='%V' method='%V'",
                   &section, &method);


#define NGX_RTMP_CONTROL_SECTION(flag, secname)                             \
    if (llcf->control & NGX_RTMP_CONTROL_##flag &&                          \
        section.len == sizeof(#secname) - 1 &&                              \
        ngx_strncmp(section.data, #secname, sizeof(#secname) - 1) == 0)     \
    {                                                                       \
        return ngx_rtmp_control_##secname(r, &method);                      \
    }

    NGX_RTMP_CONTROL_SECTION(RECORD, record);

#undef NGX_RTMP_CONTROL_SECTION


    return NGX_DECLINED;
}


static void *
ngx_rtmp_control_create_loc_conf(ngx_conf_t *cf)
{
    ngx_rtmp_control_loc_conf_t       *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_control_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->control = 0;

    return conf;
}


static char *
ngx_rtmp_control_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_control_loc_conf_t       *prev = parent;
    ngx_rtmp_control_loc_conf_t       *conf = child;

    ngx_conf_merge_bitmask_value(conf->control, prev->control, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_control_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt            *h;
    ngx_http_core_main_conf_t      *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_rtmp_control_handler;

    return NGX_OK;
} 
