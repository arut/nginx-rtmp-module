
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_record_module.h"


static char *ngx_rtmp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_rtmp_control_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_control_merge_loc_conf(ngx_conf_t *cf,
       void *parent, void *child);


typedef struct {
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_core_app_conf_t       *cacf;
} ngx_rtmp_control_core_t;


typedef struct {
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_stream_t         *ls;
} ngx_rtmp_control_live_t;


#define NGX_RTMP_CONTROL_ALL        0xff
#define NGX_RTMP_CONTROL_RECORD     0x01
#define NGX_RTMP_CONTROL_DROP       0x02


enum {
    NGX_RTMP_CONTROL_DROP_PUBLISHER,
    NGX_RTMP_CONTROL_DROP_SUBSCRIBER,
    NGX_RTMP_CONTROL_DROP_CLIENT,
};


typedef struct {
    ngx_uint_t                      method;
    ngx_str_t                       addr;
    ngx_uint_t                      ndropped;
} ngx_rtmp_control_drop_t;


typedef struct {
    ngx_uint_t                      control;
} ngx_rtmp_control_loc_conf_t;


static ngx_conf_bitmask_t           ngx_rtmp_control_masks[] = {
    { ngx_string("all"),            NGX_RTMP_CONTROL_ALL       },
    { ngx_string("record"),         NGX_RTMP_CONTROL_RECORD    },
    { ngx_string("drop"),           NGX_RTMP_CONTROL_DROP      },
    { ngx_null_string,              0                          }
};


static ngx_command_t  ngx_rtmp_control_commands[] = {

    { ngx_string("rtmp_control"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_rtmp_control,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_control_loc_conf_t, control),
      ngx_rtmp_control_masks },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_control_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

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


static ngx_int_t
ngx_rtmp_control_output_error(ngx_http_request_t *r, const char *msg)
{
    size_t          len;
    ngx_buf_t      *b;
    ngx_chain_t     cl;

    len = ngx_strlen(msg);

    r->headers_out.status = NGX_HTTP_BAD_REQUEST;
    r->headers_out.content_length_n = len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    b->start = b->pos = (u_char *) msg;
    b->end = b->last = (u_char *) msg + len;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);
}


static const char *
ngx_rtmp_control_parse_core(ngx_http_request_t *r,
                            ngx_rtmp_control_core_t *core)
{
    ngx_str_t                   srv, app;
    ngx_uint_t                  sn, n;
    ngx_rtmp_core_srv_conf_t  **pcscf;
    ngx_rtmp_core_app_conf_t  **pcacf;


    core->cmcf = ngx_rtmp_core_main_conf;
    if (core->cmcf == NULL) {
        return "Missing main RTMP conf";
    }

    /* find server */
    sn = 0;

    if (ngx_http_arg(r, (u_char *) "srv", sizeof("srv") - 1, &srv) == NGX_OK) {
        sn = ngx_atoi(srv.data, srv.len);
    }

    if (sn >= core->cmcf->servers.nelts) {
        return "Server index out of range";
    }

    pcscf  = core->cmcf->servers.elts;
    pcscf += sn;

    core->cscf = *pcscf;

    /* find application */
    if (ngx_http_arg(r, (u_char *) "app", sizeof("app") - 1, &app) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "rtmp_control: app not specified");
        return "Application not specified";
    }

    core->cacf = NULL;

    pcacf = core->cscf->applications.elts;

    for (n = 0; n < core->cscf->applications.nelts; ++n, ++pcacf) {
        if ((*pcacf)->name.len == app.len &&
            ngx_strncmp((*pcacf)->name.data, app.data, app.len) == 0)
        {
            core->cacf = *pcacf;
            break;
        }
    }

    if (core->cacf == NULL) {
        return "Application not found";
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_parse_live(ngx_http_request_t *r,
                            ngx_rtmp_control_core_t *core,
                            ngx_rtmp_control_live_t *live)
{
    ngx_str_t   name;
    size_t      len;

    ngx_memzero(&name, sizeof(name));
    ngx_http_arg(r, (u_char *) "name", sizeof("name") - 1, &name);

    if (name.len == 0) {
        return NGX_CONF_OK;
    }

    live->lacf = core->cacf->app_conf[ngx_rtmp_live_module.ctx_index];

    /* find live stream by name */
    for (live->ls = live->lacf->streams[ngx_hash_key(name.data, name.len) %
                                        live->lacf->nbuckets];
         live->ls; live->ls = live->ls->next)
    {
        len = ngx_strlen(live->ls->name);

        if (name.len == len && ngx_strncmp(name.data, live->ls->name, name.len)
                                == 0)
        {
            break;
        }
    }

    if (live->ls == NULL) {
        return "Live stream not found";
    }

    return NGX_CONF_OK;
}


/* /record arguments:
 *      srv  - server index (optional)
 *      app  - application name
 *      name - stream name
 *      rec  - recorder name
 */


static ngx_int_t
ngx_rtmp_control_record(ngx_http_request_t *r, ngx_str_t *method)
{
    ngx_rtmp_control_core_t         core;
    ngx_rtmp_control_live_t         live;
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_live_ctx_t            *lctx;
    ngx_rtmp_session_t             *s;
    ngx_chain_t                     cl;
    ngx_uint_t                      rn;
    ngx_str_t                       rec, path;
    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    const char                     *msg;

    msg = ngx_rtmp_control_parse_core(r, &core);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    ngx_memzero(&live, sizeof(live));
    msg = ngx_rtmp_control_parse_live(r, &core, &live);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    /* find publisher context */
    for (lctx = live.ls->ctx; lctx; lctx = lctx->next) {
        if (lctx->publishing) {
            break;
        }
    }

    if (lctx == NULL) {
        msg = "No publisher";
        goto error;
    }

    s = lctx->session;

    /* find recorder */
    ngx_memzero(&rec, sizeof(rec));
    ngx_http_arg(r, (u_char *) "rec", sizeof("rec") - 1, &rec);

    racf = core.cacf->app_conf[ngx_rtmp_record_module.ctx_index];

    rn = ngx_rtmp_record_find(racf, &rec);
    if (rn == NGX_CONF_UNSET_UINT) {
        msg = "Recorder not found";
        goto error;
    }

    /* call the method */
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
        msg = "Undefined method";
        goto error;
    }

    if (rc == NGX_ERROR) {
        msg = "Recorder error";
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
    return ngx_rtmp_control_output_error(r, msg);
}


static const char *
ngx_rtmp_control_drop_session(ngx_http_request_t *r,
                              ngx_rtmp_control_drop_t *drop,
                              ngx_rtmp_live_ctx_t *lctx)
{
    ngx_rtmp_session_t *s;
    ngx_str_t          *paddr;

    s = lctx->session;

    if (s == NULL || s->connection == NULL)
    {
        return NGX_CONF_OK;
    }

    if (drop->addr.len) {
        paddr = &s->connection->addr_text;
        if (paddr->len != drop->addr.len ||
            ngx_strncmp(paddr->data, drop->addr.data, drop->addr.len))
        {
            return NGX_CONF_OK;
        }
    }

    switch (drop->method) {
        case NGX_RTMP_CONTROL_DROP_PUBLISHER:
            if (!lctx->publishing) {
                return NGX_CONF_OK;
            }

        case NGX_RTMP_CONTROL_DROP_SUBSCRIBER:
            if (lctx->publishing) {
                return NGX_CONF_OK;
            }

        case NGX_RTMP_CONTROL_DROP_CLIENT:
            break;
    }

    ngx_rtmp_finalize_session(s);
    ++drop->ndropped;

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_drop_stream(ngx_http_request_t *r,
                             ngx_rtmp_control_drop_t *drop,
                             ngx_rtmp_live_stream_t *ls)
{
    ngx_rtmp_live_ctx_t    *lctx;
    const char             *s;

    for (lctx = ls->ctx; lctx; lctx = lctx->next) {
        s = ngx_rtmp_control_drop_session(r, drop, lctx);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_drop_app(ngx_http_request_t *r,
                          ngx_rtmp_control_drop_t *drop,
                          ngx_rtmp_core_app_conf_t *cacf)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_stream_t     *ls;
    ngx_str_t                   name;
    const char                 *s;
    size_t                      len;
    ngx_uint_t                  n;

    ngx_memzero(&name, sizeof(name));
    ngx_http_arg(r, (u_char *) "name", sizeof("name") - 1, &name);

    lacf = cacf->app_conf[ngx_rtmp_live_module.ctx_index];

    if (name.len == 0) {
        for (n = 0; n < (ngx_uint_t) lacf->nbuckets; ++n) {
            for (ls = lacf->streams[n]; ls; ls = ls->next) 
            {
                s = ngx_rtmp_control_drop_stream(r, drop, ls);
                if (s != NGX_CONF_OK) {
                    return s;
                }
            }
        }

        return NGX_CONF_OK;
    }

    for (ls = lacf->streams[ngx_hash_key(name.data, name.len) % lacf->nbuckets];
         ls; ls = ls->next) 
    {
        len = ngx_strlen(ls->name);
        if (name.len != len || ngx_strncmp(name.data, ls->name, name.len)) {
            continue;
        }

        s = ngx_rtmp_control_drop_stream(r, drop, ls);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_drop_srv(ngx_http_request_t *r,
                          ngx_rtmp_control_drop_t *drop,
                          ngx_rtmp_core_srv_conf_t *cscf)
{
    ngx_rtmp_core_app_conf_t  **pcacf;
    ngx_str_t                   app;
    ngx_uint_t                  n;
    const char                 *s;

    ngx_memzero(&app, sizeof(app));
    ngx_http_arg(r, (u_char *) "app", sizeof("app") - 1, &app);

    pcacf = cscf->applications.elts;

    for (n = 0; n < cscf->applications.nelts; ++n, ++pcacf) {
        if (app.len && ((*pcacf)->name.len != app.len ||
                        ngx_strncmp((*pcacf)->name.data, app.data, app.len)))
        {
            continue;
        }

        s = ngx_rtmp_control_drop_app(r, drop, *pcacf);
        if (s != NGX_CONF_OK) {
            return s;
        }
    }

    return NGX_CONF_OK;
}


static const char *
ngx_rtmp_control_drop_main(ngx_http_request_t *r,
                           ngx_rtmp_control_drop_t *drop,
                           ngx_rtmp_core_main_conf_t *cmcf)
{
    ngx_rtmp_core_srv_conf_t  **pcscf;
    ngx_str_t                   srv;
    ngx_uint_t                  sn;

    sn = 0;
    if (ngx_http_arg(r, (u_char *) "srv", sizeof("srv") - 1, &srv) == NGX_OK) {
        sn = ngx_atoi(srv.data, srv.len);
    }

    if (sn >= cmcf->servers.nelts) {
        return "Server index out of range";
    }

    pcscf  = cmcf->servers.elts;
    pcscf += sn;

    return ngx_rtmp_control_drop_srv(r, drop, *pcscf);
}


static ngx_int_t
ngx_rtmp_control_drop(ngx_http_request_t *r, ngx_str_t *method)
{
    ngx_rtmp_control_drop_t         drop;
    size_t                          len;
    u_char                         *p;
    ngx_buf_t                      *b;
    ngx_chain_t                     cl;
    const char                     *msg;

    if (ngx_rtmp_core_main_conf == NULL) {
        msg = "Empty main conf";
        goto error;
    }

    ngx_memzero(&drop, sizeof(drop));

    if (method->len == sizeof("publisher") - 1 &&
        ngx_memcmp(method->data, "publisher", method->len) == 0)
    {
        drop.method = NGX_RTMP_CONTROL_DROP_PUBLISHER;

    } else if (method->len == sizeof("subscriber") - 1 &&
               ngx_memcmp(method->data, "subscriber", method->len) == 0)
    {
        drop.method = NGX_RTMP_CONTROL_DROP_SUBSCRIBER;

    } else if (method->len == sizeof("client") - 1 &&
               ngx_memcmp(method->data, "client", method->len) == 0)
    {
        drop.method = NGX_RTMP_CONTROL_DROP_CLIENT;

    } else {
        msg = "Undefined method";
        goto error;
    }

    ngx_http_arg(r, (u_char *) "addr", sizeof("addr") - 1, &drop.addr);

    msg = ngx_rtmp_control_drop_main(r, &drop, ngx_rtmp_core_main_conf);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    /* output ndropped */

    len = NGX_INT_T_LEN;

    p = ngx_palloc(r->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = (size_t) (ngx_snprintf(p, len, "%ui", drop.ndropped) - p);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->start = b->pos = p;
    b->end = b->last = p + len;
    b->temporary = 1;
    b->last_buf = 1;

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    return ngx_rtmp_control_output_error(r, msg);
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
    NGX_RTMP_CONTROL_SECTION(DROP, drop);

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


static char *
ngx_rtmp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rtmp_control_handler;

    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}
