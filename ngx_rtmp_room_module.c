/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_room_module.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;


static ngx_int_t ngx_rtmp_room_init_process(ngx_cycle_t *cycle);
static char *ngx_rtmp_room_persistent(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void * ngx_rtmp_room_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_room_merge_app_conf(ngx_conf_t *cf, void *parent,
       void *child);
static ngx_int_t ngx_rtmp_room_postconfiguration(ngx_conf_t *cf);
static void ngx_rtmp_room_create_persistent(ngx_rtmp_room_app_conf_t *racf,
       ngx_str_t *appname);
static ngx_rtmp_room_t ** ngx_rtmp_room_get_room(ngx_rtmp_room_app_conf_t *racf,
       ngx_str_t *name);
static ngx_rtmp_room_t * ngx_rtmp_room_create(ngx_rtmp_room_app_conf_t *racf,
       ngx_str_t *name);


/* chain handler stubs */

static ngx_int_t
ngx_rtmp_room_create_room(ngx_rtmp_room_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_room_delete_room(ngx_rtmp_room_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_room_join_room(ngx_rtmp_room_t *r, ngx_rtmp_session_t *s)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_room_leave_room(ngx_rtmp_room_t *r, ngx_rtmp_session_t *s)
{
    return NGX_OK;
}


ngx_rtmp_create_room_pt     ngx_rtmp_create_room = ngx_rtmp_room_create_room;
ngx_rtmp_delete_room_pt     ngx_rtmp_delete_room = ngx_rtmp_room_delete_room;
ngx_rtmp_join_room_pt       ngx_rtmp_join_room = ngx_rtmp_room_join_room;
ngx_rtmp_leave_room_pt      ngx_rtmp_leave_room = ngx_rtmp_room_leave_room;


static ngx_command_t  ngx_rtmp_room_commands[] = {

    { ngx_string("rooms"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_room_app_conf_t, active),
      NULL },

    { ngx_string("persistent"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_room_persistent,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("room_buckets"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_room_app_conf_t, nbuckets),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_room_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_room_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_room_create_app_conf,          /* create app configuration */
    ngx_rtmp_room_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_room_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_room_module_ctx,              /* module context */
    ngx_rtmp_room_commands,                 /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_room_init_process,             /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_room_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_room_app_conf_t      *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_room_app_conf_t));
    if (racf == NULL) {
        return NULL;
    }

    racf->active = NGX_CONF_UNSET;
    racf->nbuckets = NGX_CONF_UNSET;
    racf->log = &cf->cycle->new_log;

    if (ngx_array_init(&racf->persistent, cf->pool, 1, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return racf;
}


static char *
ngx_rtmp_room_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_room_app_conf_t *prev = parent;
    ngx_rtmp_room_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->active, prev->active, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);

    conf->rooms = ngx_pcalloc(cf->pool, sizeof(void *) * conf->nbuckets);
    if (conf->rooms == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->ctx = cf->ctx;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_room_init_process(ngx_cycle_t *cycle)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_rtmp_core_srv_conf_t  **cscf;
    ngx_rtmp_core_app_conf_t  **cacf;
    ngx_rtmp_room_app_conf_t   *racf;
    ngx_uint_t                  n, m;

    cmcf = ngx_rtmp_core_main_conf;

    cscf = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; ++n, ++cscf) {
        cacf = (*cscf)->applications.elts;
        for (m = 0; m < (*cscf)->applications.nelts; ++m, ++cacf) {
            racf = (*cacf)->app_conf[ngx_rtmp_room_module.ctx_index];
            if (racf && racf->persistent.nelts) {
                ngx_rtmp_room_create_persistent(racf, &(*cacf)->name);
            }
        }
    }

    return NGX_OK;
}


static char *
ngx_rtmp_room_persistent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_room_app_conf_t   *racf = conf;
    ngx_str_t                  *value, *dst;

    value = cf->args->elts;

    dst = ngx_array_push(&racf->persistent);
    if (dst == NULL) {
        return NGX_CONF_ERROR;
    }
    *dst = value[1];

    return NGX_CONF_OK;
}


static void
ngx_rtmp_room_create_persistent(ngx_rtmp_room_app_conf_t *racf,
                                ngx_str_t *appname)
{
    ngx_str_t                  *value;
    ngx_rtmp_room_t           **rr, *r;
    size_t                      n;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                   "room: create %uz persistent rooms in application '%V'",
                   racf->persistent.nelts, appname);

    value = racf->persistent.elts;
    for (n = 0; n < racf->persistent.nelts; ++n, ++value) {

        rr = ngx_rtmp_room_get_room(racf, value);
        if (rr == NULL || *rr) {
            ngx_log_error(NGX_LOG_ERR, racf->log, 0,
                          "room: error creating persistent '%V'", value);
        }

        r = ngx_rtmp_room_create(racf, value);
        if (r == NULL) {
            continue;
        }

        *rr = r;
        r->persistent = 1;
    }
}


static ngx_rtmp_room_t **
ngx_rtmp_room_get_room(ngx_rtmp_room_app_conf_t *racf, ngx_str_t *name)
{
    ngx_rtmp_room_t   **rr, *r;

    rr = &racf->rooms[ngx_hash_key(name->data, name->len) % racf->nbuckets];

    for (; *rr; rr = &(*rr)->next) {
        r = *rr;

        if (r->name.len == name->len &&
            ngx_strncmp(r->name.data, name->data, name->len) == 0)
        {
            break;
        }
    }

    return rr;
}


static ngx_rtmp_room_t *
ngx_rtmp_room_create(ngx_rtmp_room_app_conf_t *racf, ngx_str_t *name)
{
    ngx_pool_t                 *pool;
    ngx_rtmp_room_t            *r;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                   "room: create room '%V'", name);

    pool = ngx_create_pool(4096, racf->log);
    if (pool == NULL) {
        return NULL;
    }

    r = ngx_pcalloc(pool, sizeof(ngx_rtmp_room_t));
    if (r == NULL) {
        goto error;
    }

    r->pool = pool;
    r->epoch = ngx_current_msec;

    r->ctx = ngx_pcalloc(pool, sizeof(void *) * ngx_rtmp_max_module);
    if (r->ctx == NULL) {
        goto error;
    }

    r->main_conf = racf->ctx->main_conf;
    r->srv_conf = racf->ctx->srv_conf;
    r->app_conf = racf->ctx->app_conf;

    r->name.len = name->len;
    r->name.data = ngx_palloc(pool, name->len);
    if (r->name.data == NULL) {
        goto error;
    }
    ngx_memcpy(r->name.data, name->data, name->len);

    if (ngx_rtmp_room_create_room(r) != NGX_OK) {
        ngx_rtmp_room_delete_room(r);
        goto error;
    }

    return r;

error:
    ngx_destroy_pool(pool);

    return NULL;
}


static ngx_int_t
ngx_rtmp_room_join(ngx_rtmp_session_t *s, u_char *sname, unsigned publishing)
{
    ngx_rtmp_room_app_conf_t       *racf;
    ngx_rtmp_room_t               **rr, *r;
    ngx_rtmp_room_ctx_t            *ctx;
    ngx_str_t                       name;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_room_module);

    name.data = sname;
    name.len = ngx_strlen(sname);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_room_module);
    if (ctx && ctx->room) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "room: already joined to '%V'", &ctx->room->name);
        return NGX_OK;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_room_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_room_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                   "room: join '%V'", &name);

    rr = ngx_rtmp_room_get_room(racf, &name);
    if (rr == NULL) {
        return NGX_ERROR;
    }

    if (*rr == NULL) {
        *rr = ngx_rtmp_room_create(racf, &name);
        if (*rr == NULL) {
            return NGX_ERROR;
        }
    }

    r = *rr;

    ctx->room = r;
    ctx->publishing = publishing;

    ctx->next = r->first_ctx;
    r->first_ctx = ctx;

    return ngx_rtmp_join_room(r, s);
}


static ngx_int_t
ngx_rtmp_room_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_room_app_conf_t       *racf;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_room_module);
    if (racf == NULL || !racf->active) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "room: publish: name='%s' type='%s'",
                   v->name, v->type);

    /* join stream as publisher */

    if (ngx_rtmp_room_join(s, v->name, 1) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_room_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_room_app_conf_t       *racf;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_room_module);
    if (racf == NULL || !racf->active) {
        goto next;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "room: play: name='%s' start=%uD duration=%uD reset=%d",
                   v->name, (uint32_t) v->start, 
                   (uint32_t) v->duration, (uint32_t) v->reset);

    /* join stream as subscriber */

    if (ngx_rtmp_room_join(s, v->name, 0) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_room_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_room_app_conf_t       *racf;
    ngx_rtmp_room_ctx_t           **cctx, *ctx;
    ngx_rtmp_room_t               **rr, *r;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_room_module);
    if (racf == NULL || !racf->active) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_room_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->room == NULL) {
        goto next;
    }

    r = ctx->room;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "room: leave '%V'", &r->name);

    for (cctx = &r->first_ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    ctx->room = NULL;

    ngx_rtmp_leave_room(r, s);

    if (r->first_ctx || r->persistent) {
        goto next;
    }

    /* non-persistent room is empty*/

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, racf->log, 0,
                   "room: delete room '%V'", &r->name);

    rr = ngx_rtmp_room_get_room(racf, &r->name);
    if (rr == NULL) {
        goto next;
    }

    *rr = (*rr)->next;

    ngx_rtmp_delete_room(r);

    ngx_destroy_pool(r->pool);

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_room_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_room_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_room_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_room_close_stream;

    return NGX_OK;
}
