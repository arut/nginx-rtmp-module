/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

#include "ngx_rtmp_cmd_module.h"

#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef NGX_LINUX
#include <unistd.h>
#endif


static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_delete_stream_pt                next_delete_stream;


static char *ngx_rtmp_enotify_on_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_enotify_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_enotify_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_enotify_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


#define NGX_RTMP_ENOTIFY_PUBLISHING             0x01
#define NGX_RTMP_ENOTIFY_PLAYING                0x02


#define NGX_RTMP_ENOTIFY_PUBLISH                0
#define NGX_RTMP_ENOTIFY_PLAY                   1
#define NGX_RTMP_ENOTIFY_PUBLISH_DONE           2
#define NGX_RTMP_ENOTIFY_PLAY_DONE              3
#define NGX_RTMP_ENOTIFY_MAX                    4


typedef struct {
    ngx_str_t                                   cmd;
    ngx_array_t                                 args; /* ngx_str_t */
} ngx_rtmp_enotify_conf_t;


typedef struct {
    ngx_rtmp_enotify_conf_t                    *events[NGX_RTMP_ENOTIFY_MAX];
    ngx_flag_t                                  active;
} ngx_rtmp_enotify_app_conf_t;


typedef struct {
    ngx_uint_t                                  flags;
    u_char                                      name[NGX_RTMP_MAX_NAME];
    u_char                                      args[NGX_RTMP_MAX_ARGS];
} ngx_rtmp_enotify_ctx_t;


static ngx_command_t  ngx_rtmp_enotify_commands[] = {

    { ngx_string("exec_publish"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_enotify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("exec_play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_enotify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("exec_publish_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_enotify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("exec_play_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_enotify_on_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_enotify_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_enotify_postconfiguration,     /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_enotify_create_app_conf,       /* create app configuration */
    ngx_rtmp_enotify_merge_app_conf         /* merge app configuration */
};


ngx_module_t  ngx_rtmp_enotify_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_enotify_module_ctx,           /* module context */
    ngx_rtmp_enotify_commands,              /* module directives */
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
ngx_rtmp_enotify_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_enotify_app_conf_t     *enacf;

    enacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_enotify_app_conf_t));
    if (enacf == NULL) {
        return NULL;
    }

    return enacf;
}


static char *
ngx_rtmp_enotify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_enotify_app_conf_t    *prev = parent;
    ngx_rtmp_enotify_app_conf_t    *conf = child;
    ngx_uint_t                      n;

    for (n = 0; n < NGX_RTMP_ENOTIFY_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->events[n], prev->events[n], 0);

        if (conf->events[n]) {
            conf->active = 1;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_exec_prepare_arg(ngx_rtmp_session_t *s, ngx_str_t *arg)
{
    /*TODO*/
    return (char *) arg->data;
}


static ngx_int_t
ngx_rtmp_enotify_exec(ngx_rtmp_session_t *s, ngx_rtmp_enotify_conf_t *ec)
{
#ifndef NGX_WIN32
    ngx_rtmp_enotify_ctx_t     *ctx;
    int                         pid;
    ngx_str_t                  *arg;
    char                      **args;
    ngx_uint_t                  n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_enotify_module);

    pid = fork();

    switch (pid) {
        case -1:
            ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                          "enotify: fork failed");
            return NGX_ERROR;

        case 0:
            /* child */
            args = malloc((ec->args.nelts + 2) * sizeof(char *));
            if (args == NULL) {
                exit(1);
            }
            arg = ec->args.elts;
            args[0] = (char *)ec->cmd.data;
            for (n = 0; n < ec->args.nelts; ++n, ++arg) {
                args[n + 1] = ngx_rtmp_exec_prepare_arg(s, arg);
            }
            args[n + 1] = NULL;
            if (execvp((char *)ec->cmd.data, args) == -1) {
                exit(1);
            }
            break;

        default:
            /* parent */
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "enotify: child '%V' started pid=%ui", 
                           &ec->cmd, (ngx_uint_t)pid);
            break;
    }
#endif /* NGX_WIN32 */

    return NGX_OK;
}


static void
ngx_rtmp_enotify_init(ngx_rtmp_session_t *s, 
        u_char name[NGX_RTMP_MAX_NAME], u_char args[NGX_RTMP_MAX_ARGS],
        ngx_uint_t flags)
{
    ngx_rtmp_enotify_ctx_t         *ctx;
    ngx_rtmp_enotify_app_conf_t    *enacf;

    enacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_enotify_module);

    if (!enacf->active) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_enotify_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_enotify_ctx_t));
        if (ctx == NULL) {
            return;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_enotify_module);
    }

    ngx_memcpy(ctx->name, name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, args, NGX_RTMP_MAX_ARGS);

    ctx->flags |= flags;
}


static ngx_int_t
ngx_rtmp_enotify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_enotify_app_conf_t    *enacf;
    ngx_rtmp_enotify_conf_t        *ec;

    if (s->auto_pushed) {
        goto next;
    }

    enacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_enotify_module);

    if (enacf == NULL) {
        goto next;
    }

    ngx_rtmp_enotify_init(s, v->name, v->args, NGX_RTMP_ENOTIFY_PUBLISHING);

    ec = enacf->events[NGX_RTMP_ENOTIFY_PUBLISH];

    if (ec == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "enotify: publish '%V'", &ec->cmd);

    ngx_rtmp_enotify_exec(s, ec);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_enotify_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_enotify_app_conf_t    *enacf;
    ngx_rtmp_enotify_conf_t        *ec;

    if (s->auto_pushed) {
        goto next;
    }

    enacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_enotify_module);

    if (enacf == NULL) {
        goto next;
    }

    ngx_rtmp_enotify_init(s, v->name, v->args, NGX_RTMP_ENOTIFY_PLAYING);

    ec = enacf->events[NGX_RTMP_ENOTIFY_PLAY];
    
    if (ec == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "enotify: play '%V'", &ec->cmd);

    ngx_rtmp_enotify_exec(s, ec);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_enotify_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t 
        *v)
{
    ngx_rtmp_enotify_ctx_t         *ctx;
    ngx_rtmp_enotify_app_conf_t    *enacf;
    ngx_rtmp_enotify_conf_t        *ec;

    if (s->auto_pushed) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_enotify_module);

    if (ctx == NULL) {
        goto next;
    }

    enacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_enotify_module);

    if (enacf == NULL) {
        goto next;
    }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "enotify: delete_stream %ui", 
                       ctx->flags);

    if (enacf->events[NGX_RTMP_ENOTIFY_PUBLISH_DONE] &&
       (ctx->flags & NGX_RTMP_ENOTIFY_PUBLISHING)) 
    {
        ec = enacf->events[NGX_RTMP_ENOTIFY_PUBLISH_DONE];

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "enotify: publish_done '%V'", &ec->cmd);

        ngx_rtmp_enotify_exec(s, ec);
    }

    if (enacf->events[NGX_RTMP_ENOTIFY_PLAY_DONE] &&
       (ctx->flags & NGX_RTMP_ENOTIFY_PLAYING)) 
    {
        ec = enacf->events[NGX_RTMP_ENOTIFY_PLAY_DONE];

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "enotify: play_done '%V'", &ec->cmd);

        ngx_rtmp_enotify_exec(s, ec);
    }

    ctx->flags = 0;

next:
    return next_delete_stream(s, v);
}


static char *
ngx_rtmp_enotify_on_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_enotify_app_conf_t    *enacf;
    ngx_rtmp_enotify_conf_t        *ec;
    ngx_str_t                      *name, *value, *s;
    size_t                          len, nargs;
    ngx_uint_t                      n;

    value = cf->args->elts;
    name = &value[0];

    ec = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_enotify_conf_t));

    if (ec == NULL) {
        return NGX_CONF_ERROR;
    }

    ec->cmd = value[1];

    nargs = cf->args->nelts - 2;

    if (nargs) {
        if (ngx_array_init(&ec->args, cf->pool, nargs, sizeof(ngx_str_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        s = ngx_array_push_n(&ec->args, nargs);
        for (n = 2; n < cf->args->nelts; ++n, ++s) {
            *s = value[n];
        }
    }

    enacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_enotify_module);

    len = name->len;
    n = 0;

    switch (name->data[6]) {

        case 'l': /* exec_pLay... */
            if (len == sizeof("exec_play") - 1) {
                n = NGX_RTMP_ENOTIFY_PLAY;
            } else {
                n = NGX_RTMP_ENOTIFY_PLAY_DONE;
            }
            break;

        case 'u': /* exec_pUblish... */
            if (len == sizeof("exec_publish") - 1) {
                n = NGX_RTMP_ENOTIFY_PUBLISH;
            } else {
                n = NGX_RTMP_ENOTIFY_PUBLISH_DONE;
            }
            break;
    }

    enacf->events[n] = ec;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_enotify_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_enotify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_enotify_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_enotify_delete_stream;

    return NGX_OK;
}
