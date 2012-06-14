/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_cmd_module.h"
#include <malloc.h>

#ifdef NGX_LINUX
#include <unistd.h>
#endif


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_delete_stream_pt        next_delete_stream;


static ngx_int_t ngx_rtmp_exec_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_exec_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_exec_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child);
static char * ngx_rtmp_exec_exec(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf);


#define NGX_RTMP_EXEC_RESPAWN           0x01
#define NGX_RTMP_EXEC_KILL              0x02


typedef struct {
    ngx_str_t                           cmd;
    ngx_array_t                         args; /* ngx_str_t */
} ngx_rtmp_exec_conf_t;


typedef struct {
    ngx_array_t                         execs; /* ngx_rtmp_exec_conf_t */
    ngx_msec_t                          respawn_timeout;
    ngx_flag_t                          respawn;
} ngx_rtmp_exec_app_conf_t;


typedef struct {
    ngx_rtmp_session_t                 *session;
    size_t                              index;
    unsigned                            active:1;
    int                                 pid;
    int                                 pipefd;
    ngx_connection_t                    dummy_conn; /*needed by ngx_xxx_event*/
    ngx_event_t                         read_evt, write_evt;
    ngx_event_t                         respawn_evt;
} ngx_rtmp_exec_t;


typedef struct {
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_exec_t                    *execs;
} ngx_rtmp_exec_ctx_t;


static ngx_int_t ngx_rtmp_exec_kill(ngx_rtmp_session_t *s, ngx_rtmp_exec_t *e,
       ngx_int_t  term);
static ngx_int_t ngx_rtmp_exec_run(ngx_rtmp_session_t *s, size_t n);


static ngx_command_t  ngx_rtmp_exec_commands[] = {

    { ngx_string("exec"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_exec_exec,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("respawn"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_exec_app_conf_t, respawn),
      NULL },

    { ngx_string("respawn_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_exec_app_conf_t, respawn_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_exec_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_exec_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_exec_create_app_conf,          /* create app configuration */
    ngx_rtmp_exec_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_exec_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_exec_module_ctx,              /* module context */
    ngx_rtmp_exec_commands,                 /* module directives */
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
ngx_rtmp_exec_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_exec_app_conf_t      *eacf;

    eacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_exec_app_conf_t));
    if (eacf == NULL) {
        return NULL;
    }

    eacf->respawn = NGX_CONF_UNSET;
    eacf->respawn_timeout = NGX_CONF_UNSET;

    if (ngx_array_init(&eacf->execs, cf->pool, 1, 
                sizeof(ngx_rtmp_exec_conf_t)) != NGX_OK)
    {
        return NULL;
    }

    return eacf;
}


static char *
ngx_rtmp_exec_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_exec_app_conf_t   *prev = parent;
    ngx_rtmp_exec_app_conf_t   *conf = child;
    size_t                      n;
    ngx_rtmp_exec_conf_t       *ec, *pec;

    ngx_conf_merge_value(conf->respawn, prev->respawn, 1);
    ngx_conf_merge_msec_value(conf->respawn_timeout, prev->respawn_timeout, 
            5000);

    if (prev->execs.nelts) {
        ec = ngx_array_push_n(&conf->execs, prev->execs.nelts);
        if (ec == NULL) {
            return NGX_CONF_ERROR;
        }
        pec = prev->execs.elts;
        for (n = 0; n < prev->execs.nelts; ++n, ++ec, ++pec) {
            *ec = *pec;
        }
    }
            
    return NGX_CONF_OK;
}


static void 
ngx_rtmp_exec_respawn(ngx_event_t *ev)
{
    ngx_rtmp_exec_t                *e;

    e = ev->data;
    ngx_rtmp_exec_run(e->session, e->index);
}


static void 
ngx_rtmp_exec_child_dead(ngx_event_t *ev)
{
    ngx_connection_t               *dummy_conn;
    ngx_rtmp_exec_t                *e;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_exec_app_conf_t       *eacf;

    dummy_conn = ev->data;
    e = dummy_conn->data;
    s = e->session;
    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: child %ui exited; %s", 
            (ngx_int_t)e->pid,
            eacf->respawn ? "respawning" : "ignoring");

    ngx_rtmp_exec_kill(s, e, 0);

    if (!eacf->respawn) {
        return;
    }

    if (eacf->respawn_timeout == 0) {
        ngx_rtmp_exec_run(s, e->index);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: shedule respawn %Mmsec", eacf->respawn_timeout);
    e->respawn_evt.data = e;
    e->respawn_evt.log = s->connection->log;
    e->respawn_evt.handler = ngx_rtmp_exec_respawn;
    ngx_add_timer(&e->respawn_evt, eacf->respawn_timeout);
}


static ngx_int_t
ngx_rtmp_exec_kill(ngx_rtmp_session_t *s, ngx_rtmp_exec_t *e, ngx_int_t term)
{
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: terminating child %ui", 
            (ngx_int_t)e->pid);

    if (e->respawn_evt.timer_set) {
        ngx_del_timer(&e->respawn_evt);
    }

    ngx_del_event(&e->read_evt, NGX_READ_EVENT, 0);
    e->active = 0;
    close(e->pipefd);

    if (!term) {
        return NGX_OK;
    }

    if (kill(e->pid, SIGKILL) == -1) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                "exec: kill failed pid=%i", (ngx_int_t)e->pid);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "exec: killed pid=%i", (ngx_int_t)e->pid);
    }

    return NGX_OK;
}


static void
ngx_rtmp_exec_append(ngx_str_t *result, u_char *data, size_t len)
{
    if (len == 0) {
        len = ngx_strlen(data);
    }

    /* use malloc in child */
    if (result->len == 0) {
        result->data = malloc(len + 1);
        result->len = len;
        ngx_memcpy(result->data, data, len);
        result->data[len] = 0;
        return;
    }

    result->data = realloc(result->data, result->len + len + 1);
    ngx_memcpy(result->data + result->len, data, len);
    result->len += len;
    result->data[result->len] = 0;
}


static char *
ngx_rtmp_exec_prepare_arg(ngx_rtmp_session_t *s, ngx_str_t *arg)
{
    ngx_rtmp_core_app_conf_t       *cacf;
    ngx_rtmp_exec_ctx_t            *ctx;
    u_char                         *p, *pp;
    ngx_str_t                       result;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);

    /* substitute $app/${app} & $name/${name} */
    ngx_str_set(&result, "");
    pp = arg->data;
    for ( ;; ) {
        p = (u_char *)ngx_strchr(pp, '$');
        ngx_rtmp_exec_append(&result, pp, p ? p - pp : 0);
        if (p == NULL) {
            return (char *)result.data;
        }
        pp = p + 1;
        if (p != arg->data && p[-1] == '\\') {
            goto dollar;
        }
        if (!ngx_strncmp(p + 1, "app", sizeof("app") - 1)
            || !ngx_strncmp(p + 1, "{app}", sizeof("{app}") - 1)) 
        {
            ngx_rtmp_exec_append(&result, cacf->name.data, cacf->name.len);
            pp += (p[1] == '{' ? sizeof("{app}") - 1 : sizeof("app") - 1);
            continue;
        }
        if (!ngx_strncmp(p + 1, "name", sizeof("name") - 1)
            || !ngx_strncmp(p + 1, "{name}", sizeof("{name}") - 1)) 
        {
            ngx_rtmp_exec_append(&result, ctx->name, 0);
            pp += (p[1] == '{' ? sizeof("{name}") - 1 : sizeof("name") - 1);
            continue;
        }
dollar:
        ngx_rtmp_exec_append(&result, (u_char *)"$", 1);
    }
}


static ngx_int_t
ngx_rtmp_exec_run(ngx_rtmp_session_t *s, size_t n)
{
#ifdef NGX_LINUX
    ngx_rtmp_exec_app_conf_t       *eacf;
    ngx_rtmp_exec_ctx_t            *ctx;
    int                             pid;
    int                             pipefd[2];
    int                             ret;
    ngx_rtmp_exec_conf_t           *ec;
    ngx_rtmp_exec_t                *e;
    ngx_str_t                      *arg;
    char                          **args;

    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);
    ec = (ngx_rtmp_exec_conf_t *)eacf->execs.elts + n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);
    e = ctx->execs + n;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: starting child '%V'", 
            &ec->cmd);

    if (pipe(pipefd) == -1) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                "exec: pipe failed");
        return NGX_ERROR;
    }

    /* make pipe write end survive through exec */
    ret = fcntl(pipefd[1], F_GETFD);
    if (ret != -1) {
        ret &= ~FD_CLOEXEC;
        ret = fcntl(pipefd[1], F_SETFD, ret);
    }
    if (ret == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                "exec: fcntl failed");
        return NGX_ERROR;
    }

    pid = fork();
    switch (pid) {
        case -1:
            close(pipefd[0]);
            close(pipefd[1]);
            ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                    "exec: fork failed");
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
            if (execv((char *)ec->cmd.data, args) == -1) {
                exit(1);
            }
            break;

        default:
            /* parent */
            close(pipefd[1]);
            e->session = s;
            e->index = n;
            e->active = 1;
            e->pid = pid;
            e->pipefd = pipefd[0];

            e->dummy_conn.fd = e->pipefd;
            e->dummy_conn.data = e;
            e->dummy_conn.read  = &e->read_evt;
            e->dummy_conn.write = &e->write_evt;
            e->read_evt.data  = &e->dummy_conn;
            e->write_evt.data = &e->dummy_conn;

            e->read_evt.log = s->connection->log;
            e->read_evt.handler = ngx_rtmp_exec_child_dead;

            if (ngx_add_event(&e->read_evt, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                        "exec: failed to add child control event");
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "exec: child '%V' started pid=%ui", 
                    &ec->cmd, (ngx_uint_t)pid);
            break;
    }
#endif /* NGX_LINUX */
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_exec_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_exec_app_conf_t       *eacf;
    ngx_rtmp_exec_ctx_t            *ctx;
    ngx_rtmp_exec_t                *e;
    size_t                          n;

    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);
    if (eacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);
    if (ctx == NULL || ctx->execs == NULL) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: delete %uz command(s)", eacf->execs.nelts);

    e = ctx->execs;
    for (n = 0; n < eacf->execs.nelts; ++n, ++e) {
        if (e->active) {
            ngx_rtmp_exec_kill(s, e, 1);
        }
    }

next:
    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_exec_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_exec_app_conf_t       *eacf;
    ngx_rtmp_exec_conf_t           *ec;
    ngx_rtmp_exec_ctx_t            *ctx;
    size_t                          n;

    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);
    if (eacf == NULL || eacf->execs.nelts == 0) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_exec_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_exec_module);
        ctx->execs = ngx_pcalloc(s->connection->pool, eacf->execs.nelts 
                * sizeof(ngx_rtmp_exec_t));
    }
    ngx_memcpy(ctx->name, v->name, NGX_RTMP_MAX_NAME);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: run %uz command(s)", eacf->execs.nelts);

    ec = eacf->execs.elts;
    for (n = 0; n < eacf->execs.nelts; ++n, ++ec) {
        ngx_rtmp_exec_run(s, n);
    }

next:
    return next_publish(s, v);
}


static char *
ngx_rtmp_exec_exec(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_rtmp_exec_app_conf_t   *eacf;
    size_t                      n, nargs;
    ngx_str_t                  *s;
    ngx_rtmp_exec_conf_t       *ec;

    eacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_exec_module);
    value = cf->args->elts;

    ec = ngx_array_push(&eacf->execs);
    if (ec == NULL) {
        return NGX_CONF_ERROR;
    }

    ec->cmd = value[1];

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    nargs = cf->args->nelts - 2;
    if (ngx_array_init(&ec->args, cf->pool, nargs, 
            sizeof(ngx_str_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    s = ngx_array_push_n(&ec->args, nargs);
    for (n = 2; n < cf->args->nelts; ++n, ++s) {
        *s = value[n];
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_exec_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_exec_publish;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_exec_delete_stream;

    return NGX_OK;
}
