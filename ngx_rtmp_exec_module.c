/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_eval.h"
#include <stdlib.h>

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
    ngx_int_t                           kill_signal;
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


static char *ngx_rtmp_exec_kill_signal(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
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

    { ngx_string("exec_kill_signal"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_exec_kill_signal,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
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


static void
ngx_rtmp_exec_eval_astr(ngx_rtmp_session_t *s, ngx_rtmp_eval_t *e,
                           ngx_str_t *ret)
{
    ngx_rtmp_exec_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);
    if (ctx == NULL) {
        ret->len = 0;
        return;
    }

    ret->data = (u_char *) ctx + e->offset;
    ret->len = ngx_strlen(ret->data);
}


static ngx_rtmp_eval_t ngx_rtmp_exec_eval[] = {

    { ngx_string("name"),
      ngx_rtmp_exec_eval_astr,
      offsetof(ngx_rtmp_exec_ctx_t, name) },

    ngx_rtmp_null_eval
};


static ngx_rtmp_eval_t * ngx_rtmp_exec_eval_p[] = {
    ngx_rtmp_eval_session,
    ngx_rtmp_exec_eval,
    NULL
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
    eacf->kill_signal = NGX_CONF_UNSET;

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
    ngx_conf_merge_value(conf->kill_signal, prev->kill_signal, SIGKILL);

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
    ngx_rtmp_exec_app_conf_t   *eacf;

    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);

    if (e->respawn_evt.timer_set) {
        ngx_del_timer(&e->respawn_evt);
    }

    if (e->read_evt.active) {
        ngx_del_event(&e->read_evt, NGX_READ_EVENT, 0);
    }

    if (e->active == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "exec: terminating child %ui", 
            (ngx_int_t)e->pid);

    e->active = 0;
    close(e->pipefd);

    if (!term) {
        return NGX_OK;
    }

    if (kill(e->pid, eacf->kill_signal) == -1) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                "exec: kill failed pid=%i", (ngx_int_t)e->pid);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "exec: killed pid=%i", (ngx_int_t)e->pid);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_exec_run(ngx_rtmp_session_t *s, size_t n)
{
#if !(NGX_WIN32)
    ngx_rtmp_exec_app_conf_t       *eacf;
    ngx_rtmp_exec_ctx_t            *ctx;
    int                             pid, fd, maxfd;
    int                             pipefd[2];
    int                             ret;
    ngx_rtmp_exec_conf_t           *ec;
    ngx_rtmp_exec_t                *e;
    ngx_str_t                      *arg, a;
    char                          **args;

    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);
    ec = (ngx_rtmp_exec_conf_t *)eacf->execs.elts + n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_exec_module);
    e = ctx->execs + n;

    ngx_memzero(e, sizeof(*e));

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

            /* close all descriptors but pipe write end */
            maxfd = sysconf(_SC_OPEN_MAX);
            for (fd = 0; fd < maxfd; ++fd) {
                if (fd == pipefd[1]) {
                    continue;
                }

                close(fd);
            }

            fd = open("/dev/null", O_RDWR);            

            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);

            args = ngx_palloc(s->connection->pool, 
                              (ec->args.nelts + 2) * sizeof(char *));
            if (args == NULL) {
                exit(1);
            }
            arg = ec->args.elts;
            args[0] = (char *)ec->cmd.data;
            for (n = 0; n < ec->args.nelts; ++n, ++arg) {
                ngx_rtmp_eval(s, arg, ngx_rtmp_exec_eval_p, &a);
                args[n + 1] = (char *) a.data;
            }
            args[n + 1] = NULL;
            if (execvp((char *)ec->cmd.data, args) == -1) {
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
#endif /* NGX_WIN32 */
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
        ngx_rtmp_exec_kill(s, e, 1);
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

    if (s->auto_pushed) {
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


static char *
ngx_rtmp_exec_kill_signal(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_exec_app_conf_t   *eacf;
    ngx_str_t                  *value;

    eacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_exec_module);
    value = cf->args->elts;
    value++;

    eacf->kill_signal = ngx_atoi(value->data, value->len);
    if (eacf->kill_signal != NGX_ERROR) {
        return NGX_CONF_OK;
    }

#define NGX_RMTP_EXEC_SIGNAL(name)                                          \
    if (value->len == sizeof(#name) - 1 &&                                  \
        ngx_strncasecmp(value->data, (u_char *) #name, value->len) == 0)    \
    {                                                                       \
        eacf->kill_signal = SIG##name;                                      \
        return NGX_CONF_OK;                                                 \
    }

    /* POSIX.1-1990 signals */

    NGX_RMTP_EXEC_SIGNAL(HUP);
    NGX_RMTP_EXEC_SIGNAL(INT);
    NGX_RMTP_EXEC_SIGNAL(QUIT);
    NGX_RMTP_EXEC_SIGNAL(ILL);
    NGX_RMTP_EXEC_SIGNAL(ABRT);
    NGX_RMTP_EXEC_SIGNAL(FPE);
    NGX_RMTP_EXEC_SIGNAL(KILL);
    NGX_RMTP_EXEC_SIGNAL(SEGV);
    NGX_RMTP_EXEC_SIGNAL(PIPE);
    NGX_RMTP_EXEC_SIGNAL(ALRM);
    NGX_RMTP_EXEC_SIGNAL(TERM);
    NGX_RMTP_EXEC_SIGNAL(USR1);
    NGX_RMTP_EXEC_SIGNAL(USR2);
    NGX_RMTP_EXEC_SIGNAL(CHLD);
    NGX_RMTP_EXEC_SIGNAL(CONT);
    NGX_RMTP_EXEC_SIGNAL(STOP);
    NGX_RMTP_EXEC_SIGNAL(TSTP);
    NGX_RMTP_EXEC_SIGNAL(TTIN);
    NGX_RMTP_EXEC_SIGNAL(TTOU);

#undef NGX_RMTP_EXEC_SIGNAL

    return "unknown signal";
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
