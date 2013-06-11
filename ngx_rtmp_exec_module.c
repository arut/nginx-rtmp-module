/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_eval.h"
#include <stdlib.h>

#ifdef NGX_LINUX
#include <unistd.h>
#endif


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;


static ngx_int_t ngx_rtmp_exec_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_rtmp_exec_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_exec_create_main_conf(ngx_conf_t *cf);
static char * ngx_rtmp_exec_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_rtmp_exec_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_exec_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);
static char * ngx_rtmp_exec_exec(ngx_conf_t *cf, ngx_command_t *cmd, 
       void *conf);
static char * ngx_rtmp_exec_exec_static(ngx_conf_t *cf, ngx_command_t *cmd, 
       void *conf);
static void ngx_rtmp_exec_respawn(ngx_event_t *ev);


#define NGX_RTMP_EXEC_RESPAWN           0x01
#define NGX_RTMP_EXEC_KILL              0x02


typedef struct {
    ngx_str_t                           cmd;
    ngx_array_t                         args;       /* ngx_str_t */
} ngx_rtmp_exec_conf_t;


typedef struct {
    ngx_rtmp_exec_conf_t               *conf;
    ngx_log_t                          *log;
    ngx_rtmp_session_t                 *session;    /* NULL for init execs */
    unsigned                            active:1;
    ngx_pid_t                           pid;
    ngx_pid_t                          *save_pid;
    int                                 pipefd;
    ngx_connection_t                    dummy_conn; /*needed by ngx_xxx_event*/
    ngx_event_t                         read_evt, write_evt;
    ngx_event_t                         respawn_evt;
    ngx_msec_t                          respawn_timeout;
    ngx_int_t                           kill_signal;
} ngx_rtmp_exec_t;


typedef struct {
    ngx_array_t                         confs;      /* ngx_rtmp_exec_conf_t */
    ngx_array_t                         execs;      /* ngx_rtmp_exec_t */
    ngx_msec_t                          respawn_timeout;
    ngx_int_t                           kill_signal;
} ngx_rtmp_exec_main_conf_t;


typedef struct {
    ngx_array_t                         confs;      /* ngx_rtmp_exec_conf_t */
    ngx_flag_t                          respawn;
} ngx_rtmp_exec_app_conf_t;


typedef struct {
    u_char                              name[NGX_RTMP_MAX_NAME];
    u_char                              args[NGX_RTMP_MAX_ARGS];
    ngx_array_t                         execs;
} ngx_rtmp_exec_ctx_t;


static char *ngx_rtmp_exec_kill_signal(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_exec_kill(ngx_rtmp_exec_t *e, ngx_int_t kill_signal);
static ngx_int_t ngx_rtmp_exec_run(ngx_rtmp_exec_t *e);


static ngx_command_t  ngx_rtmp_exec_commands[] = {

    { ngx_string("exec"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_exec_exec,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("exec_static"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_exec_exec_static,
      NGX_RTMP_MAIN_CONF_OFFSET,
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
      NGX_RTMP_MAIN_CONF_OFFSET,
      offsetof(ngx_rtmp_exec_main_conf_t, respawn_timeout),
      NULL },

    { ngx_string("exec_kill_signal"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_exec_kill_signal,
      NGX_RTMP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_exec_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_exec_postconfiguration,        /* postconfiguration */
    ngx_rtmp_exec_create_main_conf,         /* create main configuration */
    ngx_rtmp_exec_init_main_conf,           /* init main configuration */
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
    ngx_rtmp_exec_init_process,             /* init process */
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

    { ngx_string("args"),
      ngx_rtmp_exec_eval_astr,
      offsetof(ngx_rtmp_exec_ctx_t, args) },

    ngx_rtmp_null_eval
};


static ngx_rtmp_eval_t * ngx_rtmp_exec_eval_p[] = {
    ngx_rtmp_eval_session,
    ngx_rtmp_exec_eval,
    NULL
};


static void *
ngx_rtmp_exec_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_exec_main_conf_t     *emcf;

    emcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_exec_main_conf_t));
    if (emcf == NULL) {
        return NULL;
    }

    emcf->respawn_timeout = NGX_CONF_UNSET_MSEC;
    emcf->kill_signal = NGX_CONF_UNSET;

    if (ngx_array_init(&emcf->confs, cf->pool, 1, 
                       sizeof(ngx_rtmp_exec_conf_t)) != NGX_OK)
    {
        return NULL;
    }

    return emcf;
}


static char *
ngx_rtmp_exec_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_exec_main_conf_t  *emcf = conf;
    ngx_rtmp_exec_conf_t       *ec;
    ngx_rtmp_exec_t            *e;
    ngx_uint_t                  n;

    if (emcf->respawn_timeout == NGX_CONF_UNSET_MSEC) {
        emcf->respawn_timeout = 5000;
    }

    if (emcf->kill_signal == NGX_CONF_UNSET) {
 //       emcf->kill_signal = SIGKILL;
    }

    if (ngx_array_init(&emcf->execs, cf->pool, emcf->confs.nelts,
                       sizeof(ngx_rtmp_exec_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    e = ngx_array_push_n(&emcf->execs, emcf->confs.nelts);
    if (e == NULL) {
        return NGX_CONF_ERROR;
    }

    ec = emcf->confs.elts;

    for (n = 0; n < emcf->confs.nelts; ++n, ++e, ++ec) {
        ngx_memzero(e, sizeof(*e));
        e->conf = ec;
        e->log = &cf->cycle->new_log;
        e->respawn_timeout = emcf->respawn_timeout;
        e->kill_signal = emcf->kill_signal;
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_exec_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_exec_app_conf_t      *eacf;

    eacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_exec_app_conf_t));
    if (eacf == NULL) {
        return NULL;
    }

    eacf->respawn = NGX_CONF_UNSET;

    if (ngx_array_init(&eacf->confs, cf->pool, 1, 
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

    if (prev->confs.nelts) {
        ec = ngx_array_push_n(&conf->confs, prev->confs.nelts);
        if (ec == NULL) {
            return NGX_CONF_ERROR;
        }
        pec = prev->confs.elts;
        for (n = 0; n < prev->confs.nelts; ++n, ++ec, ++pec) {
            *ec = *pec;
        }
    }
            
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_exec_init_process(ngx_cycle_t *cycle)
{
    ngx_rtmp_core_main_conf_t  *cmcf = ngx_rtmp_core_main_conf;
    ngx_rtmp_core_srv_conf_t  **cscf;
    ngx_rtmp_conf_ctx_t        *cctx;
    ngx_rtmp_exec_main_conf_t  *emcf;
    ngx_rtmp_exec_t            *e;
    ngx_uint_t                  n;

    if (cmcf == NULL || cmcf->servers.nelts == 0) {
        return NGX_OK;
    }

    /* execs are always started by the first worker */
    if (ngx_pid != ngx_processes[0].pid) {
        return NGX_OK;
    }

    cscf = cmcf->servers.elts;
    cctx = (*cscf)->ctx;
    emcf = cctx->main_conf[ngx_rtmp_exec_module.ctx_index];

    /* FreeBSD note:
     * When worker is restarted, child process (ffmpeg) will
     * not be terminated if it's connected to another 
     * (still alive) worker. That leads to starting
     * another instance of exec_static process.
     * Need to kill previously started processes.
     *
     * On Linux "prctl" syscall is used to kill child
     * when nginx worker is terminated.
     */

    e = emcf->execs.elts;
    for (n = 0; n < emcf->execs.nelts; ++n, ++e) {
        e->respawn_evt.data = e;
        e->respawn_evt.log = e->log;
        e->respawn_evt.handler = ngx_rtmp_exec_respawn;
        ngx_post_event((&e->respawn_evt), &ngx_rtmp_init_queue);
    }

    return NGX_OK;
}


static void 
ngx_rtmp_exec_respawn(ngx_event_t *ev)
{
    ngx_rtmp_exec_run((ngx_rtmp_exec_t *) ev->data);
}


static void 
ngx_rtmp_exec_child_dead(ngx_event_t *ev)
{
    ngx_connection_t   *dummy_conn = ev->data;
    ngx_rtmp_exec_t    *e;

    e = dummy_conn->data;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, e->log, 0,
                   "exec: child %ui exited; %s", (ngx_int_t) e->pid,
                   e->respawn_timeout == NGX_CONF_UNSET_MSEC ? "respawning" :
                                                               "ignoring");

    ngx_rtmp_exec_kill(e, 0);

    if (e->respawn_timeout == NGX_CONF_UNSET_MSEC) {
        return;
    }

    if (e->respawn_timeout == 0) {
        ngx_rtmp_exec_run(e);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->log, 0,
                   "exec: shedule respawn %Mmsec", e->respawn_timeout);

    e->respawn_evt.data = e;
    e->respawn_evt.log = e->log;
    e->respawn_evt.handler = ngx_rtmp_exec_respawn;

    ngx_add_timer(&e->respawn_evt, e->respawn_timeout);
}


static ngx_int_t
ngx_rtmp_exec_kill(ngx_rtmp_exec_t *e, ngx_int_t kill_signal)
{
    if (e->respawn_evt.timer_set) {
        ngx_del_timer(&e->respawn_evt);
    }

    if (e->read_evt.active) {
        ngx_del_event(&e->read_evt, NGX_READ_EVENT, 0);
    }

    if (e->active == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->log, 0,
                   "exec: terminating child %ui", 
                   (ngx_int_t) e->pid);

    e->active = 0;
    close(e->pipefd);
    if (e->save_pid) {
        *e->save_pid = NGX_INVALID_PID;
    }

    if (kill_signal == 0) {
        return NGX_OK;
    }

//    if (kill(e->pid, kill_signal) == -1) {
//        ngx_log_error(NGX_LOG_INFO, e->log, ngx_errno,
//                      "exec: kill failed pid=%i", (ngx_int_t) e->pid);
//    } else {
//        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->log, 0,
//                       "exec: killed pid=%i", (ngx_int_t) e->pid);
//    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_exec_run(ngx_rtmp_exec_t *e)
{
#if !(NGX_WIN32)
    ngx_pid_t                       pid;
    int                             fd, maxfd;
    int                             pipefd[2];
    int                             ret;
    ngx_rtmp_exec_conf_t           *ec;
    ngx_str_t                      *arg_in, a;
    char                          **args, **arg_out;
    ngx_uint_t                      n;

    ec = e->conf;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->log, 0,
                   "exec: starting child '%V'", &ec->cmd);

    if (e->active) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->log, 0,
                       "exec: already active '%V'", &ec->cmd);
        return NGX_OK;
    }

    if (pipe(pipefd) == -1) {
        ngx_log_error(NGX_LOG_INFO, e->log, ngx_errno,
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
        ngx_log_error(NGX_LOG_INFO, e->log, ngx_errno,
                      "exec: fcntl failed");
        return NGX_ERROR;
    }

    pid = fork();
    switch (pid) {
        case -1:
            close(pipefd[0]);
            close(pipefd[1]);
            ngx_log_error(NGX_LOG_INFO, e->log, ngx_errno,
                          "exec: fork failed");
            return NGX_ERROR;

        case 0:
            /* child */

#if (NGX_LINUX)
            prctl(PR_SET_PDEATHSIG, e->kill_signal, 0, 0, 0);
#endif

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

            args = ngx_alloc((ec->args.nelts + 2) * sizeof(char *), e->log);
            if (args == NULL) {
                exit(1);
            }

            arg_in = ec->args.elts;
            arg_out = args;
            *arg_out++ = (char *) ec->cmd.data;

            for (n = 0; n < ec->args.nelts; n++, ++arg_in) {

                if (e->session == NULL) {
                    a = *arg_in;
                } else {
                    ngx_rtmp_eval(e->session, arg_in, ngx_rtmp_exec_eval_p, &a);
                }
                
                if (ngx_rtmp_eval_streams(&a) != NGX_DONE) {
                    continue;
                }

                *arg_out++ = (char *) a.data;
            }

            *arg_out = NULL;

            if (execvp((char *) ec->cmd.data, args) == -1) {
                exit(1);
            }

            break;

        default:
            /* parent */
            close(pipefd[1]);
            e->active = 1;
            e->pid = pid;
            e->pipefd = pipefd[0];
            if (e->save_pid) {
                *e->save_pid = pid;
            }

            e->dummy_conn.fd = e->pipefd;
            e->dummy_conn.data = e;
            e->dummy_conn.read  = &e->read_evt;
            e->dummy_conn.write = &e->write_evt;
            e->read_evt.data  = &e->dummy_conn;
            e->write_evt.data = &e->dummy_conn;

            e->read_evt.log = e->log;
            e->read_evt.handler = ngx_rtmp_exec_child_dead;

            if (ngx_add_event(&e->read_evt, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, e->log, ngx_errno,
                              "exec: failed to add child control event");
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, e->log, 0,
                           "exec: child '%V' started pid=%i", 
                           &ec->cmd, (ngx_int_t) pid);
            break;
    }
#endif /* NGX_WIN32 */
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_exec_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
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
    if (ctx == NULL || ctx->execs.nelts == 0) {
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "exec: delete %uz command(s)", ctx->execs.nelts);

    e = ctx->execs.elts;
    for (n = 0; n < ctx->execs.nelts; ++n, ++e) {
        ngx_rtmp_exec_kill(e, e->kill_signal);
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_exec_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_exec_main_conf_t      *emcf;
    ngx_rtmp_exec_app_conf_t       *eacf;
    ngx_rtmp_exec_t                *e;
    ngx_rtmp_exec_conf_t           *ec;
    ngx_rtmp_exec_ctx_t            *ctx;
    size_t                          n;

    emcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_exec_module);
    eacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_exec_module);
    if (eacf == NULL || eacf->confs.nelts == 0) {
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

        if (ngx_array_init(&ctx->execs, s->connection->pool, eacf->confs.nelts,
                           sizeof(ngx_rtmp_exec_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }

        e = ngx_array_push_n(&ctx->execs, eacf->confs.nelts);
        if (e == NULL) {
            return NGX_ERROR;
        }

        ec = eacf->confs.elts;
        for (n = 0; n < eacf->confs.nelts; ++n, ++e, ++ec) {
            ngx_memzero(e, sizeof(*e));
            e->conf = ec;
            e->log = s->connection->log;
            e->session = s;
            e->kill_signal = emcf->kill_signal;
            e->respawn_timeout = (eacf->respawn ? emcf->respawn_timeout :
                                                  NGX_CONF_UNSET_MSEC);
        }
    }

    ngx_memcpy(ctx->name, v->name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, v->args, NGX_RTMP_MAX_ARGS);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "exec: run %uz command(s)", ctx->execs.nelts);

    e = ctx->execs.elts;
    for (n = 0; n < ctx->execs.nelts; ++n, ++e) {
        ngx_rtmp_exec_run(e);
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

    ec = ngx_array_push(&eacf->confs);
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
ngx_rtmp_exec_exec_static(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_exec_main_conf_t  *emcf = conf;

    ngx_str_t                  *value;
    size_t                      n, nargs;
    ngx_str_t                  *s;
    ngx_rtmp_exec_conf_t       *ec;

    value = cf->args->elts;

    ec = ngx_array_push(&emcf->confs);
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
    ngx_rtmp_exec_main_conf_t  *emcf = conf;
    ngx_str_t                  *value;

    value = cf->args->elts;
    value++;

    emcf->kill_signal = ngx_atoi(value->data, value->len);
    if (emcf->kill_signal != NGX_ERROR) {
        return NGX_CONF_OK;
    }

#define NGX_RMTP_EXEC_SIGNAL(name)                                          \
    if (value->len == sizeof(#name) - 1 &&                                  \
        ngx_strncasecmp(value->data, (u_char *) #name, value->len) == 0)    \
    {                                                                       \
        emcf->kill_signal = SIG##name;                                      \
        return NGX_CONF_OK;                                                 \
    }

    /* POSIX.1-1990 signals */

 //   NGX_RMTP_EXEC_SIGNAL(HUP);
 //   NGX_RMTP_EXEC_SIGNAL(INT);
 //   NGX_RMTP_EXEC_SIGNAL(QUIT);
 //   NGX_RMTP_EXEC_SIGNAL(ILL);
 //   NGX_RMTP_EXEC_SIGNAL(ABRT);
 //   NGX_RMTP_EXEC_SIGNAL(FPE);
 //   NGX_RMTP_EXEC_SIGNAL(KILL);
 //   NGX_RMTP_EXEC_SIGNAL(SEGV);
 //   NGX_RMTP_EXEC_SIGNAL(PIPE);
 //   NGX_RMTP_EXEC_SIGNAL(ALRM);
 //   NGX_RMTP_EXEC_SIGNAL(TERM);
 //   NGX_RMTP_EXEC_SIGNAL(USR1);
 //   NGX_RMTP_EXEC_SIGNAL(USR2);
 //   NGX_RMTP_EXEC_SIGNAL(CHLD);
 //   NGX_RMTP_EXEC_SIGNAL(CONT);
 //   NGX_RMTP_EXEC_SIGNAL(STOP);
 //   NGX_RMTP_EXEC_SIGNAL(TSTP);
 //   NGX_RMTP_EXEC_SIGNAL(TTIN);
 //   NGX_RMTP_EXEC_SIGNAL(TTOU);

#undef NGX_RMTP_EXEC_SIGNAL

    return "unknown signal";
}


static ngx_int_t
ngx_rtmp_exec_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_exec_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_exec_close_stream;

    return NGX_OK;
}
