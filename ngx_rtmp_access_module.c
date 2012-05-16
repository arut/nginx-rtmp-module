/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_play_pt             next_play;


#define NGX_RTMP_ACCESS_PUBLISH     0x01
#define NGX_RTMP_ACCESS_PLAY        0x02


static char * ngx_rtmp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, 
       void *conf);
static ngx_int_t ngx_rtmp_access_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_access_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_access_merge_app_conf(ngx_conf_t *cf, 
       void *parent, void *child);


typedef struct {
    in_addr_t               mask;
    in_addr_t               addr;
    ngx_uint_t              deny;
    ngx_uint_t              flags;
} ngx_rtmp_access_rule_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr;
    struct in6_addr         mask;
    ngx_uint_t              deny;
    ngx_uint_t              flags;
} ngx_rtmp_access_rule6_t;

#endif


typedef struct {
    ngx_array_t            *rules;     /* array of ngx_rtmp_access_rule_t */
#if (NGX_HAVE_INET6)
    ngx_array_t            *rules6;    /* array of ngx_rtmp_access_rule6_t */
#endif
} ngx_rtmp_access_app_conf_t;


static ngx_command_t  ngx_rtmp_access_commands[] = {

    { ngx_string("allow"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
      ngx_rtmp_access_rule,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
      ngx_rtmp_access_rule,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_access_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_access_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_access_create_app_conf,        /* create app configuration */
    ngx_rtmp_access_merge_app_conf,         /* merge app configuration */
};


ngx_module_t  ngx_rtmp_access_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_access_module_ctx,            /* module context */
    ngx_rtmp_access_commands,               /* module directives */
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
ngx_rtmp_access_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_access_app_conf_t      *aacf;

    aacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_access_app_conf_t));
    if (aacf == NULL) {
        return NULL;
    }

    return aacf;
}


static char *
ngx_rtmp_access_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_access_found(ngx_rtmp_session_t *s, ngx_uint_t deny)
{
    if (deny) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "access forbidden by rule");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_access_inet(ngx_rtmp_session_t *s, 
    ngx_rtmp_access_app_conf_t *ascf,
    in_addr_t addr, ngx_uint_t flag)
{
    ngx_uint_t                  i;
    ngx_rtmp_access_rule_t     *rule;

    rule = ascf->rules->elts;
    for (i = 0; i < ascf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr
                && flag & rule[i].flags) 
        {
            return ngx_rtmp_access_found(s, rule[i].deny);
        }
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_rtmp_access_inet6(ngx_rtmp_session_t *s, 
    ngx_rtmp_access_app_conf_t *ascf,
    u_char *p, ngx_uint_t flag)
{
    ngx_uint_t                  n;
    ngx_uint_t                  i;
    ngx_rtmp_access_rule6_t    *rule6;

    rule6 = ascf->rules6->elts;
    for (i = 0; i < ascf->rules6->nelts; i++) {

#if (NGX_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NGX_INET6_ADDRSTRLEN];
        u_char  mt[NGX_INET6_ADDRSTRLEN];
        u_char  at[NGX_INET6_ADDRSTRLEN];

        cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
        ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
        al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        if (flag & rule6[i].flags) {
            return ngx_rtmp_access_found(s, rule6[i].deny);
        }

    next:
        continue;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_rtmp_access(ngx_rtmp_session_t *s, ngx_uint_t flag)
{
    struct sockaddr_in             *sin;
    ngx_rtmp_access_app_conf_t     *ascf;
#if (NGX_HAVE_INET6)
    u_char                         *p;
    in_addr_t                       addr;
    struct sockaddr_in6            *sin6;
#endif

    ascf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_access_module);

    if (ascf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                "access: NULL app conf");
        return NGX_ERROR;
    }

    /* relay etc */
    if (s->connection->sockaddr == NULL) {
        return NGX_OK;
    }

    switch (s->connection->sockaddr->sa_family) {

    case AF_INET:
        if (ascf->rules) {
            sin = (struct sockaddr_in *) s->connection->sockaddr;
            return ngx_rtmp_access_inet(s, ascf, 
                    sin->sin_addr.s_addr, flag);
        }
        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (ascf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_rtmp_access_inet(s, ascf, htonl(addr), flag);
        }

        if (ascf->rules6) {
            return ngx_rtmp_access_inet6(s, ascf, p, flag);
        }

#endif
    }

    return NGX_OK;

}


static char *
ngx_rtmp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_access_app_conf_t         *ascf = conf;

    ngx_int_t                           rc;
    ngx_uint_t                          all;
    ngx_str_t                          *value;
    ngx_cidr_t                          cidr;
    ngx_rtmp_access_rule_t             *rule;
#if (NGX_HAVE_INET6)
    ngx_rtmp_access_rule6_t            *rule6;
#endif
    size_t                              n; 
    ngx_uint_t                          flags;

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    value = cf->args->elts;

    n = 1;
    flags = 0;

    if (cf->args->nelts == 2) {
        flags = NGX_RTMP_ACCESS_PUBLISH | NGX_RTMP_ACCESS_PLAY;

    } else {

        for(; n < cf->args->nelts - 1; ++n) {

            if (value[n].len == sizeof("publish") - 1
                    && ngx_strcmp(value[1].data, "publish") == 0)
            {
                flags |= NGX_RTMP_ACCESS_PUBLISH;
                continue;

            }
            
            if (value[n].len == sizeof("play") - 1
                    && ngx_strcmp(value[1].data, "play") == 0)
            {
                flags |= NGX_RTMP_ACCESS_PLAY;
                continue;

            }

            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                    "unexpected access specified: '%V'", &value[n]);
            return NGX_CONF_ERROR;
        }
    }

    all = (value[n].len == 3 && ngx_strcmp(value[n].data, "all") == 0);

    if (!all) {

        rc = ngx_ptocidr(&value[n], &cidr);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    switch (cidr.family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
    case 0: /* all */

        if (ascf->rules6 == NULL) {
            ascf->rules6 = ngx_array_create(cf->pool, 4,
                                            sizeof(ngx_rtmp_access_rule6_t));
            if (ascf->rules6 == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule6 = ngx_array_push(ascf->rules6);
        if (rule6 == NULL) {
            return NGX_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
        rule6->flags = flags;

        if (!all) {
            break;
        }

        /* "all" passes through */
#endif

    default: /* AF_INET */

        if (ascf->rules == NULL) {
            ascf->rules = ngx_array_create(cf->pool, 4,
                    sizeof(ngx_rtmp_access_rule_t));
            if (ascf->rules == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule = ngx_array_push(ascf->rules);
        if (rule == NULL) {
            return NGX_CONF_ERROR;
        }

        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
        rule->flags = flags;
    }

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_rtmp_access_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    if (ngx_rtmp_access(s, NGX_RTMP_ACCESS_PUBLISH) != NGX_OK) {
        return NGX_ERROR;
    }

    return next_publish(s, v);
}


static ngx_int_t 
ngx_rtmp_access_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    if (ngx_rtmp_access(s, NGX_RTMP_ACCESS_PLAY) != NGX_OK) {
        return NGX_ERROR;
    }

    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_access_postconfiguration(ngx_conf_t *cf)
{
    /* chain handlers */
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_access_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_access_play;

    return NGX_OK;
}
