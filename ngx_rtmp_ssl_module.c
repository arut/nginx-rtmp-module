
/*
 * RTMPS supporting module
 * Copyright (C) Ilya Panfilov
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_rtmp_ssl_module.h"

#define NGX_RTMPS_DEFAULT_CIPHERS       "HIGH:MEDIUM:!aNULL:!eNULL"
#define NGX_RTMPS_DEFAULT_ECDH_CURVE    "prime256v1"
#define NGX_RTMPS_DEFAULT_PROTOCOLS     NGX_SSL_SSLv2 \
                                        | NGX_SSL_SSLv3 \
                                        | NGX_SSL_TLSv1 \
                                        | NGX_SSL_TLSv1_1 \
                                        | NGX_SSL_TLSv1_2


static void *ngx_rtmp_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

void ngx_rtmp_ssl_handshake(ngx_rtmp_session_t *s);
static void ngx_rtmp_ssl_handshake_handler(ngx_connection_t *c);


static ngx_conf_bitmask_t  ngx_rtmp_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_rtmp_ssl_commands[] = {
    { ngx_string("ssl_protocols"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, protocols),
      &ngx_rtmp_ssl_protocols },

    { ngx_string("ssl_certificate"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("ssl_password_file"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, password_file),
      NULL },

    { ngx_string("ssl_ciphers"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, dhparam),
      NULL },

    { ngx_string("ssl_ecdh_curve"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_ssl_srv_conf_t, ecdh_curve),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_ssl_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_ssl_create_srv_conf,           /* create server configuration */
    ngx_rtmp_ssl_merge_srv_conf,            /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_ssl_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_ssl_module_ctx,             /* module context */
    ngx_rtmp_ssl_commands,                /* module directives */
    NGX_RTMP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_rtmp_ssl_enable(ngx_conf_t *cf)
{
    ngx_rtmp_ssl_srv_conf_t *sscf;

    sscf = ngx_rtmp_conf_get_module_srv_conf(cf, ngx_rtmp_ssl_module);
    sscf->enable = 1;

    return NGX_OK;
}


static void *
ngx_rtmp_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_ssl_srv_conf_t *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->prefer_server_ciphers = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_rtmp_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_ssl_srv_conf_t *prev = parent;
    ngx_rtmp_ssl_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;
    ngx_array_t         *passwords = NULL;

    conf->ssl.log = cf->log;

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    if (conf->certificate.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Missing ssl_certificate");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    if (conf->certificate_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Missing ssl_certificate_key");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                                 NGX_CONF_BITMASK_SET
                                 |NGX_RTMPS_DEFAULT_PROTOCOLS);

    ngx_conf_merge_str_value(conf->password_file, prev->password_file, "");

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                             NGX_RTMPS_DEFAULT_ECDH_CURVE);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers,
                             NGX_RTMPS_DEFAULT_CIPHERS);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (conf->password_file.len > 0) {
        passwords = ngx_ssl_read_password_file(cf, &conf->password_file);
        if (passwords == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_certificate(cf, &conf->ssl, &conf->certificate,
                            &conf->certificate_key, passwords)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_set_cipher_list(conf->ssl.ctx,
                                (const char *) conf->ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(%V) failed", &conf->ciphers);
        return NGX_CONF_ERROR;
    }

    if (conf->prefer_server_ciphers) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);

    return NGX_CONF_OK;
}


void
ngx_rtmp_ssl_handshake(ngx_rtmp_session_t *s)
{
    ngx_connection_t  *c;
    ngx_rtmp_ssl_srv_conf_t       *sscf;

    c = s->connection;

    sscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_ssl_module);

    if (ngx_ssl_create_connection(&sscf->ssl, c, 0) != NGX_OK)
    {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_rtmp_ssl_handshake_handler(c);
    return;
}


static void
ngx_rtmp_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_rtmp_session_t *s;
    ngx_event_t        *rev;
    ngx_int_t          rc;

    s = c->data;

    if (c->ssl->handshaked) {
        ngx_rtmp_handshake(s);
        return;
    }

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "SSL handshake timed out");
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (c->read->error || c->write->error || c->error) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "SSL handshake failed: c%d w%d r%d",
        c->error, c->write->error, c->read->error);
        ngx_rtmp_finalize_session(s);
        return;
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {

        rev = c->read;

        if (!rev->timer_set) {
            ngx_add_timer(rev, s->timeout);
        }

        c->ssl->handler = ngx_rtmp_ssl_handshake_handler;
        return;
    }

    if (rc == NGX_OK) {
        ngx_rtmp_handshake(s);
        return;
    }

    ngx_rtmp_finalize_session(s);
    return;
}
