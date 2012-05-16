/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>


static void ngx_rtmp_handshake_send(ngx_event_t *wev);
static void ngx_rtmp_handshake_recv(ngx_event_t *rev);
static void ngx_rtmp_handshake_done(ngx_rtmp_session_t *s);


/* Handshake keys */
static u_char 
ngx_rtmp_server_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
    'S', 'e', 'r', 'v', 'e', 'r', ' ', 
    '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 
    0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};


static u_char 
ngx_rtmp_client_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ', 
    '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 
    0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};


static const u_char
ngx_rtmp_server_version[4] = {
    0x0D, 0x0E, 0x0A, 0x0D
};


static const u_char
ngx_rtmp_client_version[4] = {
    0x0C, 0x00, 0x0D, 0x0E
};


#define NGX_RTMP_HANDSHAKE_KEYLEN                   SHA256_DIGEST_LENGTH 
#define NGX_RTMP_HANDSHAKE_BUFSIZE                  1537


#define NGX_RTMP_HANDSHAKE_SERVER_RECV_CHALLENGE    1
#define NGX_RTMP_HANDSHAKE_SERVER_SEND_CHALLENGE    2
#define NGX_RTMP_HANDSHAKE_SERVER_SEND_RESPONSE     3
#define NGX_RTMP_HANDSHAKE_SERVER_RECV_RESPONSE     4
#define NGX_RTMP_HANDSHAKE_SERVER_DONE              5


#define NGX_RTMP_HANDSHAKE_CLIENT_SEND_CHALLENGE    6
#define NGX_RTMP_HANDSHAKE_CLIENT_RECV_CHALLENGE    7
#define NGX_RTMP_HANDSHAKE_CLIENT_RECV_RESPONSE     8
#define NGX_RTMP_HANDSHAKE_CLIENT_SEND_RESPONSE     9
#define NGX_RTMP_HANDSHAKE_CLIENT_DONE              10


static ngx_str_t            ngx_rtmp_server_full_key 
    = { sizeof(ngx_rtmp_server_key), ngx_rtmp_server_key };
static ngx_str_t            ngx_rtmp_server_partial_key
    = { 36, ngx_rtmp_server_key };

static ngx_str_t            ngx_rtmp_client_partial_key
    = { 30, ngx_rtmp_client_key };


static ngx_int_t
ngx_rtmp_make_digest(ngx_str_t *key, ngx_buf_t *src, 
        u_char *skip, u_char *dst, ngx_log_t *log)
{
    HMAC_CTX                hmac;
    unsigned int            len;

    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, key->data, key->len, EVP_sha256(), NULL);

    if (skip && src->pos <= skip && skip <= src->last) {
        if (skip != src->pos) {
            HMAC_Update(&hmac, src->pos, skip - src->pos);
        }
        if (src->last != skip + NGX_RTMP_HANDSHAKE_KEYLEN) {
            HMAC_Update(&hmac, skip + NGX_RTMP_HANDSHAKE_KEYLEN, 
                    src->last - skip - NGX_RTMP_HANDSHAKE_KEYLEN);
        }
    } else {
        HMAC_Update(&hmac, src->pos, src->last - src->pos);
    }

    HMAC_Final(&hmac, dst, &len);
    HMAC_CTX_cleanup(&hmac);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_find_digest(ngx_buf_t *b, ngx_str_t *key, size_t base, ngx_log_t *log)
{
    size_t                  n, offs;
    u_char                  digest[NGX_RTMP_HANDSHAKE_KEYLEN];
    u_char                 *p;

    offs = 0;
    for (n = 0; n < 4; ++n) {
        offs += b->pos[base + n];
    }
    offs = (offs % 728) + base + 4;
    p = b->pos + offs;

    if (ngx_rtmp_make_digest(key, b, p, digest, log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_memcmp(digest, p, NGX_RTMP_HANDSHAKE_KEYLEN) == 0) {
        return offs;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_write_digest(ngx_buf_t *b, ngx_str_t *key, size_t base, 
        ngx_log_t *log)
{
    size_t                  n, offs;
    u_char                 *p;

    offs = 0;
    for (n = 8; n < 12; ++n) {
        offs += b->pos[base + n];
    }
    offs = (offs % 728) + base + 12;
    p = b->pos + offs;

    if (ngx_rtmp_make_digest(key, b, p, p, log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_rtmp_fill_random_buffer(ngx_buf_t *b)
{
    for (; b->last != b->end; ++b->last) {
        *b->last = rand();
    }
}


static ngx_buf_t *
ngx_rtmp_alloc_handshake_buffer(ngx_rtmp_session_t *s, int short_buf)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *cl;
    ngx_buf_t                  *b;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: allocating %sbuffer",
            short_buf ? "short " : "");

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (cscf->free_hs) {
        cl = cscf->free_hs;
        b = cl->buf;
        cscf->free_hs = cl->next;
        ngx_free_chain(cscf->pool, cl);

    } else {
        b = ngx_pcalloc(cscf->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NULL;
        }
        b->memory = 1;
        b->start = ngx_pcalloc(cscf->pool, NGX_RTMP_HANDSHAKE_BUFSIZE);
        if (b->start == NULL) {
            return NULL;
        }
        b->end = b->start + NGX_RTMP_HANDSHAKE_BUFSIZE;
    }

    if (short_buf) {
        b->pos = b->last = b->start + 1;
    } else {
        b->pos = b->last = b->start;
    }

    return b;
}


static ngx_int_t
ngx_rtmp_free_handshake_buffer(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *cl;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    cl = ngx_alloc_chain_link(cscf->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    cl->buf = b;
    cl->next = cscf->free_hs;
    cscf->free_hs = cl;
    return NGX_OK;
}


void
ngx_rtmp_free_handshake_buffers(ngx_rtmp_session_t *s)
{
    size_t          n;

    for (n = 0; n < sizeof(s->hs_bufs) / sizeof(s->hs_bufs[0]); ++n) {
        if (s->hs_bufs[n]) {
            ngx_rtmp_free_handshake_buffer(s, s->hs_bufs[n]);
            s->hs_bufs[n] = NULL;
        }
    }
}


static ngx_int_t
ngx_rtmp_old_handshake_response(ngx_rtmp_session_t *s)
{
    ngx_buf_t              *b;
    u_char                 *src;
    size_t                  len;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "handshake: old-style handshake");

    src = s->hs_bufs[0]->pos + 8;
    len = s->hs_bufs[0]->last - src;

    b = s->hs_bufs[1];
    *b->last++ = '\x03';
    b->last = ngx_rtmp_rcpymem(b->last, &s->epoch, 4);
    ngx_memzero(b->last, 4);
    b->last = ngx_cpymem(b->last + 4, src, len);

    b = s->hs_bufs[2];
    b->last = ngx_rtmp_rcpymem(b->last, &s->peer_epoch, 4);
    ngx_memzero(b->last, 4);
    b->last = ngx_cpymem(b->last + 4, src, len);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_handshake_response(ngx_rtmp_session_t *s)
{
    u_char                 *p;
    ngx_buf_t              *b;
    ngx_int_t               offs;
    u_char                  digest[NGX_RTMP_HANDSHAKE_KEYLEN];
    ngx_str_t               key;

    /* read input buffer */
    b = s->hs_bufs[0];
    if (*b->pos != '\x03') {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "handshake: unexpected RTMP version: %i", (ngx_int_t)*b->pos);
        return NGX_ERROR;
    }
    ++b->pos;
    ngx_rtmp_rmemcpy(&s->peer_epoch, b->pos, 4);

    p = b->pos + 4;
    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: client version=%i.%i.%i.%i epoch=%uD",
            (ngx_int_t)p[3], (ngx_int_t)p[2],
            (ngx_int_t)p[1], (ngx_int_t)p[0],
            s->peer_epoch);
    if (*(uint32_t *)p == 0) {
        return ngx_rtmp_old_handshake_response(s);
    }

    offs = ngx_rtmp_find_digest(b, &ngx_rtmp_client_partial_key, 
            772, s->connection->log);
    if (offs == NGX_ERROR) {
        offs = ngx_rtmp_find_digest(b, &ngx_rtmp_client_partial_key,
                8, s->connection->log);
    }
    if (offs == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "handshake: digest not found");
        return ngx_rtmp_old_handshake_response(s);
    }
    b->pos += offs;
    b->last = b->pos + NGX_RTMP_HANDSHAKE_KEYLEN;
    if (ngx_rtmp_make_digest(&ngx_rtmp_server_full_key, b,
            NULL, digest, s->connection->log) != NGX_OK)
    {
        return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: digest found at pos=%i", offs);

    /* create first output buffer */
    b = s->hs_bufs[1];
    *b->last++ = '\x03';
    b->last = ngx_rtmp_rcpymem(b->last, &s->epoch, 4);
    b->last = ngx_cpymem(b->last, ngx_rtmp_server_version, 4);
    ngx_rtmp_fill_random_buffer(b);
    ++b->pos;
    if (ngx_rtmp_write_digest(b, &ngx_rtmp_server_partial_key, 
                0, s->connection->log) != NGX_OK) 
    {
        return NGX_ERROR;
    }
    --b->pos;

    /* create second output buffer */
    b = s->hs_bufs[2];
    ngx_rtmp_fill_random_buffer(b);
    key.data = digest;
    key.len = sizeof(digest);
    p = b->last - key.len;
    if (ngx_rtmp_make_digest(&key, b, p, p, s->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_handshake_client_response(ngx_rtmp_session_t *s)
{
    /*TODO: implement good client response generation
     * to make it possible relaying data from/to FMS.
     *
     * This module as server ignores the last response
     * from client. */

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_handshake_make_client_request(ngx_rtmp_session_t *s)
{
    ngx_buf_t          *b;

    b = s->hs_bufs[0];
    *b->last++ = '\x03';
    b->last = ngx_rtmp_rcpymem(b->last, &s->epoch, 4);
    b->last = ngx_rtmp_rcpymem(b->last, ngx_rtmp_client_version, 4);
    ngx_rtmp_fill_random_buffer(b);
    ++b->pos;
    if (ngx_rtmp_write_digest(b, &ngx_rtmp_client_partial_key,
                0, s->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }
    --b->pos;
    
    return NGX_OK;
}


static void
ngx_rtmp_handshake_done(ngx_rtmp_session_t *s)
{
    ngx_rtmp_free_handshake_buffers(s);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: done");

    if (ngx_rtmp_fire_event(s, NGX_RTMP_HANDSHAKE_DONE, 
                NULL, NULL) != NGX_OK) 
    {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_rtmp_cycle(s);
}


static void
ngx_rtmp_handshake_recv(ngx_event_t *rev)
{
    ssize_t                     n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_buf_t                  *b;

    c = rev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, 
                "handshake: client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = s->hs_buf;

    while (b->last != b->end) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, s->timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        b->last += n;
    }

    if (rev->active) {
        ngx_del_event(rev, NGX_READ_EVENT, 0);
    }

    ++s->hs_stage;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: stage %ui", s->hs_stage);

    switch (s->hs_stage) {
        case NGX_RTMP_HANDSHAKE_SERVER_SEND_CHALLENGE:
            s->hs_bufs[1] = ngx_rtmp_alloc_handshake_buffer(s, 0);
            s->hs_bufs[2] = ngx_rtmp_alloc_handshake_buffer(s, 1);
            if (ngx_rtmp_handshake_response(s) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0, 
                        "handshake: response error");
                ngx_rtmp_finalize_session(s);
                return;
            }
            s->hs_buf = s->hs_bufs[1];
            ngx_rtmp_handshake_send(c->write);
            break;

        case NGX_RTMP_HANDSHAKE_SERVER_DONE:
            ngx_rtmp_handshake_done(s);
            break;

        case NGX_RTMP_HANDSHAKE_CLIENT_RECV_RESPONSE:
            s->hs_bufs[2] = ngx_rtmp_alloc_handshake_buffer(s, 1);
            s->hs_buf = s->hs_bufs[2];
            ngx_rtmp_handshake_recv(c->read);
            break;

        case NGX_RTMP_HANDSHAKE_CLIENT_SEND_RESPONSE:
            if (ngx_rtmp_handshake_client_response(s) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0, 
                        "handshake: client response error");
                ngx_rtmp_finalize_session(s);
                return;
            }
            s->hs_buf = s->hs_bufs[2];
            ngx_rtmp_handshake_send(c->write);
            break;
    }
}


static void
ngx_rtmp_handshake_send(ngx_event_t *wev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_buf_t                  *b;

    c = wev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, 
                "handshake: client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    b = s->hs_buf;

    while(b->pos != b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_ERROR) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        b->pos += n;
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ++s->hs_stage;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: stage %ui", s->hs_stage);

    switch (s->hs_stage) {
        case NGX_RTMP_HANDSHAKE_SERVER_SEND_RESPONSE:
            s->hs_buf = s->hs_bufs[2];
            ngx_rtmp_handshake_send(wev);
            break;

        case NGX_RTMP_HANDSHAKE_SERVER_RECV_RESPONSE:
            s->hs_buf = s->hs_bufs[0];
            s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start + 1;
            ngx_rtmp_handshake_recv(c->read);
            break;

        case NGX_RTMP_HANDSHAKE_CLIENT_RECV_CHALLENGE:
            s->hs_bufs[1] = ngx_rtmp_alloc_handshake_buffer(s, 0);
            s->hs_buf = s->hs_bufs[1];
            ngx_rtmp_handshake_recv(c->read);
            break;

        case NGX_RTMP_HANDSHAKE_CLIENT_DONE:
            ngx_rtmp_handshake_done(s);
            break;
    }
}


void
ngx_rtmp_handshake(ngx_rtmp_session_t *s)
{
    ngx_connection_t           *c;

    c = s->connection;
    c->read->handler =  ngx_rtmp_handshake_recv;
    c->write->handler = ngx_rtmp_handshake_send;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: start server handshake");

    s->hs_bufs[0] = ngx_rtmp_alloc_handshake_buffer(s, 0);
    s->hs_buf = s->hs_bufs[0];
    s->hs_stage = NGX_RTMP_HANDSHAKE_SERVER_RECV_CHALLENGE;

    ngx_rtmp_handshake_recv(c->read);
}


void
ngx_rtmp_client_handshake(ngx_rtmp_session_t *s)
{
    ngx_connection_t           *c;

    c = s->connection;
    c->read->handler =  ngx_rtmp_handshake_recv;
    c->write->handler = ngx_rtmp_handshake_send;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "handshake: start client handshake");

    s->hs_bufs[0] = ngx_rtmp_alloc_handshake_buffer(s, 0);
    s->hs_buf = s->hs_bufs[0];
    s->hs_stage = NGX_RTMP_HANDSHAKE_CLIENT_SEND_CHALLENGE;

    if (ngx_rtmp_handshake_make_client_request(s) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_rtmp_handshake_send(c->write);
}

