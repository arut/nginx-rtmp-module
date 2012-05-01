/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#ifdef NGX_SSL
#include <openssl/hmac.h>
#include <openssl/sha.h>
#endif


/* Handshake keys */
static const u_char 
ngx_rtmp_server_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
    'S', 'e', 'r', 'v', 'e', 'r', ' ', 
    '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 
    0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};


static const u_char 
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
    0x0A, 0x00, 0x00, 0x00  /* TODO */
};


#define NGX_RTMP_KEYLEN                 SHA256_DIGEST_LENGTH 
#define NGX_RTMP_HANDSHAKE_BUFSIZE      1537


static ngx_str_t            ngx_rtmp_server_full_key 
    = { ngx_rtmp_server_key, sizeof(ngx_rtmp_server_key) };
static ngx_str_t            ngx_rtmp_server_partial_key;
    = { ngx_rtmp_server_key, 36 };

static ngx_str_t            ngx_rtmp_client_full_key
    = { ngx_rtmp_client_key, sizeof(ngx_rtmp_client_key) };
static ngx_str_t            ngx_rtmp_client_partial_key
    = { ngx_rtmp_client_key, 30 };


static ngx_int_t
ngx_rtmp_make_digest(ngx_str_t *key, ngx_buf_t *src, 
        u_char *skip, u_char *dst, ngx_log_t *log)
{
#ifdef NGX_SSL
    HMAC_CTX                hmac;
    unsigned int            len; /* TODO */

    if (HMAC_Init_ex(&hmac, key->data, key->len, 
                EVP_sha256, NULL) == 0) 
    {
        ngx_log_error(NGX_LOG_INFO, log, 0, "HMAC_Init_ex error");
        return NGX_ERROR;
    }

    if (skip && src->pos <= skip && skip <= src->last) {
        if (skip != src->pos
                && HMAC_Update(&hmac, src->pos, skip - src->pos) == 0) 
        {
            ngx_log_error(NGX_LOG_INFO, log, 0, "HMAC_Update error");
            return NGX_ERROR;
        }
        if (src->last != skip + NGX_RTMP_KEYLEN
                && HMAC_Update(&hmac, skip + NGX_RTMP_KEYLEN, 
                    src->last - skip - NGX_RTMP_KEYLEN) == 0) 
        {
            ngx_log_error(NGX_LOG_INFO, log, 0, "HMAC_Update error");
            return NGX_ERROR;
        }
    } else if (HMAC_Update(&hmac, src->pos, src->last - src->pos) == 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0, "HMAC_Update error");
        return NGX_ERROR;
    }

    if (HMAC_Final(&hmac, dst, &len) == 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0, "HMAC_Final error");
        return NGX_ERROR;
    }

    /* TODO: free? */

    return NGX_OK;

#else /* NGX_SSL */
    return NGX_ERROR;
#endif
}


static ngx_int_t
ngx_rtmp_get_digest(ngx_buf_t *b, size_t base, ngx_log_t *log)
{
    size_t                  n, offs;
    u_char                  digest[NGX_RTMP_KEYLEN];
    u_char                 *p;

    offs = 0;
    for (n = 0; n < 4; ++n) {
        offs += b->pos[base + n];
    }
    offs = (offs % 728) + base + 4;
    p = b->pos + offs;

    if (ngx_rtmp_make_digest(&ngx_rtmp_client_partial_key, 
                b, p, digest, log) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_memcmp(digest, p, NGX_RTMP_KEYLEN) == 0) {
        return offs;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_put_digest(ngx_buf_t *b, size_t base, ngx_log_t *log)
{
    size_t                  n, offs;

    offs = 0;
    for (n = 0; n < 4; ++n) {
        offs += b->pos[base + n];
    }
    offs = (offs % 728) + base + 4;
    p = b->pos + offs;

    if (ngx_rtmp_make_digest(&ngx_rtmp_server_partial_key,
                b, p, p, log) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_rtmp_make_random_buffer(ngx_buf_t *b)
{
    u_char                 *p;

    for (p = b->pos; p != b->last; ++p) {
        *p = rand();
    }
}


static ngx_buf_t *
ngx_rtmp_alloc_handshake_buffer(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *cl;
    ngx_buf_t                  *b;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf->free_hs) {
        cl = cscf->free_hs;
        b = cl->buf;
        cscf->free_hs = cl->next;
        ngx_free_chain(cacf->pool, cl);
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

    b->pos = b->last = b->start;
    return b;
}


static ngx_int_t
ngx_rtmp_free_handshake_buffer(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *cl;
    ngx_buf_t                  *b;

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


static ngx_int_t
ngx_rtmp_handshake_response(ngx_rtmp_session_t *s)
{
    u_char                 *p, *pp;
    ngx_buf_t               b;
    ngx_int_t               offs;
    u_char                  digest[NGX_RTMP_KEYLEN];
    ngx_str_t               key;


    s->hs_out1 = ngx_rtmp_alloc_handshake_buffer(s);
    s->hs_out1->last = s->hs_out1.end;
    s->hs_out2 = ngx_rtmp_alloc_handshake_buffer(s);
    s->hs_out1->last = s->hs_out2.end - 1;


    /* read input buffer */
    b = *s->hs_in;
    p = b->pos;
    if (*p != '\x03') {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "Unexpected RTMP version: %i", (int)*p);
        return NGX_ERROR;
    }
    ++p;
    pp = (u_char *)&s->peer_epoch + 3;
    *pp-- = *p++;
    *pp-- = *p++;
    *pp-- = *p++;
    *pp-- = *p++;
    if (
#ifndef NGX_SSL
            1 ||
#endif
            *(uint32_t *)p == 0) 
    {
        /*TODO*/
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                "RTMP epoch=%uD", s->peer_epoch);
        ngx_memzero(p, 4);
        p += 4;
        ngx_memcpy(p, s->hs_in->pos + 9, s->hs_out1->last - p);
        p = s->hs_out;
        ngx_memzero(p, 8);
        p += 8;
        ngx_memcpy(pp, s->hs_in->pos + 9, s->hs_out2->last - p);
        return NGX_OK;
    }
    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP client version=%i.%i.%i.%i epoch=%uD",
            (ngx_int_t)p[0], (ngx_int_t)p[1],
            (ngx_int_t)p[2], (ngx_int_t)p[3],
            s->peer_epoch);
    p += 4;
    b.pos = p;
    offs = ngx_rtmp_get_digest(&b, 764, s->connection->log);
    if (offs == NGX_ERROR) {
        offs = ngx_rtmp_get_digest(&b, 0, s->connection->log);
    }
    if (offs == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "RTMP digest not found");
        return NGX_ERROR;
    }


    /* create first output buffer */
    b = *s->hs_out1;
    p = b.pos;
    *p++ = '\x03';
    pp = (u_char *)&s->epoch + 3;
    *p++ = *pp--;
    *p++ = *pp--;
    *p++ = *pp--;
    *p++ = *pp--;
    p = ngx_cpymem(p, ngx_rtmp_server_version, 4);
    b.pos = p;
    ngx_rtmp_make_random_buffer(&b);
    if (ngx_rtmp_put_digest(&b, 0, s->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }


    /* create second output buffer */
    b = *s->hs_out2;
    p = b.pos;
    p = ngx_cpymem(b, s->hs_out1->pos + 1, 8);
    ngx_rtmp_make_random_buffer(&b);
    if (ngx_rtmp_make_digest(&ngx_rtmp_server_full_key, &b,
            NULL, digest, s->connection->log) != NGX_OK)
    {
        return NGX_ERROR;
    }
    key.data = digest;
    key.len = sizeof(digest);
    p = b.last - key.len;
    if (ngx_rtmp_make_digest(&key, &b, p, p, s->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_response(ngx_rtmp_session_t *s)
{
    s->hs_in = ngx_rtmp_alloc_handshake_buffer(s);

    return ngx_rtmp_handshake_recv(s->connection->read);
}

