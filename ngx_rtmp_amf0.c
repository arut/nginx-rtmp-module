/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp_amf0.h"
#include "ngx_rtmp.h"
#include <string.h>

static inline void*
ngx_rtmp_amf0_reverse_copy(void *dst, void* src, size_t len)
{
    size_t  k;

    if (dst == NULL || src == NULL) {
        return NULL;
    }

    for(k = 0; k < len; ++k) {
        ((u_char*)dst)[k] = ((u_char*)src)[len - 1 - k];
    }

    return dst;
}

#define NGX_RTMP_AMF0_DEBUG_SIZE 16

#ifdef NGX_DEBUG
static void
ngx_rtmp_amf0_debug(const char* op, ngx_log_t *log, u_char *p, size_t n)
{
    u_char          hstr[3 * NGX_RTMP_AMF0_DEBUG_SIZE + 1];
    u_char          str[NGX_RTMP_AMF0_DEBUG_SIZE + 1];
    u_char         *hp, *sp;
    static u_char   hex[] = "0123456789ABCDEF";
    size_t          i;

    hp = hstr;
    sp = str;

    for(i = 0; i < n && i < NGX_RTMP_AMF0_DEBUG_SIZE; ++i) {
        *hp++ = ' ';
        *hp++ = hex[(*p & 0xf0) >> 4];
        *hp++ = hex[*p & 0x0f];
        *sp++ = (*p >= 0x20 && *p <= 0x7e) ?
            *p : (u_char)'?';
        ++p;
    }
    *hp = *sp = '\0';

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, log, 0,
            "AMF0 %s (%d)%s '%s'", op, n, hstr, str);
}
#endif

static ngx_int_t
ngx_rtmp_amf0_get(ngx_rtmp_amf0_ctx_t *ctx, void *p, size_t n)
{
    ngx_buf_t      *b;
    size_t          size;
    ngx_chain_t   **l;
#ifdef NGX_DEBUG
    void           *op = p;
#endif

    if (!n)
        return NGX_OK;

    for(l = ctx->link; *l; l = &(*l)->next) {

        b = (*l)->buf;

        if (b->last > n + b->pos) {
            if (p) {
                p = ngx_cpymem(p, b->pos, n);
            }
            b->pos += n;
            
#ifdef NGX_DEBUG
            ngx_rtmp_amf0_debug("read", ctx->log, (u_char*)op, n);
#endif

            return NGX_OK;
        }

        size = b->last - b->pos;

        if (p)
            p = ngx_cpymem(p, b->pos, size);

        n -= size;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ctx->log, 0,
            "AMF0 read eof (%d)", n);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_amf0_put(ngx_rtmp_amf0_ctx_t *ctx, void *p, size_t n)
{
    ngx_buf_t       *b;
    size_t          size;
    ngx_chain_t    *l, *ln;

#ifdef NGX_DEBUG
    ngx_rtmp_amf0_debug("write", ctx->log, (u_char*)p, n);
#endif

    l = ctx->link;

    while(n) {
        b = l ? l->buf : NULL;

        if (b == NULL || b->last == b->end) {

            ln = ctx->alloc(ctx->arg);
            if (ln == NULL) {
                return NGX_ERROR;
            }

            if (l == NULL) {
                l = ln;
                ctx->first = l;
            } else {
                l->next = ln;
                l = ln;
            }

            b = l->buf;
            b->pos = b->last = b->start;
        }

        size = b->end - b->last;

        if (size >= n) {
            b->last = ngx_cpymem(b->last, p, n);
            return NGX_OK;
        }

        b->last = ngx_cpymem(b->last, p, size);
        p = (u_char*)p + size;
        n -= size;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_amf0_read_object(ngx_rtmp_amf0_ctx_t *ctx, ngx_rtmp_amf0_elt_t *elts, 
        size_t nelts)
{
    uint8_t                 type;
    uint16_t                len;
    size_t                  n, namelen, maxlen;
    ngx_int_t               rc;

    maxlen = 0;
    for(n = 0; n < nelts; ++n) {
        namelen = strlen(elts[n].name);
        if (namelen > maxlen)
            maxlen = namelen;
    }

    for(;;) {

        char    name[maxlen + 1];

        /* read key */
        if (ngx_rtmp_amf0_get(ctx, &len, sizeof(len)) != NGX_OK)
            return NGX_ERROR;

        if (!len)
            break;

        if (len <= maxlen) {
            rc = ngx_rtmp_amf0_get(ctx, name, len);
            name[len] = 0;

        } else {
            rc = ngx_rtmp_amf0_get(ctx, name, maxlen);
            if (rc != NGX_OK)
                return NGX_ERROR;
            name[maxlen] = 0;
            rc = ngx_rtmp_amf0_get(ctx, 0, len - maxlen);
        }

        if (rc != NGX_OK)
            return NGX_ERROR;

        /* TODO: if we require array to be sorted on name
         * then we could be able to use binary search */
        for(n = 0; n < nelts && strcmp(name, elts[n].name); ++n);

        if (ngx_rtmp_amf0_read(ctx, n < nelts ? &elts[n] : NULL, 1) != NGX_OK)
            return NGX_ERROR;
    }

    if (ngx_rtmp_amf0_get(ctx, &type, 1) != NGX_OK
        || type != NGX_RTMP_AMF0_END)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#define NGX_RTMP_AMF0_TILL_END_FLAG ((size_t)1 << (sizeof(size_t) * 8 - 1))

ngx_int_t 
ngx_rtmp_amf0_read(ngx_rtmp_amf0_ctx_t *ctx, ngx_rtmp_amf0_elt_t *elts, size_t nelts)
{
    void                   *data;
    uint8_t                 type;
    size_t                  n;
    uint16_t                len;
    ngx_int_t               rc;
    int                     till_end;
    u_char                  buf[8];

    if (nelts & NGX_RTMP_AMF0_TILL_END_FLAG) {
        till_end = 1;
        nelts = nelts & ~NGX_RTMP_AMF0_TILL_END_FLAG;
    } else {
        till_end = 0;
    }

    for(n = 0; till_end || n < nelts; ++n) {

        if (ngx_rtmp_amf0_get(ctx, &type, sizeof(type)) != NGX_OK)
            return NGX_ERROR;

        data = (n >= nelts || elts == NULL || elts->type != type)
            ? NULL
            : elts->data;

        switch(type) {
            case NGX_RTMP_AMF0_NUMBER:
                if (ngx_rtmp_amf0_get(ctx, buf, 8) != NGX_OK) {
                    return NGX_ERROR;
                }
                ngx_rtmp_amf0_reverse_copy(data, buf, 0);
                break;

            case NGX_RTMP_AMF0_BOOLEAN:
                if (ngx_rtmp_amf0_get(ctx, data, 1) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_STRING:
                if (ngx_rtmp_amf0_get(ctx, buf, 2) != NGX_OK) {
                    return NGX_ERROR;
                }
                ngx_rtmp_amf0_reverse_copy(&len, buf, 2);

                if (data == NULL) {
                    rc = ngx_rtmp_amf0_get(ctx, data, len);

                } else if (elts->len <= len) {
                    rc = ngx_rtmp_amf0_get(ctx, data, elts->len - 1);
                    if (rc != NGX_OK)
                        return NGX_ERROR;
                    ((char*)data)[elts->len - 1] = 0;
                    rc = ngx_rtmp_amf0_get(ctx, NULL, len - elts->len + 1);

                } else {
                    rc = ngx_rtmp_amf0_get(ctx, data, len);
                    ((char*)data)[len] = 0;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                break;

            case NGX_RTMP_AMF0_NULL:
                break;

            case NGX_RTMP_AMF0_OBJECT:
                if (ngx_rtmp_amf0_read_object(ctx, data, 
                        elts ? elts->len / sizeof(ngx_rtmp_amf0_elt_t) : 0
                    ) != NGX_OK) 
                {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_ARRAY:
                if (ngx_rtmp_amf0_read(ctx, data, 
                        elts ? (elts->len / sizeof(ngx_rtmp_amf0_elt_t))
                            | NGX_RTMP_AMF0_TILL_END_FLAG : 0
                    ) != NGX_OK) 
                {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_END:
                return NGX_OK;

            default:
                return NGX_ERROR;
        }

        if (elts) {
            ++elts;
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_rtmp_amf0_write_object(ngx_rtmp_amf0_ctx_t *ctx,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts)
{
    uint16_t                len, len_sb;
    size_t                  n;
    char                   *name;
    u_char                  buf[2];

    for(n = 0; n < nelts; ++n) {

        name = elts[n].name;
        len_sb = len = strlen(name);

        if (ngx_rtmp_amf0_put(ctx, 
                    ngx_rtmp_amf0_reverse_copy(buf, 
                        &len, 2), 2) != NGX_OK) 
        {
            return NGX_ERROR;
        }

        if (ngx_rtmp_amf0_put(ctx, name, len) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_rtmp_amf0_write(ctx, &elts[n], 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    len = 0;

    if (ngx_rtmp_amf0_put(ctx, "\00\00", 2) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_rtmp_amf0_write(ngx_rtmp_amf0_ctx_t *ctx,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts)
{
    size_t                  n;
    uint8_t                 type;
    void                   *data;
    uint16_t                len;
    u_char                  buf[8];

    for(n = 0; n < nelts; ++n) {

        type = elts[n].type;
        data = elts[n].data;
        len  = elts[n].len;

        if (ngx_rtmp_amf0_put(ctx, &type, sizeof(type)) != NGX_OK)
            return NGX_ERROR;

        switch(type) {
            case NGX_RTMP_AMF0_NUMBER:
                if (ngx_rtmp_amf0_put(ctx, 
                            ngx_rtmp_amf0_reverse_copy(buf, 
                                data, 8), 8) != NGX_OK) 
                {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_BOOLEAN:
                if (ngx_rtmp_amf0_put(ctx, data, 1) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_STRING:
                if (ngx_rtmp_amf0_put(ctx, 
                            ngx_rtmp_amf0_reverse_copy(buf, 
                                &len, 2), 2) != NGX_OK) 
                {
                    return NGX_ERROR;
                }

                if (ngx_rtmp_amf0_put(ctx, data, len) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_NULL:
                break;

            case NGX_RTMP_AMF0_OBJECT:
                type = NGX_RTMP_AMF0_END;
                if (ngx_rtmp_amf0_write_object(ctx, data,
                        elts[n].len / sizeof(ngx_rtmp_amf0_elt_t)) != NGX_OK
                    || ngx_rtmp_amf0_put(ctx, &type, 
                        sizeof(type)) != NGX_OK)
                {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_ARRAY:
                type = NGX_RTMP_AMF0_END;
                if (ngx_rtmp_amf0_write(ctx, data, 
                        elts[n].len / sizeof(ngx_rtmp_amf0_elt_t)) != NGX_OK
                    || ngx_rtmp_amf0_put(ctx, &type, 
                        sizeof(type)) != NGX_OK)
                {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_END:
                return NGX_OK;

            default:
                return NGX_ERROR;
        }
    }

    return NGX_OK;
}

