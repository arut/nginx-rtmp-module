/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

#include "ngx_rtmp_amf0.h"
#include "ngx_rtmp.h"
#include <string.h>

#define NGX_RTMP_AMF0_SV(x, y) \
    (x) ^= (y); (y) ^= (x); (x) ^= (y)

#define NGX_RTMP_AMF0_SB(x) \
    NGX_RTMP_AMF0_SV(*(uint8_t*)(&x), *((uint8_t*)(&x) + 1))

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

#define NGX_RTMP_AMF0_DEBUG_SIZE 16
#ifdef NGX_DEBUG
            {
                u_char          hstr[3 * NGX_RTMP_AMF0_DEBUG_SIZE + 1];
                u_char          str[NGX_RTMP_AMF0_DEBUG_SIZE + 1];
                u_char         *hp, *pp, *sp;
                static u_char   hex[] = "0123456789ABCDEF";

                hp = hstr;
                sp = str;
                pp = op;

                while (pp < (u_char*)p
                    && pp - (u_char*)op < NGX_RTMP_AMF0_DEBUG_SIZE) 
                {
                    *hp++ = ' ';
                    *hp++ = hex[(*pp & 0xf0) >> 4];
                    *hp++ = hex[*pp & 0x0f];
                    *sp++ = (*pp >= 0x20 && *pp <= 0x7e) ?
                        *pp : (u_char)'?';
                    ++pp;
                }
                *hp = *sp = '\0';

                ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ctx->log, 0,
                    "AMF0 read (%d)%s '%s'", n, hstr, str);
            }
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
    ngx_chain_t   **l, **free;

    l = ctx->link;
    free = ctx->free;

    while(n) {
        b = (*l) ? (*l)->buf : NULL;

        if (b == NULL || b->last == b->end) {
            if (*free == NULL)
                return NGX_ERROR;

            if (*l == NULL) {
                *l = *free;
                *free = (*free)->next;
            } else {
                (*l)->next = *free;
                *free = (*free)->next;
                *l = (*l)->next;
            }
            (*l)->next = NULL;
            b = (*l)->buf;
            b->pos = b->last = b->start;
        }

        size = b->end - b->last;

        if (size <= n) {
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
                if (ngx_rtmp_amf0_get(ctx, data, 8) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_BOOLEAN:
                if (ngx_rtmp_amf0_get(ctx, data, 1) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_STRING:
                if (ngx_rtmp_amf0_get(ctx, &len, sizeof(len)) != NGX_OK) {
                    return NGX_ERROR;
                }

                NGX_RTMP_AMF0_SB(len);

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
    uint16_t                len;
    size_t                  n;
    char                   *name;

    for(n = 0; n < nelts; ++n) {

        name = elts[n].name;
        len = strlen(name);

        if (ngx_rtmp_amf0_put(ctx, &name, len) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_rtmp_amf0_write(ctx, &elts[n], 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    len = 0;

    if (ngx_rtmp_amf0_put(ctx, &name, len) != NGX_OK) {
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

    for(n = 0; n < nelts; ++n) {

        type = elts[n].type;
        data = elts[n].data;
        len  = elts[n].len;

        if (ngx_rtmp_amf0_put(ctx, &type, sizeof(type)) != NGX_OK)
            return NGX_ERROR;

        switch(type) {
            case NGX_RTMP_AMF0_NUMBER:
                if (ngx_rtmp_amf0_put(ctx, data, 8) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_BOOLEAN:
                if (ngx_rtmp_amf0_put(ctx, data, 1) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;

            case NGX_RTMP_AMF0_STRING:
                if (ngx_rtmp_amf0_put(ctx, &len, sizeof(len)) != NGX_OK) {
                    return NGX_ERROR;
                }

                NGX_RTMP_AMF0_SB(len);

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

