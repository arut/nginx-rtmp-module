#include "ngx_rtmp.h"


/* Store refcount in negative bytes of shared buffer */

#define NGX_RTMP_REFCOUNT_TYPE      uint32_t
#define NGX_RTMP_REFCOUNT_BYTES     sizeof(NGX_RTMP_REFCOUNT_TYPE)

#define ngx_rtmp_ref(b) \
    *((NGX_RTMP_REFCOUNT_TYPE*)(b) - 1)

#define ngx_rtmp_ref_set(b, v)  \
    ngx_rtmp_ref(b) = v

#define ngx_rtmp_ref_get(b)     \
    ++ngx_rtmp_ref(b)

#define ngx_rtmp_ref_put(b)     \
    --ngx_rtmp_ref(b)

/*
#define ngx_rtmp_ref_set(b, v)  \
    *(int*)&((b)->tag) = v

#define ngx_rtmp_ref_get(b)     \
    (++*(int*)&((b)->tag))

#define ngx_rtmp_ref_put(b)     \
    (--*(int*)&((b)->tag))
*/

ngx_chain_t * 
ngx_rtmp_alloc_shared_buf(ngx_rtmp_core_srv_conf_t *cscf)
{
    ngx_chain_t               *out;
    ngx_buf_t                 *b;
    size_t                     size;

    if (cscf->out_free) {
        out = cscf->out_free;
        cscf->out_free = out->next;

    } else {

        if (cscf->out_free_chains) {
            out = cscf->out_free_chains;
            cscf->out_free_chains = out->next;

        } else {
            out = ngx_alloc_chain_link(cscf->out_pool);
            if (out == NULL) {
                return NULL;
            }

            out->buf = ngx_calloc_buf(cscf->out_pool);
            if (out->buf == NULL) {
                ngx_free_chain(cscf->out_pool, out);
                return NULL;
            }
        }

        size = cscf->out_chunk_size + NGX_RTMP_MAX_CHUNK_HEADER 
            + NGX_RTMP_REFCOUNT_BYTES;

        b = out->buf;
        b->start = ngx_palloc(cscf->out_pool, size);
        if (b->start == NULL) {
            out->next = cscf->out_free_chains;
            cscf->out_free_chains = out;
            return NULL;
        }

        b->start += NGX_RTMP_REFCOUNT_BYTES;
        b->end = b->start + size - NGX_RTMP_REFCOUNT_BYTES;
    }

    out->next = NULL;
    b = out->buf;
    b->pos = b->last = b->start + NGX_RTMP_MAX_CHUNK_HEADER;
    b->memory = 1;

    /* buffer has refcount =1 when created! */
    ngx_rtmp_ref_set(b->start, 1);

    return out;
}


void
ngx_rtmp_free_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_chain_t *out)
{
    ngx_chain_t                *cl;

    while (out) {
        cl = out;
        out = out->next;

        if (ngx_rtmp_ref_put(cl->buf->start) == 0) {
            /* both chain & buf are free;
             * put the whole chain in free list */
            cl->next = cscf->out_free;
            cscf->out_free = cl;
            continue;
        }

        /* only chain is free;
         * buf is still used by somebody & will
         * be freed in ngx_rtmp_free_shared_buf */
         cl->next = cscf->out_free_chains;
         cscf->out_free_chains = cl;
    }
}


void
ngx_rtmp_acquire_shared_buf(ngx_buf_t *b) 
{
    ngx_rtmp_ref_get(b->start);
}


void
ngx_rtmp_free_shared_buf(ngx_rtmp_core_srv_conf_t *cscf, ngx_buf_t *b) 
{
    ngx_chain_t                *cl;

    if (ngx_rtmp_ref_put(b->start)) {
        return;
    }

    if (cscf->out_free_chains) {
        cl = cscf->out_free_chains;
        cscf->out_free_chains = cl->next;

    } else {
        cl = ngx_alloc_chain_link(cscf->out_pool);
        if (cl == NULL) {
            return;
        }

        cl->buf = ngx_calloc_buf(cscf->out_pool);
        if (cl->buf == NULL) {
            ngx_free_chain(cscf->out_pool, cl);
            return;
        }
    }

    cl->buf->start = b->start;
    cl->buf->end = b->end;
    cl->next = cscf->out_free;
    cscf->out_free = cl;
}


ngx_chain_t *
ngx_rtmp_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, 
        ngx_chain_t *head, ngx_chain_t *in)
{
    ngx_chain_t                    *l, **ll;
    u_char                         *p;
    size_t                          size;

    ll = &head;
    p = in->buf->pos;
    l = head;

    if (l) {
        for(; l->next; l = l->next);
        ll = &l->next;
    }

    for ( ;; ) {

        if (l == NULL || l->buf->last == l->buf->end) {
            l = ngx_rtmp_alloc_shared_buf(cscf);
            if (l == NULL || l->buf == NULL) {
                break;
            }

            *ll = l;
            ll = &l->next;
        }

        while (l->buf->end - l->buf->last >= in->buf->last - p) {
            l->buf->last = ngx_cpymem(l->buf->last, p, 
                    in->buf->last - p);
            in = in->next;
            if (in == NULL) {
                goto done;
            }
            p = in->buf->pos;
        }

        size = l->buf->end - l->buf->last;
        l->buf->last = ngx_cpymem(l->buf->last, p, size);
        p += size;
    }

done:
    *ll = NULL;

    return head;
}
