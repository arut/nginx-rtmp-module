
/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <strings.h>

#include "ngx_rtmp.h"
#include "ngx_rtmp_amf0.h"


static void ngx_rtmp_init_session(ngx_connection_t *c);

static void ngx_rtmp_handshake_recv(ngx_event_t *rev);
static void ngx_rtmp_handshake_send(ngx_event_t *rev);

static void ngx_rtmp_recv(ngx_event_t *rev);
static void ngx_rtmp_send(ngx_event_t *rev);
static ngx_int_t ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


#ifdef NGX_DEBUG
char*
ngx_rtmp_message_type(uint8_t type) {
    static char* types[] = {
        "?",
        "chunk_size",
        "abort",
        "ack",
        "user",
        "ack_size",
        "bandwidth",
        "edge",
        "audio",
        "video",
        "?",
        "?",
        "?",
        "?",
        "?",
        "amf3_meta",
        "amf3_shared",
        "amd3_cmd",
        "amf0_meta",
        "amf0_shared",
        "amf0_cmd",
        "?",
        "aggregate"
    };

    return type < sizeof(types) / sizeof(types[0])
        ? types[type]
        : "?";
}


char*
ngx_rtmp_user_message_type(uint16_t evt) {
    static char* evts[] = {
        "stream_begin",
        "stream_eof",
        "stream dry",
        "set_buflen",
        "recorded",
        "ping_request",
        "ping_response",
    };

    return evt < sizeof(evts) / sizeof(evts[0])
        ? evts[evt]
        : "?";
}
#endif

void
ngx_rtmp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t             i;
    ngx_rtmp_port_t       *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_rtmp_log_ctx_t    *ctx;
    ngx_rtmp_in_addr_t    *addr;
    ngx_rtmp_session_t    *s;
    ngx_rtmp_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t));
    if (s == NULL) {
        ngx_rtmp_close_connection(c);
        return;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client connected",
                  c->number, &c->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_log_ctx_t));
    if (ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_rtmp_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = NGX_ERROR_INFO;

    ngx_rtmp_init_session(c);
}


static void
ngx_rtmp_init_session(ngx_connection_t *c)
{
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_buf_t                 *b;
    size_t                     size;

    s = c->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return;
    }

    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t) 
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_close_connection(c);
        return;
    }

    size = NGX_RTMP_HANDSHAKE_SIZE + 1;
    s->in_chunk_size = NGX_RTMP_DEFAULT_CHUNK_SIZE;
    s->in_pool = ngx_create_pool(4096/*2 * size + sizeof(ngx_pool_t)*/, c->log);

    /* start handshake */
    b = &s->hs_in_buf;
    b->start = b->pos = b->last = ngx_pcalloc(s->in_pool, size);
    b->end = b->start + size;
    b->temporary = 1;

    b = &s->hs_out_buf;
    b->start = b->pos = b->last = ngx_pcalloc(s->in_pool, size);
    b->end = b->start + size;
    b->temporary = 1;

    c->write->handler = ngx_rtmp_handshake_send;
    c->read->handler  = ngx_rtmp_handshake_recv;

    ngx_rtmp_handshake_recv(c->read);
}


uint32_t 
ngx_rtmp_get_timestamp()
{
    ngx_time_t     *tod;

    tod = ngx_timeofday();

    return (uint32_t)tod->sec * 1e3
        + (uint32_t)tod->msec / 1e3;
}


void
ngx_rtmp_handshake_recv(ngx_event_t *rev)
{
    ssize_t                     n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_buf_t                  *b;
    u_char                     *p;

    c = rev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_connection(c);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = (s->hs_stage == NGX_RTMP_HS_READ_DATA)
        ? &s->hs_in_buf
        : &s->hs_out_buf;

    while (b->last != b->end) {

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_close_connection(c);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, cscf->timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_close_connection(c);
            }
            return;
        }

        b->last += n;
    }

    ngx_del_event(c->read, NGX_READ_EVENT, 0);

    ++s->hs_stage;

    if (s->hs_stage == NGX_RTMP_HS_WRITE_DATA) {

        if (*b->pos != NGX_RTMP_VERSION) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, 
                    "invalid handshake signature");
            ngx_rtmp_close_connection(c);
            return;
        }

        /* version is never needed anymore */
        ++b->pos;

        /* store current time as our epoch */
        s->epoch = ngx_rtmp_get_timestamp();

        /* read client epoch */
        p = (u_char*)&s->peer_epoch;
        *p++ = b->pos[3];
        *p++ = b->pos[2];
        *p++ = b->pos[1];
        *p++ = b->pos[0];

        /* prepare output signature:
         * set version, set epoch, fill zeroes */
        p = (u_char*)&s->epoch;
        b = &s->hs_out_buf;
        b->pos[0] = NGX_RTMP_VERSION;
        b->pos[4] = *p++;
        b->pos[3] = *p++;
        b->pos[2] = *p++;
        b->pos[1] = *p++;
        b->pos[5] = b->pos[6] = b->pos[7] = b->pos[8] = 0;
        for(b->last = b->pos + 9, n = 1; 
                b->last < b->end; 
                ++b->last, ++n) 
        {
            *b->last = (u_char)(n & 0xff);
        }

        /* reply timestamp is the same as out epoch */
        /*ngx_memcpy(s->hs_in_buf.pos + 4, b->pos + 1, 4);*/

        ngx_rtmp_handshake_send(c->write);

        return;
    }

    /* handshake done */
    ngx_reset_pool(s->in_pool);

    c->read->handler =  ngx_rtmp_recv;
    c->write->handler = ngx_rtmp_send;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "RTMP handshake done; epoch=%uD peer_epoch=%uD",
            s->epoch, s->peer_epoch);

    ngx_rtmp_recv(rev);
}


void
ngx_rtmp_handshake_send(ngx_event_t *wev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_buf_t                  *b;

    c = wev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, 
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_connection(c);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

restart:

    b = (s->hs_stage == NGX_RTMP_HS_WRITE_DATA)
        ? &s->hs_out_buf
        : &s->hs_in_buf;

    while(b->pos != b->last) {

        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_ERROR) {
            ngx_rtmp_close_connection(c);
            return;
        }

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, cscf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_close_connection(c);
                return;
            }
        }

        b->pos += n;
    }

    ++s->hs_stage;

    if (s->hs_stage == NGX_RTMP_HS_WRITE_ECHO) {
        goto restart;
    }

    ngx_del_event(wev, NGX_WRITE_EVENT, 0);

    b = &s->hs_out_buf;
    b->pos = b->last = b->start + 1;
    ngx_rtmp_handshake_recv(c->read);
}

ngx_chain_t * tmp;


void
ngx_rtmp_recv(ngx_event_t *rev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t          *h;
    ngx_rtmp_stream_t          *st, *st0;
    ngx_chain_t                *in, *head;
    ngx_buf_t                  *b;
    u_char                     *p, *pp, *old_pos;
    size_t                      size, fsize, old_size;
    uint8_t                     fmt;
    uint32_t                    csid, timestamp;

    c = rev->data;
    s = c->data;
    b = NULL;
    old_pos = NULL;
    old_size = 0;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    for( ;; ) {

        st = &s->in_streams[s->in_csid];

        /* allocate new buffer */
        if (st->in == NULL) {

            if ((st->in = ngx_alloc_chain_link(s->in_pool)) == NULL
                || (st->in->buf = ngx_calloc_buf(s->in_pool)) == NULL) 
            {
                ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, 
                        "chain alloc failed");
                ngx_rtmp_close_connection(c);
                return;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "allocating input buffer %p : %p", 
                    st->in, st->in->buf);

            st->in->next = NULL;
            b = st->in->buf;
            size = s->in_chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;

            b->start = b->last = b->pos = ngx_palloc(s->in_pool, size);
            if (b->start == NULL) {
                ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, 
                        "buf alloc failed");
                ngx_rtmp_close_connection(c);
                return;
            }
            b->end = b->start + size;
        }

        h  = &st->hdr;
        in = st->in;
        b  = in->buf;

        if (old_size) {

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "reusing formerly read data: %d", old_size);

            b->pos = b->start;
            b->last = ngx_movemem(b->pos, old_pos, old_size);

        } else { 

            if (old_pos) {
                b->pos = b->last = b->start;
            }

            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                ngx_rtmp_close_connection(c);
                return;
            }

            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                    ngx_rtmp_close_connection(c);
                }
                return;
            }

            b->last += n;
            s->in_bytes += n;

            if (s->in_bytes - s->in_last_ack >= cscf->ack_window) {
                
                s->in_last_ack = s->in_bytes;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "sending RTMP ACK(%D)", s->in_bytes);

                if (ngx_rtmp_send_ack(s, s->in_bytes)) {
                    ngx_rtmp_close_connection(c);
                    return;
                }
            }
        }

        old_pos = NULL;
        old_size = 0;

        /* parse headers */
        if (b->pos == b->start) {
            p = b->pos;

            /* chunk basic header */
            fmt  = (*p >> 6) & 0x03;
            csid = *p++ & 0x3f;

            if (csid == 0) {
                if (b->last - p < 1)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;

            } else if (csid == 1) {
                if (b->last - p < 2)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;
                csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)fmt, csid);

            if (csid >= cscf->max_streams) {
                ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR,
                    "RTMP in chunk stream too big: %D >= %D",
                    csid, cscf->max_streams);
                ngx_rtmp_close_connection(c);
                return;
            }

            /* link orphan */
            if (s->in_csid == 0) {

                /* unlink from stream #0 */
                st->in = st->in->next;

                /* link to new stream */
                s->in_csid = csid;
                st = &s->in_streams[csid];
                if (st->in == NULL) {
                    in->next = in;
                } else {
                    in->next = st->in->next;
                    st->in->next = in;
                }
                st->in = in;
                h = &st->hdr;
                h->csid = csid;
            }

            /* get previous header to inherit data from */
            timestamp = h->timestamp;

            if (fmt <= 2 ) {
                if (b->last - p < 3)
                    continue;
                /* timestamp: 
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;

                if (fmt <= 1) {
                    if (b->last - p < 4)
                        continue;
                    /* size:
                     *  big-endian 3b -> little-endian 4b 
                     * type:
                     *  1b -> 1b*/
                    pp = (u_char*)&h->mlen;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                    pp[3] = 0;
                    h->type = *(uint8_t*)p++;

                    if (fmt == 0) {
                        if (b->last - p < 4)
                            continue;
                        /* stream:
                         *  little-endian 4b -> little-endian 4b */
                        pp = (u_char*)&h->msid;
                        pp[0] = *p++;
                        pp[1] = *p++;
                        pp[2] = *p++;
                        pp[3] = *p++;
                    }
                }

                /* extended header */
                if (timestamp == 0x00ffffff) {
                    if (b->last - p < 4)
                        continue;
                    pp = (u_char*)&timestamp;
                    pp[3] = *p++;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                }
                if (fmt) {
                    h->timestamp += timestamp;
                } else {
                    h->timestamp = timestamp;
                }
            }

            ngx_log_debug6(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP mheader %s (%d) "
                    "timestamp=%uD mlen=%D len=%D msid=%D",
                    ngx_rtmp_message_type(h->type), (int)h->type,
                    h->timestamp, h->mlen, st->len, h->msid);

            if (h->mlen==51441 && st->len==20864) {
                /*asm("int $0x03");*/
                tmp = in;
            }

            /* header done */
            b->pos = p;
        }

        size = b->last - b->pos;
        fsize = h->mlen - st->len;

        if (size < ngx_min(fsize, s->in_chunk_size)) 
            continue;

        /* buffer is ready */

        if (fsize > s->in_chunk_size) {
            /* collect fragmented chunks */
            st->len += s->in_chunk_size;
            b->last = b->pos + s->in_chunk_size;
            old_pos = b->last;
            old_size = size - s->in_chunk_size;

        } else {
            /* handle! */
            head = st->in->next;
            st->in->next = NULL;
            b->last = b->pos + fsize;
            old_pos = b->last;
            old_size = size - fsize;
            st->len = 0;

            if (ngx_rtmp_receive_message(s, h, head) != NGX_OK) {
                ngx_rtmp_close_connection(c);
                return;
            }

            /* add used bufs to stream #0 */
            st0 = &s->in_streams[0];
            st->in->next = st0->in;
            st0->in = head;
            st->in = NULL;
        }

        s->in_csid = 0;
    }
}

static void
ngx_rtmp_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *out, *l, *cl;
    u_char                     *p;
    off_t                       limit;
    size_t                      n;

    c = wev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, 
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_connection(c);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    while (s->out) {
        p = s->out->buf->pos;

        /* send_chain calls writev for output.
         * It uses mixed allocation model for
         * for iovecs passed to writev. Only 64
         * structs fit into stack. When writing more
         * memory is allocated from c->pool and
         * **NEVER EVER** returned back.
         * IOV_MAX=1024 on Linux.
         *
         * The only way to escape allocation is
         * limiting the number of output data blocks
         * being written at once with NGX_HEADERS
         * (64 by default).
         *
         * FIXME: NGINX 
         * Unfortunately NGINX API does not allow
         * us to specify max number of such blocks
         * but only size limit. We're left with
         * limiting by size which leads to extra
         * loop here to find size of first 64
         * blocks in output.
         * */

        limit = 0;
        n = 0;
        cl = s->out;
        while (cl && n < 64) {
            ++n;
            limit += cl->buf->last - cl->buf->pos;
            cl = cl->next;
        }

        out = c->send_chain(c, s->out, limit);

        if (out == NGX_CHAIN_ERROR) {
            ngx_rtmp_close_connection(c);
            return;
        }

        if (out == s->out && out->buf->pos == p) {
            cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
            ngx_add_timer(c->write, cscf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_close_connection(c);
            }
            return;
        }

        while (s->out) {
            l = s->out;

            if (l->buf->pos < l->buf->last) {
                break;
            }

            s->out = s->out->next;
            l->next = NULL;

            l->next = s->out_free_chains;
            s->out_free_chains = l;

            ngx_rtmp_free_shared_buf(cscf, l->buf);

            if (s->out == out) {
                break;
            }
        }
    }

    ngx_del_event(wev, NGX_WRITE_EVENT, 0);
}


void 
ngx_rtmp_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_rtmp_header_t *lh, ngx_chain_t *out)
{
    ngx_chain_t                *l;
    u_char                     *p, *pp;
    ngx_int_t                   hsize, thsize, nbufs;
    uint32_t                    mlen, timestamp, ext_timestamp;
    static uint8_t              hdrsize[] = { 12, 8, 4, 1 };
    u_char                      th[3];
    ngx_rtmp_core_srv_conf_t   *cscf;
    uint8_t                     fmt;
    ngx_connection_t           *c;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (h->csid >= cscf->max_streams) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR,
                "RTMP out chunk stream too big: %D >= %D",
                h->csid, cscf->max_streams);
        ngx_rtmp_close_connection(c);
        return;
    }

    /* detect packet size */
    mlen = 0;
    nbufs = 0; 
    for(l = out; l; l = l->next) {
        mlen += (l->buf->last - l->buf->pos);
        ++nbufs;
    }

    fmt = 0;
    if (lh && lh->csid && h->msid == lh->msid) {
        ++fmt;
        if (h->type == lh->type && mlen == lh->mlen) {
            ++fmt;
            if (h->timestamp == lh->timestamp) {
                ++fmt;
            }
        }
        timestamp = h->timestamp - lh->timestamp;
    } else {
        timestamp = h->timestamp;
    }

    if (lh) {
        *lh = *h;
        lh->mlen = mlen;
    }

    hsize = hdrsize[fmt];

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP prep %s (%d) fmt=%d csid=%uD timestamp=%uD "
            "mlen=%uD msid=%uD nbufs=%d",
            ngx_rtmp_message_type(h->type), (int)h->type, (int)fmt,
            h->csid, h->timestamp, mlen, h->msid, nbufs);

    ext_timestamp = 0;
    if (timestamp >= 0x00ffffff) {
        ext_timestamp = timestamp;
        timestamp = 0x00ffffff;
        hsize += 4;
    }

    if (h->csid >= 64) {
        ++hsize;
        if (h->csid >= 320) {
            ++hsize;
        }
    }

    /* fill initial header */
    out->buf->pos -= hsize;
    p = out->buf->pos;

    /* basic header */
    *p = (fmt << 6);
    if (h->csid >= 2 && h->csid <= 63) {
        *p++ |= (((uint8_t)h->csid) & 0x3f);
    } else if (h->csid >= 64 && h->csid < 320) {
        ++p;
        *p++ = (uint8_t)(h->csid - 64);
    } else {
        *p++ |= 1;
        *p++ = (uint8_t)(h->csid - 64);
        *p++ = (uint8_t)((h->csid - 64) >> 8);
    }

    /* create fmt3 header for successive fragments */
    thsize = p - out->buf->pos;
    ngx_memcpy(th, out->buf->pos, thsize);
    th[0] |= 0xc0;

    /* message header */
    if (fmt <= 2) {
        pp = (u_char*)&timestamp;
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];
        if (fmt <= 1) {
            pp = (u_char*)&mlen;
            *p++ = pp[2];
            *p++ = pp[1];
            *p++ = pp[0];
            *p++ = h->type;
            if (fmt == 0) {
                pp = (u_char*)&h->msid;
                *p++ = pp[0];
                *p++ = pp[1];
                *p++ = pp[2];
                *p++ = pp[3];
            }
        }
    }

    /* extended header */
    if (ext_timestamp) {
        pp = (u_char*)&ext_timestamp;
        *p++ = pp[3];
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];
    }

    /* append headers to successive fragments */
    for(out = out->next; out; out = out->next) {
        out->buf->pos -= thsize;
        ngx_memcpy(out->buf->pos, th, thsize);
    }
}


ngx_int_t
ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out, 
        ngx_uint_t priority)
{
    ngx_chain_t                    *l, **ll;
    ngx_connection_t               *c;
    ngx_buf_t                      *b;
    ngx_rtmp_core_srv_conf_t       *cscf;
    size_t                          nbytes, nbufs, qbytes, qbufs;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    qbytes = 0;
    qbufs = 0;
    nbytes = 0;
    nbufs = 0;

    for(ll = &s->out; *ll; ll = &(*ll)->next) {
        qbytes += (*ll)->buf->last - (*ll)->buf->pos;
        ++qbufs;
    }

    /* drop packet? */
    if (qbytes > cscf->max_buf / (priority + 1)) {
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "drop message bytes=%uz, bufs=%uz priority=%ui",
                qbytes, qbufs, priority);
        return NGX_AGAIN;
    }

    /* append locally-linked chain of shared buffers */
    for(l = out; l; l = l->next) {

        if (s->out_free_chains) {
            *ll = s->out_free_chains;
            s->out_free_chains = (*ll)->next;

        } else {
            *ll = ngx_alloc_chain_link(c->pool);
            if (*ll == NULL) {
                break;
            }
            (*ll)->buf = ngx_calloc_buf(c->pool);
            if ((*ll)->buf == NULL) {
                ngx_free_chain(c->pool, (*ll));
                break;
            }
        }

        b = (*ll)->buf;
        *b = *l->buf;

        ngx_rtmp_acquire_shared_buf(b);

        ll = &(*ll)->next;

        nbytes += (b->last - b->pos);
        ++nbufs;
    }
    *ll = NULL;

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "RTMP send bytes=%uz+%uz, bufs=%uz+%uz, priority=%ui, "
            "ready=%d, active=%d",
            qbytes, nbytes, qbufs, nbufs, priority,
            c->write->ready, c->write->active);

    ngx_rtmp_send(c->write);

    return c->destroyed ? NGX_ERROR : NGX_OK;
}


static ngx_int_t 
ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_array_t                *evhs;
    size_t                      n;
    ngx_rtmp_event_handler_pt  *evh;
    ngx_connection_t           *c;

    c = s->connection;
    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

#ifdef NGX_DEBUG
    {
        int             nbufs;
        ngx_chain_t    *ch;

        for(nbufs = 1, ch = in; 
                ch->next; 
                ch = ch->next, ++nbufs);

        ngx_log_debug7(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "RTMP recv %s (%d) csid=%D timestamp=%D "
                "mlen=%D msid=%D nbufs=%d",
                ngx_rtmp_message_type(h->type), (int)h->type, 
                h->csid, h->timestamp, h->mlen, h->msid, nbufs);
    }
#endif

    if (h->type >= NGX_RTMP_MSG_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "unexpected RTMP message type: %d", (int)h->type);
        return NGX_OK;
    }

    evhs = &cmcf->events[h->type];
    evh = evhs->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "nhandlers: %d", evhs->nelts);

    for(n = 0; n < evhs->nelts; ++n, ++evh) {
        if (!evh) {
            continue;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "calling handler %d", n);
           
        if ((*evh)(s, h, in) != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "handler %d failed", n);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_rtmp_close_connection(ngx_connection_t *c)
{
    ngx_rtmp_session_t                 *s;
    ngx_pool_t                         *pool;
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_disconnect_handler_pt     *h;
    size_t                              n;

    if (c->destroyed) {
        return;
    }

    s = c->data;
    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close connection");

    if (s) {
        h = cmcf->disconnect.elts;
        for(n = 0; n < cmcf->disconnect.nelts; ++n, ++h) {
            if (*h) {
                (*h)(s);
            }
        }

        if (s->in_pool) {
            ngx_destroy_pool(s->in_pool);
        }
    }

    /* release only buffers, links are local 
     * and will be released as part of pool */
    for (; s->out; s->out = s->out->next) {
        ngx_rtmp_free_shared_buf(cscf, s->out->buf);
    }

    c->destroyed = 1;
    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


u_char *
ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_rtmp_session_t  *s;
    ngx_rtmp_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V", s->addr_text);
    len -= p - buf;
    buf = p;

    return p;
}
