
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

static void ngx_rtmp_close_connection(ngx_connection_t *c);

#ifdef NGX_DEBUG
static char*
ngx_rtmp_packet_type(uint8_t type) {
    static char* types[] = {
        "?",
        "chunk_size",
        "abort",
        "ack",
        "ctl",
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
    ngx_bufs_t                 bufs;
    ngx_buf_t                 *b;
    size_t                     size;

    s = c->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_close_session(s);
        return;
    }

    s->chunk_size = NGX_RTMP_DEFAULT_CHUNK_SIZE;

    bufs.size = s->chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;
    bufs.num = cscf->buffers;

    s->free = ngx_create_chain_of_bufs(c->pool, &bufs);

    b = &s->buf;
    size = NGX_RTMP_HANDSHAKE_SIZE + 1;
    b->start = b->pos = b->last = ngx_pcalloc(c->pool, size);
    b->end = b->start + size;
    b->temporary = 1;

    c->write->handler = ngx_rtmp_handshake_send;
    c->read->handler  = ngx_rtmp_handshake_recv;

    ngx_rtmp_handshake_recv(c->read);
}


void
ngx_rtmp_handshake_recv(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_buf_t                 *b;

    c = rev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_session(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = &s->buf;

    while(b->last != b->end) {

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_close_session(s);
            return;
        }

        if (n > 0) {
            if (b->last == b->start
                && s->hs_stage == 0 && *b->last != '\x03') 
            {
                ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, 
                        "invalid handshake signature");
                ngx_rtmp_close_session(s);
                return;
            }
            b->last += n;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, cscf->timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
            }
            return;
        }
    }

    ngx_del_event(c->read, NGX_READ_EVENT, 0);

    if (s->hs_stage++ == 0) {
        ngx_rtmp_handshake_send(c->write);
        return;
    }

    /* handshake done */
    ngx_pfree(c->pool, s->buf.start);
    c->read->handler =  ngx_rtmp_recv;
    c->write->handler = ngx_rtmp_send;
    ngx_rtmp_recv(rev);
}


void
ngx_rtmp_handshake_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_buf_t                 *b;

    c = wev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    b = &s->buf;

restart:
    while(b->pos != b->last) {
        n = c->send(c, b->pos, b->last - b->pos);
        if (n > 0) {
            b->pos += n;
        }

        if (n == NGX_ERROR) {
            ngx_rtmp_close_session(s);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, cscf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
                return;
            }
        }
    }

    if (s->hs_stage++ == 1) {
        b->pos = b->start + 1;
        goto restart;
    }

    b->pos = b->last = b->start + 1;
    ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    ngx_rtmp_handshake_recv(c->read);
}


void
ngx_rtmp_recv(ngx_event_t *rev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_buf_t                  *b, *bb;
    u_char                     *p, *pp;
    ngx_chain_t                *lin;
    ngx_rtmp_packet_hdr_t      *h;
    uint32_t                    timestamp;

    c = rev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (s->in == NULL) {
        if (s->free == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "no free buffers");
            ngx_rtmp_close_session(s);
            return;
        }
        s->in = s->free;
        s->free = s->free->next;
        s->in->next = NULL;
        b = s->in->buf;
        b->pos = b->last = b->start;
    }

    for(;;) {

        /* find the last buf */
        for(lin = s->in; lin->next; lin = lin->next);
        b = lin->buf;

        if (b->last == b->end) {
            ngx_rtmp_close_session(s);
            return;
        }

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_close_session(s);
            return;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
            }
            return;
        }

        b->last += n;
        h = &s->in_hdr;

        /* parse headers */
        if (b->pos == b->start) {
            p = b->pos;
            timestamp = h->timestamp;

            /* chunk basic header */
            h->fmt  = (*p >> 6) & 0x03;
            h->csid = *p++ & 0x3f;

            if (h->csid == 0) {
                if (b->last - p < 1)
                    continue;
                h->csid = 64;
                h->csid += *(uint8_t*)p++;

            } else if (h->csid == 1) {
                if (b->last - p < 2)
                    continue;
                h->csid = 64;
                h->csid += *(uint8_t*)p++;
                h->csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)h->fmt, h->csid);

            if (h->fmt <= 2 ) {
                if (b->last - p < 3)
                    continue;
                /* timestamp: 
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;

                if (h->fmt <= 1) {
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

                    if (h->fmt == 0) {
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
                    pp = (u_char*)&h->timestamp;
                    pp[3] = *p++;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                } else if (h->fmt) {
                    h->timestamp += timestamp;
                } else {
                    h->timestamp = timestamp;
                }
            }

            ngx_log_debug5(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP mheader %s (%d) "
                    "timestamp=%D mlen=%D msid=%D",
                    ngx_rtmp_packet_type(h->type), (int)h->type,
                    h->timestamp, h->mlen, h->msid);

            /* header done */
            b->pos = p;
        }

        /* parse payload */
        if (b->last - b->pos < (ngx_int_t)ngx_min(h->mlen, s->chunk_size)) 
            continue;

        /* if fragmented then wait for more fragments */
        if (h->mlen > s->chunk_size) {
            if (s->free == NULL) {
                ngx_log_error(NGX_LOG_INFO, c->log, 
                        NGX_ERROR, "no free buffers");
                ngx_rtmp_close_session(s);
                return;
            }
            lin->next = s->free;
            s->free = s->free->next;
            lin = lin->next;
            lin->next = NULL;
            h->mlen -= s->chunk_size;
            bb = lin->buf;
            bb->pos = bb->last = bb->start;
            continue;
        }

        /* handle packet! */
        if (ngx_rtmp_receive_packet(s, h, s->in) != NGX_OK) {
            ngx_rtmp_close_session(s);
            return;
        }
        bb = s->in->buf;
        bb->pos = bb->last = bb->start;

        /* copy remained data to first buffer */
        if (h->mlen < b->last - b->pos) {
            bb->last = ngx_movemem(bb->start, 
                    b->pos + h->mlen, 
                    b->last - b->pos - h->mlen);
        }

        /* free all but one input buffer */
        if (s->in->next) {
            s->in->next->next = s->free;
            s->free = s->in->next;
            s->in->next = NULL;
        }
    }
}


void
ngx_rtmp_send(ngx_event_t *wev)
{
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_chain_t               *l, *ll;

    c = wev->data;
    s = c->data;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, 
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_close_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    while(s->out) {
        l = c->send_chain(c, s->out, 0);

        if (l == NGX_CHAIN_ERROR) {
            ngx_rtmp_close_session(s);
            return;
        }

        if (l == NULL) {
            cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
            ngx_add_timer(c->write, cscf->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
            }
            return;
        }

        if (l != s->out) {
            for(ll = s->out; 
                    ll->next && ll->next != l; 
                    ll = ll->next);
            ll->next = s->free;
            s->out = l;
        }
    }

    ngx_del_event(wev, NGX_WRITE_EVENT, 0);
}


ngx_rtmp_session_t**
ngx_rtmp_get_session_head(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t  *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    return &cscf->sessions[
        ngx_hash_key(s->name.data, s->name.len) 
        % NGX_RTMP_SESSION_HASH_SIZE];
}


void
ngx_rtmp_join(ngx_rtmp_session_t *s, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_rtmp_session_t    **ps;
    ngx_connection_t       *c;

    c = s->connection;

    if (s->name.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "already joined");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "RTMP join '%V'", 
                   &name);

    s->name = *name;
    ps = ngx_rtmp_get_session_head(s);
    s->next = *ps;
    s->flags = flags;
    *ps = s;
}


void
ngx_rtmp_leave(ngx_rtmp_session_t *s)
{
    ngx_rtmp_session_t    **ps;
    ngx_connection_t       *c;

    c = s->connection;

    if (!s->name.len)
        return;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "RTMP leave '%V'", 
                   &s->name);

    ps = ngx_rtmp_get_session_head(s);

    ngx_str_null(&s->name);

    for(; *ps; ps = &(*ps)->next) {
        if (*ps == s) {
            *ps = (*ps)->next;
            return;
        }
    }
}


void 
ngx_rtmp_send_packet(ngx_rtmp_session_t *s, ngx_rtmp_packet_hdr_t *h, 
        ngx_chain_t *ll)
{
    ngx_rtmp_packet_hdr_t  *lh;
    ngx_int_t               hsize, size, nbufs;
    ngx_chain_t            *l, **pl;
    ngx_buf_t              *b, *bb;
    u_char                 *p, *pp;
    uint8_t                 fmt;
    uint32_t                timestamp, ext_timestamp, mlen;
    ngx_connection_t       *c;

    if (ll == NULL) {
        return;
    }

    /* detect packet size */
    mlen = 0;
    l = ll;
    nbufs = 0; 
    while(l) {
        mlen += (l->buf->last - l->buf->pos);
        ++nbufs;
        l = l->next;
    }

    c = s->connection;
    bb = ll->buf;
    pp = bb->pos;
    lh = &s->out_hdr;

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, c->log, 0,
            "RTMP send %s (%d) csid=%D timestamp=%D "
            "mlen=%D msid=%D nbufs=%d",
            ngx_rtmp_packet_type(h->type), (int)h->type, 
            h->csid, h->timestamp, mlen, h->msid, nbufs);

    while(ll) {
        if (s->free == NULL) {
            /* FIXME: implement proper packet dropper */
            return;
        }

        /* append new output buffer */
        l = s->free;
        s->free = s->free->next;
        l->next = NULL;
        for(pl = &s->out; *pl; pl = &(*pl)->next);
        *pl = l;
        b = l->buf;
        b->pos = b->last = b->start + NGX_RTMP_MAX_CHUNK_HEADER;

        /* copy payload to new buffer leaving space for header */
        while (b->last < b->end) {
            size = b->end - b->last;
            if (size < bb->last - pp) {
                b->last = ngx_cpymem(b->last, pp, size);
                pp += size;
                break;
            }
            b->last = ngx_cpymem(b->last, pp, bb->last - pp);

            ll = ll->next;
            if (ll == NULL) {
                break;
            }

            bb = ll->buf;
            pp = bb->pos;
        }

        /* FIXME: there can be some occasional 
         * matches (h->msid == 0) on first out 
         * packet when we compare it
         * against initially zeroed header;
         * Though it maybe OK */

        /* fill header
         * we have
         *  h  - new header
         *  lh - old header for diffs */
        fmt = 0;
        hsize = 12;

        if (h->msid && lh->msid == h->msid) {
            ++fmt;
            hsize -= 4;
            if (lh->type == h->type && lh->mlen == mlen) {
                ++fmt;
                hsize -= 4;
                if (lh->timestamp == h->timestamp) {
                    ++fmt;
                    hsize -= 3;
                }
            }
        }

        /* message header */
        timestamp = (fmt ? h->timestamp 
                : h->timestamp - lh->timestamp);
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

        /* now we know header size */
        b->pos -= hsize;
        p = b->pos;

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

        *lh = *h;
    }

    ngx_rtmp_send(c->write);
}


ngx_int_t ngx_rtmp_receive_packet(ngx_rtmp_session_t *s,
        ngx_rtmp_packet_hdr_t *h, ngx_chain_t *l)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_connection_t           *c;
    ngx_buf_t                  *b;
    struct {
        uint16_t               *v1;
        uint16_t               *v2;
        uint16_t               *v3;
    }                           ping;
    ngx_rtmp_session_t         *ss;
    static char                 invoke_name[64]; 
    static ngx_rtmp_amf0_elt_t  invoke_name_elt = { 
        NGX_RTMP_AMF0_STRING,     
        NULL,
        invoke_name,       
        sizeof(invoke_name)        
    };
    ngx_rtmp_amf0_ctx_t         amf_ctx;

    if (l == NULL) {
        return NGX_ERROR;
    }

    c = s->connection;
    b = l->buf;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* a session handles only one chunk stream 
     * but #2 is a special one for protocol messages */
    if (h->csid != 2) {
        s->csid = h->csid;
    }


#ifdef NGX_DEBUG
    {
        int             nbufs;
        ngx_chain_t    *ch;

        for(nbufs = 1, ch = l; 
                ch->next; 
                ch = ch->next, ++nbufs);

        ngx_log_debug7(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "RTMP recv %s (%d) csid=%D timestamp=%D "
                "mlen=%D msid=%D nbufs=%d",
                ngx_rtmp_packet_type(h->type), (int)h->type, 
                h->csid, h->timestamp, h->mlen, h->msid, nbufs);
    }
#endif

    switch(h->type) {
        case NGX_RTMP_PACKET_CHUNK_SIZE:
            break;

        case NGX_RTMP_PACKET_ABORT:
            break;

        case NGX_RTMP_PACKET_ACK:
            break;

        case NGX_RTMP_PACKET_CTL:
            if (b->last - b->pos < 6)
                return NGX_ERROR;

            ping.v1 = (uint16_t*)(b->pos);
            ping.v2 = (uint16_t*)(b->pos + 2);
            ping.v3 = (uint16_t*)(b->pos + 4);

            switch(*ping.v1) {
                case NGX_RTMP_CTL_STREAM_BEGIN:
                    break;

                case NGX_RTMP_CTL_STREAM_EOF:
                    break;

                case NGX_RTMP_CTL_STREAM_DRY:
                    break;

                case NGX_RTMP_CTL_SET_BUFLEN:
                    break;

                case NGX_RTMP_CTL_RECORDED:
                    break;

                case NGX_RTMP_CTL_PING_REQUEST:
                    /* ping client from server */
                    /**ping.v1 = NGX_RTMP_PING_PONG;
                    ngx_rtmp_send_packet(s, h, l);*/
                    break;

                case NGX_RTMP_CTL_PING_RESPONSE:
                    break;
            }
            break;

        case NGX_RTMP_PACKET_ACK_SIZE:
            break;

        case NGX_RTMP_PACKET_BANDWIDTH:
            break;

        case NGX_RTMP_PACKET_EDGE:
            break;

        case NGX_RTMP_PACKET_AUDIO:
        case NGX_RTMP_PACKET_VIDEO:
            if (!(s->flags & NGX_RTMP_PUBLISHER)) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "received audio/video from non-publisher");
                return NGX_ERROR;
            }

            for(ss = *ngx_rtmp_get_session_head(s); 
                    ss; ss = ss->next) 
            {
                if (s != ss 
                        && ss->flags & NGX_RTMP_SUBSCRIBER
                        && s->name.len == ss->name.len
                        && !ngx_strncmp(s->name.data, ss->name.data, 
                            s->name.len))
                {
                    ngx_rtmp_send_packet(ss, h, l);
                }

            }
            break;

        case NGX_RTMP_PACKET_AMF3_META:
        case NGX_RTMP_PACKET_AMF3_SHARED:
        case NGX_RTMP_PACKET_AMF3_CMD:
            /* FIXME: AMF3 it not yet supported */
            break;

        case NGX_RTMP_PACKET_AMF0_META:
            break;

        case NGX_RTMP_PACKET_AMF0_SHARED:
            break;

        case NGX_RTMP_PACKET_AMF0_CMD:
            amf_ctx.link = &l;
            amf_ctx.free = &s->free;
            amf_ctx.log = c->log;

            memset(invoke_name, 0, sizeof(invoke_name));
            if (ngx_rtmp_amf0_read(&amf_ctx, &invoke_name_elt, 1) != NGX_OK) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "AMF0 cmd failed");
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "AMF0 cmd '%s'",
                    invoke_name);

#define _CMD_CALL(name) \
            if (!strcasecmp(invoke_name, #name)) { \
                return ngx_rtmp_##name(s, l); \
            }

            /* NetConnection calls */
            _CMD_CALL(connect);
            _CMD_CALL(call);
            _CMD_CALL(close);
            _CMD_CALL(createstream);
            
            /* NetStream calls */
            _CMD_CALL(play);
            _CMD_CALL(play2);
            _CMD_CALL(deletestream);
            _CMD_CALL(closestream);
            _CMD_CALL(receiveaudio);
            _CMD_CALL(receivevideo);
            _CMD_CALL(publish);
            _CMD_CALL(seek);
            _CMD_CALL(pause);

#undef _CMD_CALL

            break;

        default:
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "unexpected packet type %d", 
                   (int)h->type);
    }

    return NGX_OK;
}


void
ngx_rtmp_close_session(ngx_rtmp_session_t *s)
{
    ngx_rtmp_leave(s);
    ngx_rtmp_close_connection(s->connection);
}


void
ngx_rtmp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "close connection: %d", c->fd);

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

