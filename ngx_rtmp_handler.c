
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

static size_t   hdrsizes[] = { 12, 8, 4, 1 };


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

    /* TODO: we should move preallcation to a func to call on user request */
    bufs.size = s->chunk_size + 14 /* + max header size */;
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

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "handshake data received size=%d fd=%d",
                    n, c->fd);

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

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "handshake data sent size=%d fd=%d",
                    n, c->fd);
        
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
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_buf_t                 *b, *bb;
    u_char                     h, *p;
    ngx_chain_t               *lin;


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

        /* find the last buf buf */
        for(lin = s->in; lin->next; lin = lin->next);

        b = lin->buf;

        if (b->last == b->end) {
            ngx_rtmp_close_session(s);
            return;
        }

        /* receive data from client */
        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_close_session(s);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "data received size=%d fd=%d",
                    n, c->fd);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
            }
            return;
        }

        /* first byte of a packet? */
        if (b->last == b->start) {
            h = *b->last;
            s->in_hdr.hsize   = hdrsizes[(h >> 6) & 0x03];
            s->in_hdr.channel = h & 0x3f;
        }

        b->last += n;

        if (b->last - b->pos < s->in_hdr.hsize)
            continue;

        /* basic header */
        do {
            p = b->start + 1;

            if (s->in_hdr.hsize < 4)
                break;

            /* TODO: check endians here */

/*
            if (s->in_hdr.channel == 1) {
                p += 2;
            }*/

            s->in_hdr.timer = 0;
            ngx_memcpy(&s->in_hdr.timer, p, 3);

            if (s->in_hdr.hsize < 8)
                break;

            p += 3;
            s->in_hdr.size = 0;
            ngx_memcpy(&s->in_hdr.size, p, 3);
            p += 3;
            ngx_memcpy(&s->in_hdr.type, p, 1);

            if (s->in_hdr.hsize < 12)
                break;

            ++p;
            /* little-endian */
            ngx_memcpy(&s->in_hdr.stream, p, 4);
            p += 4;

        } while(0);


        if (b->last - p < (ngx_int_t)ngx_min(s->in_hdr.size, s->chunk_size)) 
            continue;

        b->pos = p;

        if (s->in_hdr.size > s->chunk_size) {

            /* fragmented; need more fragments */
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
            s->in_hdr.size -= s->chunk_size;
            bb = lin->buf;
            bb->pos = bb->last = bb->start;
            continue;

        }

        /* handle packet! */
        if (ngx_rtmp_receive_packet(s, &s->in_hdr, s->in) != NGX_OK) {
            ngx_rtmp_close_session(s);
            return;
        }

        bb = s->in->buf;
        bb->pos = bb->last = bb->start;

        /* copy remained data to first buffer */
        if (s->in_hdr.size < b->last - b->pos) {
            bb->last = ngx_movemem(bb->start, 
                    b->pos + s->in_hdr.size, 
                    b->last - b->pos - s->in_hdr.size);
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
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_chain_t               *l, *ll;

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

    while(s->out) {

        l = c->send_chain(c, s->out, 0);

        if (l == NGX_CHAIN_ERROR) {
            ngx_rtmp_close_session(s);
            return;
        }

        n = 0;

        if (l != s->out) {
            for(ll = s->out; ll->next && ll->next != l; ll = ll->next);
            ll->next = s->free;
            s->out = l;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "data sent size=? fd=%d",
                    c->fd);

        if (l != NULL) {

            cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

            ngx_add_timer(c->write, cscf->timeout);

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_close_session(s);
            }

            return;
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

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "join name='%V' fd=%d", 
                   &name, c->fd);

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

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "leave name='%V' fd=%d", 
                   &s->name, c->fd);

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
        ngx_chain_t *l)
{
    ngx_rtmp_packet_hdr_t  *lh;
    size_t                  hsel, hsize, size;
    ngx_chain_t            *ll, **pl;
    ngx_buf_t              *b, *bb;
    u_char                 *p, *pp;

    if (l == NULL)
        return;

    b = l->buf;
    p = b->pos;

    while(l) {

        if (s->free == NULL) {
            /* TODO: implement proper packet dropper */
            return;
        }

        /* add new output chunk */
        ll = s->free;
        s->free = s->free->next;
        ll->next = NULL;

        for(pl = &s->out; *pl; pl = &(*pl)->next);
        *pl = ll;

        /* put payload at the end; leave space for header */
        bb = ll->buf;
        bb->pos = bb->last = bb->end - s->chunk_size;

        /* fill new chunk payload */
        while(l && bb->pos != bb->last) {
            size = ngx_min(bb->last - bb->pos, b->last - p);
            bb->last = ngx_cpymem(bb->last, p, size);
            p += size;
            if (p != b->last)
                continue;
            l = l->next;
            if (l) {
                b = l->buf;
                p = b->pos;
            }
        }

        lh = &s->out_hdr;

        hsel = 0;

        /* choose header size */
        if (lh->hsize) {

            if (lh->stream == h->stream)
                ++hsel;

            if (lh->type == h->type && lh->size == h->size)
                ++hsel;

            if (lh->timer == h->timer)
                ++hsel;
        }

        hsize = hdrsizes[hsel];

        bb->pos -= hsize;

        *lh = *h;

        /* fill header: bb->pos..bb->pos+hsize */
        
        pp = bb->pos;

        *pp++ = (((uint8_t)hsel & 0x03) << 6) | (h->channel & 0x3f);

        if (hsize == 1)
            continue;

        /* TODO: watch endians */

        pp = ngx_cpymem(pp, &h->timer, 3);

        if (hsize == 4)
            continue;

        pp = ngx_cpymem(pp, &h->size, 3);
        *pp++ = h->type;

        if (hsize == 8)
            continue;

        ngx_memcpy(pp, &h->stream, 4);
    }
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


    c = s->connection;

    if (l == NULL)
        return NGX_ERROR;

#ifdef NGX_DEBUG
    {
        int             nch;
        ngx_chain_t    *ch;

        for(nch = 1, ch = l; ch->next; ch = ch->next, ++nch);

        ngx_log_debug8(NGX_LOG_DEBUG_RTMP, c->log, 0,
                "RTMP packet received type=%d channel=%d hsize=%d "
                "size=%d timer=%D stream=%D nbufs=%d fd=%d", 
                (int)h->type, 
                (int)h->channel, 
                (int)h->hsize, 
                (int)h->size, 
                h->timer,
                h->stream,
                nch,
                c->fd);
    }
#endif

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    b = l->buf;
    
    switch(h->type) {

        case NGX_RTMP_PACKET_CHUNK_SIZE:
            if (b->last - b->pos < 4)
                return NGX_ERROR;
            /*ngx_rtmp_set_chunk_size(s, *(uint32_t*)(b->pos));*/
            break;

        case NGX_RTMP_PACKET_BYTES_READ:
            if (b->last - b->pos < 4)
                return NGX_ERROR;
            /*ngx_rtmp_set_bytes_read(s, *(uint32_t*)(b->pos));*/
            break;

        case NGX_RTMP_PACKET_PING:
            if (b->last - b->pos < 6)
                return NGX_ERROR;

            ping.v1 = (uint16_t*)(b->pos);
            ping.v2 = (uint16_t*)(b->pos + 2);
            ping.v3 = (uint16_t*)(b->pos + 4);

            switch(*ping.v1) {

                case NGX_RMTP_PING_CLEAR_STEAM:
                    break;

                case NGX_RMTP_PING_CLEAR_BUFFER:
                    /*ngx_rtmp_clear_buffer(s);*/
                    break;

                case NGX_RMTP_PING_CLIENT_TIME:
                    /*ngx_rtmp_set_client_buffer_time(s, *ping.v3);*/
                    break;

                case NGX_RMTP_PING_RESET_STREAM:
                    break;

                case NGX_RMTP_PING_PING:
                    /* ping client from server */
                    *ping.v1 = NGX_RMTP_PING_PONG;
                    ngx_rtmp_send_packet(s, h, l);
                    break;

                case NGX_RMTP_PING_PONG:
                    /* TODO: wtf the arg? */
                    /*ngx_rtmp_set_ping_time(s, *ping.v2);*/
                    break;
            }

            break;

        case NGX_RTMP_PACKET_SERVER_BW:
            if (b->last - b->pos < 4)
                return NGX_ERROR;

            /*ngx_rtmp_set_server_bw(s, *(uint32_t*)b->pos,
                    b->last - b->pos >= 5
                    ? *(uint8_t*)(b->pos + 4)
                    : 0);*/
            break;

        case NGX_RTMP_PACKET_CLIENT_BW:
            if (b->last - b->pos < 4)
                return NGX_ERROR;

            /*ngx_rtmp_set_client_bw(s, *(uint32_t*)b->pos,
                    b->last - b->pos >= 5
                    ? *(uint8_t*)(b->pos + 4)
                    : 0);*/
            break;

        case NGX_RTMP_PACKET_AUDIO:
        case NGX_RTMP_PACKET_VIDEO:
            if (!(s->flags & NGX_RTMP_PUBLISHER)) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "received audio/video from non-publisher fd=%d", 
                        c->fd);
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

        case NGX_RTMP_PACKET_SO:
            /* TODO: implement
             * plain: name, version, persistent; + lots of amf key-values
             * ignore so far */
            break;

        case NGX_RTMP_PACKET_NOTIFY:
            /* TODO: Implement HTTP callbacks on such packets 
             * with AMF fields converted to HTTP
             * GET vars*/
            break;

        case NGX_RTMP_PACKET_INVOKE:
            /* amf: name, id, argv */

            /*TODO:
             * will call ngx_rtmp_join/ngx_rtmp_leave from here
             * */

            memset(invoke_name, 0, sizeof(invoke_name));
            if (ngx_rtmp_amf0_read(&l, &invoke_name_elt, 1) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP invoke name='%s' fd=%d",
                    invoke_name, c->fd);


#define INVOKE_CALL(name) \
            if (!strcasecmp(invoke_name, #name)) { \
                return ngx_rtmp_##name(s, &l); \
            }

            /* NetConnection calls */
            INVOKE_CALL(connect);
            INVOKE_CALL(call);
            INVOKE_CALL(close);
            INVOKE_CALL(createstream);
            
            /* NetStream calls */
            INVOKE_CALL(play);
            INVOKE_CALL(play2);
            INVOKE_CALL(deletestream);
            INVOKE_CALL(closestream);
            INVOKE_CALL(receiveaudio);
            INVOKE_CALL(receivevideo);
            INVOKE_CALL(publish);
            INVOKE_CALL(seek);
            INVOKE_CALL(pause);

#undef INVOKE_CALL

            break;

        case NGX_RTMP_PACKET_FLEX:
        case NGX_RTMP_PACKET_FLEX_SO:
        case NGX_RTMP_PACKET_FLEX_MSG:
            /* no support for flex */
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "flex packets are not supported type=%d fd=%d", 
                   (int)h->type, c->fd);
            break;

        default:
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "unsupported packet type type=%d fd=%d", 
                   (int)h->type, c->fd);
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

    p = ngx_snprintf(buf, len, "%s, server: %V", s->addr_text);
    len -= p - buf;
    buf = p;

    return p;
}

